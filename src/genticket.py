"""
genticket.py

A "proof of concept" Python script to generate tickets in ServiceNow for
failed BigFix actions
"""
import json
import argparse
import socket
import time
import requests

# This is here ONLY to suppress self-signed certoficate warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# End of warning supression

parser = argparse.ArgumentParser()
parser.add_argument(
    "-s",
    "--bfserver",
    help="address and port of BigFix server",
    nargs="?",
    default="10.10.220.60:52311",
)
parser.add_argument(
    "-u", "--bfuser", help="BigFix REST API Username", nargs="?", default="IEMAdmin"
)
parser.add_argument(
    "-p", "--bfpass", help="BigFix REST API Password", default="BigFix!123"
)
parser.add_argument("-S", "--snurl", help="ServiceNow API Base URL")
parser.add_argument("-U", "--snuser", help="ServiceNow API Username")
parser.add_argument("-P", "--snpass", help="ServiceNow API Password")
parser.add_argument("days", type=int, help="Number of days to look back")
args = parser.parse_args()

bf_server = args.bfserver
bf_username = args.bfuser
bf_password = args.bfpass

sn_url = args.snurl
sn_username = args.snuser
sn_password = args.snpass

# This machine's fqdn
fqdn = socket.getfqdn()


# DEBUG log http result from servicenow API call
with open("servicenow-results.log", "w", encoding="utf-8") as snr:
    snr.write("DXC genticket run at " + time.asctime(time.gmtime()))

## The POST template -- I hate to include it all here, but it is the simplest
## way to do it:

# postTemplate = '''{
# 	"EventList" : [
# {
#  "severity": "critical",
#  "title": "string",
#  "longDescription": "string",
#  "node": "string",
#  "category": "DXC_IT_BigFix",
#  "application": "500346",
#  "domainName": "CSC-I",
#  "incidentCategory": "Software",
#  "domainLookupBizSrvcName": "DXCIT BIGFIX Server Management",
#  "incidentSubcategory": "Application Batch/Job/Transaction"
# }
# ]
# }
#'''

POST_TEMPLATE = """{
	"EventList" : [ 
{
  "severity": "critical",
  "incidentImpact": "2",
  "title": "string",
  "longDescription": "string",
  "node": "string",
  "category": "DXC_IT_BigFix",
  "application": "500346",
  "domainName": "CSC-I",
  "incidentCategory": "Software",
  "incidentSubcategory": "Application Batch/Job/Transaction",
  "foundSupportGroupAction": "UseAssignmentRules"
}
]
}
"""

## Populate python dict from json template
post = json.loads(POST_TEMPLATE)

## Initialize the json "memory" of tickets
ticketHash = {}

# Try to read the existing ticket hash, if present
try:
    with open("genticketData.json", "r", encoding="utf-8") as ticketFile:
        ticketHash = json.load(ticketFile)
except Exception as err:
    # FIXME:
    # An IOError or JSONDecodeError probably indicates the file does not yet exist
    # This is something that should be explicitly checked and handled.
    # For this "demo" code, we ignore errors. NOT PRODUCTION READY!
    pass

## This is the session relevance query that pulls top level actions and actions results from
## the BigFix REST API. This query can be modified to change the set of actions that are
## ticket candidates. For example, the clause 'name of it as lowercase does not contain "dxctest"'
## was added to allow operators to exclude actions from tickets by merely putting that word
## in the name of the action.
query = f"""(id of it, name of it, multiple flag of it, \
((id of it, name of it) of action of it, status of it, \
start time of it, end time of it, \
(id of it, name of it) of computer of it) \
of results whose ((status of it as string as lowercase) \
is contained by set of ("failed"; "locked"; "user cancelled"; \
"download failed"; "expired before execution"; \
"error"; "transcoding error"; "hash mismatch"; \
"disk free limited"; "disk limited"; "invalid signature") \
and (end time of it > (now - {str(args.days)}*day))) of \
(it; member actions of it)) of bes actions whose \
(name of it as lowercase does not contain "testaction" and \
not exists parent group of it and time issued of it > now - \
{str(args.days)}*day)""".strip()

session = requests.Session()
session.auth = (bf_username, bf_password)
response = session.get("https://" + bf_server + "/api/login", verify=False)

qheader = {"Content-Type": "application/x-www-form-urlencoded"}

qquery = {"relevance": query, "output": "json"}

req = requests.Request(
    "POST", "https://" + bf_server + "/api/query", headers=qheader, data=qquery
)

prepped = session.prepare_request(req)

result = session.send(prepped, verify=False)

# DEBUG log http result from servicenow API call
with open("servicenow-results.log", "a", encoding="utf-8") as snr:
    snr.write("---------------------------------\n")
    snr.write("BigFix query and results:\n")
    snr.write(json.dumps(req, indent=2))
    snr.write(json.dumps(result, indent=2))
    snr.write("---------------------------------\n")


if result.status_code == 200:
    actions = json.loads(result.text)

    print("-----------------------------------\n")
    print(json.dumps(actions, indent=2))
    print("-----------------------------------\n")

    for row in actions["result"]:
        # Each iteration here is an array which represents a "top level"
        # action. The elements of the array are:
        #
        # [0]	Action ID
        # [1]	Action Name
        # [2]	isMultipleActionGroup (when true there will be many subactions)
        # [3]	subactionArray - The first one will always be the same as the "top"
        # 			[0][0] Subaction ID
        # 			[0][1] Subaction Name
        # 			[1] Failure Status
        # 			[2] Start time of result
        # 			[3] End time of result
        # 			[4][0] BigFix Computer ID
        # 			[4][1] BigFix Computer Name
        print("-----------------------------------\n")
        print(json.dumps(row, indent=2))

        action_top = row[0]
        action_name = row[1]

        sub_id = row[3][0][0]
        sub_name = row[3][0][1]
        sub_failure = row[3][1]
        sub_fail_start = row[3][2]
        sub_fail_end = row[3][3]
        sub_comp_id = row[3][4][0]
        sub_comp_name = row[3][4][1]

        # The key is the "top-id"-"sub-id"-"comp-id"
        ticketKey = f"{str(action_top)}-{str(sub_comp_id)}"

        # If key is not in ticketHash
        if not ticketKey in ticketHash:
            # Populate the POST with values
            post["EventList"][0][
                "title"
            ] = f"""DXC IT BigFix Patching failed for server \
{sub_comp_name} on {sub_fail_end}"""
            post["EventList"][0][
                "longDescription"
            ] = f"""DXC IT BigFix Patching failed for server \
{sub_comp_name}. The BigFix patch action {action_name} \
id {str(action_top)} failed for computer {sub_comp_name} \
id {str(sub_comp_id)} with status {sub_failure}. Sub action \
{sub_name} id {str(sub_id)} was the first failed item."""
            post["EventList"][0]["node"] = sub_comp_name
            post["EventList"][0]["eventsourcesendingserver"] = fqdn

            # Generate the ticket
            session.auth = (sn_username, sn_password)
            snreq = requests.Request(
                "POST", f"{sn_url}/dxc/events/R1/create", json=post
            )

            snprepped = session.prepare_request(snreq)

            try:
                snresult = session.send(snprepped, verify=False)

                # DEBUG log http result from servicenow API call
                with open("servicenow-results.log", "a", encoding="utf-8") as snr:
                    snr.write(str(snresult))
                    snr.write(str(snresult.status_code))
                    snr.write(snresult.text)
                    snr.write(snresult.url)
                    snr.write(str(snresult.headers))

            except Exception as err:
                # FIXME: Handle specific expected exceptions
                # DEBUG log http result from servicenow API call
                with open("servicenow-results.log", "a", encoding="utf-8") as snr:
                    snr.write(str(err.with_traceback))

            ticketHash[ticketKey] = time.time()

            # Try to write the ticketHash
            with open("genticketData.json", "w", encoding="utf-8") as ticketFile:
                json.dump(ticketHash, ticketFile, indent=2)

            # Log the SN REST transaction
            with open(
                f"SNAPI-{str(action_top)}-{str(sub_comp_id)}.json",
                "a",
                encoding="utf-8",
            ) as restFile:
                json.dump(post, restFile, indent=4)
else:
    print("Query [" + query + "] failed.")
    print(result)

with open("servicenow-results.log", "a", encoding="utf-8") as snr:
    snr.write("Normal termination\n")
