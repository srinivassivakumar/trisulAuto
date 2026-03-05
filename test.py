# Import asyncio for async/await coroutine support
import asyncio
# Import zmq (ZeroMQ) for message queue connectivity
import zmq
# Import ZeroMQ async context and sockets
import zmq.asyncio
# Import json for JSON parsing and serialization
import json
# Import re for regular expression pattern matching
import re
# Import datetime for timestamp generation
from datetime import datetime
# Import escape function to sanitize HTML content for XSS prevention
from html import escape
# Import Path for cross-platform file path handling
from pathlib import Path


# Custom exception class for HTTP-style errors with status codes
class HttpError(Exception):
    # Constructor that stores error message and HTTP status code
    def __init__(self, message, code=500):
        # Call parent Exception constructor with message
        super().__init__(message)
        # Store HTTP status code as instance attribute
        self.code = code


# ========== API Counter Group Topper ==========
# Async function to fetch counter group topper data (top N items by metric value)
async def apiCounterGroupTopper(groupId, meter=0, from_ts=0, to_ts=0, line=0, maxitems=1000, key_filter="", datacenter="IN-MUM-WEST-1"):
    # Check if both timestamp boundaries are provided
    if from_ts is not None and to_ts is not None:
        # Build request object with time interval constraints
        reqObj = {
            # Counter group ID to query
            "counter_group": groupId,
            # Specific meter index within the group
            "meter": meter,
            # Maximum number of items to return
            "maxitems": maxitems,
            # Time window for data aggregation
            "time_interval": {"from": {"tv_sec": from_ts}, "to": {"tv_sec": to_ts}}
        }
    else:
        # Build request object without time constraints
        reqObj = {
            "counter_group": groupId,
            "meter": meter,
            "maxitems": maxitems
        }

    # If a key filter is provided, add it to the request
    if key_filter:
        # Add filtering condition to narrow down results
        reqObj["key_filter"] = key_filter

    # Wraps low-level getData call in error handling
    try:
        # Call getData with command index 3 (COUNTER_GROUP_TOPPER_REQUEST)
        data = await getData(3, reqObj, line, datacenter)
        # Extract the message portion (actual data) from response
        resObj = data["message"]
    except Exception as error:
        # Convert exception to string for logging
        message = str(error)
        # Print error to console for debugging
        print("Caught error:", message)
        # Re-raise as HttpError with 500 status code
        raise HttpError(message, 500)

    # Return the counter data
    return resObj


# ========== Get Data ==========
# Core async function that sends TRP (Trisul Remote Protocol) requests to Trisul server
async def getData(index, data, line=0, datacenter="IN-MUM-WEST-1"):
    # Outer try-catch to handle all exceptions uniformly
    try:
        # Initialize command variable as None
        trp_command = None

        # Map index number to TRP command type
        if index == 1:
            # Index 1 maps to hello/handshake request
            trp_command = "HELLO_REQUEST"
        elif index == 2:
            # Index 2 maps to counter group info request
            trp_command = "COUNTER_GROUP_INFO_REQUEST"
        elif index == 3:
            # Index 3 maps to counter group topper (top N) request
            trp_command = "COUNTER_GROUP_TOPPER_REQUEST"
        elif index == 4:
            # Index 4 maps to single counter item request
            trp_command = "COUNTER_ITEM_REQUEST"
        elif index == 5:
            # Index 5 maps to session query request
            trp_command = "QUERY_SESSIONS_REQUEST"
        elif index == 6:
            # Index 6 maps to alert query request
            trp_command = "QUERY_ALERTS_REQUEST"

        # Build TRP request message from command and data payload
        try:
            # Create protobuf-encoded request message
            req = mk_trp_request(trp_command, data)
        except Exception:
            # If request building fails, indicate server error
            raise HttpError("Server Down 2", 504)

        # Get Trisul server connection credentials for specified datacenter
        try:
            # Fetch host/port for datacenter from credentials database
            trisulserver = await getTrisulCredentials(datacenter, line)
            # Check if datacenter was found (code 500 means not found)
            if trisulserver.get("code") == 500:
                # Raise error if datacenter does not exist
                raise HttpError("Datacenter not found", 500)
        except Exception as error:
            # Extract error code (default to 500)
            code = getattr(error, "code", 500)
            # Extract error message (default to string representation)
            message = getattr(error, "message", str(error))
            # Re-raise with preserved error code
            raise HttpError(message, code)

        # Choose request path based on whether we're using a dedicated lease line
        if line == 0:
            # Standard request for shared resources
            try:
                # Send request via standard ZeroMQ socket
                responseObj = await sendZeroMQRequest(req, trisulserver["host"], trisulserver["port"])
            except Exception as error:
                # Log error and return server down status
                print(error)
                raise HttpError("Server Down 3", 504)
        else:
            # Lease-line request with different timeout/reliability handling
            try:
                # Send request via lease-line ZeroMQ socket
                responseObj = await sendZeroMQRequestLeaseLine(req, trisulserver["host"], trisulserver["port"])
            except Exception as error:
                # Log the error
                print(error)
                # Check if error was a timeout (408 response code)
                if getattr(error, "message", str(error)) == "Request timeout":
                    # Propagate timeout error with 408 code
                    raise HttpError("Request timeout", 408)
                # Otherwise, report as generic server error
                raise HttpError("Server Down 3", 504)

        # Return successfully with response data
        return {"err": 0, "message": responseObj}

    # If already an HttpError, re-raise it unchanged
    except HttpError:
        raise
    # Catch-all for unexpected exceptions
    except Exception as error:
        # Log the exception
        print(error)
        # Return generic server error
        raise HttpError("Server Down 4", 504)


# ========== ZeroMQ Request - Standard ==========
# Async function to send message via ZeroMQ and receive response with timeout
async def sendZeroMqRequest(req, host="10.192.1.53", port="12001"):
    # Create ZeroMQ async context for managing sockets
    context = zmq.asyncio.Context()
    # Create request-reply socket (REQ type)
    sock = context.socket(zmq.REQ)

    # Wraps socket operations in error handling
    try:
        # Connect socket to Trisul server TCP address
        sock.connect(f"tcp://{host}:{port}")
        # Send serialized TRP request message to server
        await sock.send(req)

        # Wrap receive with timeout to prevent hanging
        try:
            # Wait for server response with 40-second timeout
            msg = await asyncio.wait_for(sock.recv(), timeout=40)
        except asyncio.TimeoutError:
            # Close socket immediately on timeout
            sock.close()
            # Raise timeout error with 408 status code
            raise HttpError("Request timeout", 408)

        # Decode TRP response message from protobuf
        response = unwrap_response(msg)
        # Return parsed response
        return response

    # Catch all ZeroMQ and other communication errors
    except Exception as error:
        # Log error details for debugging
        print("Error during ZeroMQ communication:", error)
        # Return communication error with 500 status code
        raise HttpError("Error during ZeroMQ communication", 500)

    # Guaranteed cleanup of socket resources
    finally:
        # Close socket to release TCP connection
        sock.close()


# ========== ZeroMQ Request - Lease Line ==========
# Async function for dedicated lease-line requests with special timeout handling
async def sendZeroMQRequestLeaseLine(req, host="10.192.1.53", port="12001"):
    # Create ZeroMQ async context for managing sockets
    context = zmq.asyncio.Context()
    # Create request-reply socket for this dedicated connection
    sock = context.socket(zmq.REQ)

    # Main error handler for socket operations
    try:
        # Connect to Trisul server on specified host/port
        sock.connect(f"tcp://{host}:{port}")
        # Transmit request message to server
        await sock.send(req)

        # Receive with timeout protection
        try:
            # Wait for response with 40-second timeout limit
            msg = await asyncio.wait_for(sock.recv(), timeout=40)
        except asyncio.TimeoutError:
            # Immediately close socket on timeout
            sock.close()
            # Raise timeout error with 408 status
            raise HttpError("Request timeout", 408)

        # Parse TRP response from wire format
        response = unwrap_response(msg)
        # Return decoded response
        return response

    # Handle HttpError exceptions (e.g., from timeout above)
    except HttpError as error:
        # Check if this is a timeout error
        if getattr(error, "message", str(error)) == "Request timeout":
            # Re-raise timeout unchanged to distinguish from other errors
            raise
        # Log non-timeout HttpErrors
        print("Error during ZeroMQ communication:", error)
        # Convert to generic communication error
        raise HttpError("Error during ZeroMQ communication", 500)
    # Handle any other exception type
    except Exception as error:
        # Log communication error details
        print("Error during ZeroMQ communication:", error)
        # Wrap in HttpError with 500 status code
        raise HttpError("Error during ZeroMQ communication", 500)

    # Always cleanup socket resources
    finally:
        # Close socket to free TCP connection
        sock.close()


# ========== TCP Issues Analyzer ==========
# Main async function that orchestrates the entire TCP issue detection pipeline
async def analyzeTcpIssues(from_ts=0, to_ts=0, datacenter="IN-MUM-WEST-1", line=0):

    # Outer try-catch for top-level error handling
    try:
        # Retrieve TCP analyzer counter group ID from database
        try:
            # Query database for counter group 19 (TCP Analyzer)
            groupId = await getCounterGroupIdFromDB(19, datacenter, line)
            # Validate that a counter group was found
            if not groupId:
                # Raise error if counter group doesn't exist
                raise HttpError("Failed to retrieve TCP Analyzer Counter Group ID", 500)
        except Exception as error:
            # Wrap any error in a user-friendly message
            raise HttpError(f"Failed to get Counter Group ID: {str(error)}", 500)

        # Define mapping of meter indices to human-readable metric names
        # Define mapping of meter indices to human-readable metric names
        meterMapping = {
            # Meter 0: Internal network latency measurement
            0: "Avg Latency Internal",
            # Meter 1: External/WAN latency measurement
            1: "Avg Latency External",
            # Meter 2: Internal retransmission packet count
            2: "Retrans Internal",
            # Meter 3: External retransmission packet count
            3: "Retrans External",
            # Meter 4: Internal retransmission rate percentage
            4: "Retrans Rate Internal",
            # Meter 5: External retransmission rate percentage
            5: "Retrans Rate External",
            # Meter 6: Count of flows with poor quality metrics
            6: "Poor Quality Flows",
            # Meter 7: Count of connection timeouts
            7: "Timeouts",
            # Meter 8: Count of unidirectional (asymmetric) flows
            8: "Unidirectional Flows"
        }

        # List of metrics indicating internal network path issues
        internalIssueIndicators = [
            # High latency within LAN suggests internal congestion
            "Avg Latency Internal",
            # Retransmissions inside network indicate packet loss
            "Retrans Internal",
            # High retransmit rate suggests severe congestion
            "Retrans Rate Internal",
            # Poor quality flows indicate degraded internal paths
            "Poor Quality Flows",
            # Timeouts suggest internal connectivity issues
            "Timeouts",
            # Unidirectional flows indicate asymmetric internal routing
            "Unidirectional Flows"
        ]

        # List of metrics indicating external/WAN path issues
        externalIssueIndicators = [
            # High latency to external hosts suggests WAN issues
            "Avg Latency External",
            # External retransmissions indicate WAN packet loss
            "Retrans External",
            # High external retransmit rate indicates WAN degradation
            "Retrans Rate External",
            # Poor quality is relevant to both internal and external paths
            "Poor Quality Flows",
            # Asymmetric flows with external hosts indicate routing issues
            "Unidirectional Flows"
        ]

        # Build list of async tasks to fetch top-5 items for each meter
        meterTasks = [
            # Create coroutine for each meter to fetch its top 5 items
            apiCounterGroupTopper(groupId, meter=i, from_ts=from_ts, to_ts=to_ts, line=line, maxitems=5, datacenter=datacenter)
            # Iterate over all meter indices in mapping
            for i in meterMapping.keys()
        ]

        # Execute all meter queries in parallel
        try:
            # Wait for all tasks to complete and collect results
            meterResults = await asyncio.gather(*meterTasks)
        except Exception as error:
            # If any fetch fails, report fetch error
            raise HttpError(f"Failed to fetch counter topper data: {str(error)}", 500)

        # Dictionary to aggregate issues by IP address
        ipIssueMap = {}

        # Iterate through each meter result with its index
        for meterIndex, result in enumerate(meterResults):

            # Get human-readable name for this meter
            meterName = meterMapping[meterIndex]

            # Skip if result is not a list (malformed response)
            if not isinstance(result, list):
                continue

            # Process each item in the meter result
            for item in result:

                # Extract IP address from result (try 'key' first, then 'ip')
                ip = item.get("key") or item.get("ip")

                # Skip items without an IP address
                if not ip:
                    continue

                # Initialize IP entry if not already present
                if ip not in ipIssueMap:
                    # Create tracking structure for this IP
                    ipIssueMap[ip] = {
                        # List of internal metrics with issues
                        "internalIssues": [],
                        # List of external metrics with issues
                        "externalIssues": [],
                        # Dictionary storing metric values
                        "values": {}
                    }

                # Classify metric as internal issue if applicable
                if meterName in internalIssueIndicators:
                    # Add only if not already in list (avoid duplicates)
                    if meterName not in ipIssueMap[ip]["internalIssues"]:
                        # Add internal issue to IP's issue list
                        ipIssueMap[ip]["internalIssues"].append(meterName)

                # Classify metric as external issue if applicable
                if meterName in externalIssueIndicators:
                    # Add only if not already in list (avoid duplicates)
                    if meterName not in ipIssueMap[ip]["externalIssues"]:
                        # Add external issue to IP's issue list
                        ipIssueMap[ip]["externalIssues"].append(meterName)

                # Store the metric value (try 'value' first, then 'val', default to 0)
                ipIssueMap[ip]["values"][meterName] = item.get("value") or item.get("val") or 0

        # Define path to cookbook file containing issue combinations and solutions
        cookbook_path = Path("C:/sri/trisulauto/Improved_Network_Issues_Detailed.txt")

        # Read cookbook content for pattern matching
        try:
            # Load cookbook text file
            cookbookContent = cookbook_path.read_text()
        except Exception as error:
            # Log file read failure but continue with empty cookbook
            print(f"Failed to read cookbook file: {str(error)}")
            # Use empty string so parser doesn't crash
            cookbookContent = ""

        # Parse cookbook into rule dictionary
        cookbookRules = parseCookbook(cookbookContent)

        # List to accumulate final analysis results
        results = []

        # Process each IP's aggregated issues
        for ip, issueData in ipIssueMap.items():

            # Skip IPs with no issues detected
            if len(issueData["internalIssues"]) == 0 and len(issueData["externalIssues"]) == 0:
                # Continue to next IP
                continue

            # Combine internal and external issues for matching
            allIssues = issueData["internalIssues"] + issueData["externalIssues"]

            # Match issues against cookbook rules to get root cause and solution
            rootCause, solution = matchCookbookRules(allIssues, cookbookRules, issueData["internalIssues"], issueData["externalIssues"])

            # Append result for this IP to output list
            results.append({
                # IP address with issues
                "ip": ip,
                # Internal network path issues
                "internalIssues": issueData["internalIssues"],
                # External WAN path issues
                "externalIssues": issueData["externalIssues"],
                # Metric values for this IP
                "values": issueData["values"],
                # Root cause from cookbook or fallback logic
                "probableRootCause": rootCause,
                # Recommended remediation steps
                "recommendedSolution": solution
            })

        # Return final analysis results
        return results

    # Re-raise HttpErrors unchanged
    except HttpError:
        raise
    # Catch-all for unexpected exceptions
    except Exception as error:
        # Log error for debugging
        print("Error in analyzeTcpIssues:", error)
        # Wrap in HttpError with 500 status
        raise HttpError(f"TCP Issues Analysis failed: {str(error)}", 500)


# -----------------------------
# Cookbook Parser
# -----------------------------
def parseCookbook(content):

    rules = {}

    sections = content.split("### ")

    for section in sections:

        lines = section.split("\n")

        if len(lines) < 2:
            continue

        title = lines[0]

        match = re.match(r"^([A-Z%]+)\s*\+\s*([A-Z%]+)(.*)$", title)

        if not match:
            continue

        issue1 = match.group(1)
        issue2 = match.group(2)

        key = "+".join(sorted([issue1, issue2]))

        whatsWrong = ""
        howToFix = ""

        ww = re.search(r"\*\*What's going wrong:\*\*\n([\s\S]*?)(?:\n\*\*|$)", section)
        if ww:
            whatsWrong = ww.group(1).strip()

        hf = re.search(r"\*\*How to fix:\*\*\n([\s\S]*?)(?:\n---|\n\n###|$)", section)
        if hf:
            howToFix = hf.group(1).strip()

        rules[key] = {
            "issues": [issue1, issue2],
            "rootCause": whatsWrong,
            "solution": howToFix
        }

    return rules


# ========== Issue Abbreviation Mapping ==========
# Dictionary mapping short abbreviations to full issue names
issueAbbreviationMap = {
    # Latency abbreviation
    "LAT": "Avg Latency",
    # Retransmission abbreviation
    "RPKT": "Retrans",
    # Retransmit rate abbreviation
    "R": "Retrans Rate",
    # Poor quality flow abbreviation
    "PQF": "Poor Quality Flows",
    # Timeout abbreviation
    "TO": "Timeouts",
    # Unidirectional flow abbreviation
    "UNI": "Unidirectional Flows",
}


# ========== Cookbook Rule Matching ==========
# Function that matches detected issues against cookbook rules and returns remediation
def matchCookbookRules(allIssues, cookbookRules, internalIssues, externalIssues):

    # Initialize probable root cause as empty string
    probableRootCause = ""
    # Initialize recommended solution as empty string
    recommendedSolution = ""

    # Only attempt cookbook matching if 2+ issues present
    if len(allIssues) >= 2:

        # List to store abbreviated issue codes
        abbrev = []

        # Convert each issue name to short abbreviation
        for issue in allIssues:

            # Check for latency indicators and convert to abbreviations
            if "Latency Internal" in issue:
                # Abbreviate internal latency
                abbrev.append("LAT-INT")
            elif "Latency External" in issue:
                # Abbreviate external latency
                abbrev.append("LAT-EXT")
            # Check for retransmission indicators
            elif "Retrans Internal" in issue:
                # Abbreviate internal retransmissions
                abbrev.append("RPKT-INT")
            elif "Retrans External" in issue:
                # Abbreviate external retransmissions
                abbrev.append("RPKT-EXT")
            # Check for retransmit rate indicators
            elif "Retrans Rate Internal" in issue:
                # Abbreviate internal retransmit rate
                abbrev.append("R%-INT")
            elif "Retrans Rate External" in issue:
                # Abbreviate external retransmit rate
                abbrev.append("R%-EXT")
            # Check for poor quality flows
            elif "Poor Quality" in issue:
                # Abbreviate poor quality flows
                abbrev.append("PQF")
            # Check for timeouts
            elif "Timeouts" in issue:
                # Abbreviate timeout issues
                abbrev.append("TO")
            # Check for unidirectional flows
            elif "Unidirectional" in issue:
                # Abbreviate unidirectional flows
                abbrev.append("UNI")
            # Use original if no abbreviation matches
            else:
                # Keep original if no abbreviation applies
                abbrev.append(issue)

        # Check all combinations of 2 issues from the list
        for i in range(len(abbrev)):
            # Nested loop for pairs starting after current index
            for j in range(i + 1, len(abbrev)):

                # Create combination key by sorting and joining
                combo = "+".join(sorted([abbrev[i], abbrev[j]]))

                # Check if this combination exists in cookbook
                if combo in cookbookRules:

                    # Get the matching rule
                    rule = cookbookRules[combo]

                    # Extract root cause from rule
                    probableRootCause = rule["rootCause"]
                    # Extract solution from rule
                    recommendedSolution = rule["solution"]

                    # Return immediately when match found
                    return probableRootCause, recommendedSolution

    # Fallback logic if no cookbook pattern matched: check issue categories
    # If only internal issues detected
    if internalIssues and not externalIssues:
        # Set root cause for internal-only issues
        probableRootCause = (
            # Describe issue location and likely causes
            "Issues detected in internal network path. Possible causes: server overload, "
            "internal link congestion, or security policy delays."
        )
        # Provide step-by-step remediation for internal issues
        recommendedSolution = (
            "1. Check internal network capacity and utilization\n"
            "2. Verify server resources (CPU, memory, disk I/O)\n"
            "3. Review firewall/security appliance logs\n"
            "4. Check QoS policies on internal segments\n"
            "5. Monitor internal network device health"
        )

    # If only external issues detected
    elif externalIssues and not internalIssues:
        # Set root cause for external-only issues
        probableRootCause = (
            # Describe issue location and likely causes
            "Issues detected in external/WAN path. Possible causes: WAN congestion, "
            "ISP throttling, or connection quality degradation."
        )
        # Provide step-by-step remediation for external issues
        recommendedSolution = (
            "1. Check WAN link utilization and capacity\n"
            "2. Review ISP service quality metrics\n"
            "3. Verify routing through backup paths\n"
            "4. Check external firewall rules\n"
            "5. Consider WAN optimization appliances"
        )

    # If both internal and external issues detected
    elif internalIssues and externalIssues:
        # Set root cause for end-to-end issues
        probableRootCause = (
            # Describe issue spanning both paths
            "Issues detected in both internal and external paths. Possible causes: "
            "end-to-end network degradation, multiple failure points, or pervasive congestion."
        )
        # Provide comprehensive remediation for end-to-end issues
        recommendedSolution = (
            "1. Perform comprehensive network audit\n"
            "2. Check both internal and external gateway configurations\n"
            "3. Analyze traffic flow end-to-end\n"
            "4. Review capacity planning for both segments\n"
            "5. Implement monitoring across all network segments"
        )

    # Return matched or fallback root cause and solution
    return probableRootCause, recommendedSolution


# ========== Smoke Test Function ==========
# Function that validates core parsing and matching logic
def _run_smoke_tests():
        # Create sample cookbook text for testing
        sample_cookbook = """### LAT + RPKT
**What's going wrong:**
Latency and retransmissions indicate packet loss or congestion.
**How to fix:**
Investigate links and queues.
---
"""

        # Parse the sample cookbook
        rules = parseCookbook(sample_cookbook)
        # Verify that the rule was extracted correctly
        if "LAT+RPKT" not in rules:
                # Fail if parsing didn't work
                raise AssertionError("parseCookbook did not extract LAT+RPKT rule")

        # Test exact rule matching
        root_cause, solution = matchCookbookRules(
                # Issues list with both internal metrics
                ["Avg Latency Internal", "Retrans Internal"],
                # Pre-populated rules for testing
                {"LAT-INT+RPKT-INT": {"rootCause": "Internal congestion", "solution": "Check LAN"}},
                # Internal issues list
                ["Avg Latency Internal", "Retrans Internal"],
                # No external issues
                [],
        )
        # Verify exact match returns correct values
        if root_cause != "Internal congestion" or solution != "Check LAN":
                # Fail if matching logic is broken
                raise AssertionError("matchCookbookRules exact combo match failed")


# ========== Timestamp Formatter ==========
# Function that formats datetime to 12-hour clock string with AM/PM
def _format_generated_timestamp(dt):
        # Convert 24-hour hour to 12-hour format
        hour_12 = dt.hour % 12
        # Handle midnight (0 should become 12)
        if hour_12 == 0:
                hour_12 = 12
        # Determine AM or PM based on hours
        am_pm = "am" if dt.hour < 12 else "pm"
        # Return formatted timestamp string
        return f"{dt.month}/{dt.day}/{dt.year}, {hour_12}:{dt.minute:02d}:{dt.second:02d} {am_pm}"


# ========== HTML Report Renderer ==========
# Function that converts analysis results to styled HTML report
def _render_tcp_report_html(results, generated_text):
        # List to accumulate HTML for each IP section
        ip_sections = []

        # Process each result item (one per IP with issues)
        for item in results:
                # Extract and escape IP address from result
                ip = escape(str(item.get("ip", "-")))
                # Get internal issues list (empty list if not present)
                internal_issues = item.get("internalIssues", []) or []
                # Get external issues list (empty list if not present)
                external_issues = item.get("externalIssues", []) or []
                # Get metric values dict (empty dict if not present)
                values = item.get("values", {}) or {}
                # Extract and escape root cause text
                root_cause = escape(str(item.get("probableRootCause", "")))
                # Extract and escape solution text
                solution = escape(str(item.get("recommendedSolution", "")))

                # Build HTML list items for internal issues
                internal_html = "".join(
                        # Create list item for each internal issue with escaped text
                        f'<li class="internal-issue">{escape(str(issue))}</li>' for issue in internal_issues
                )
                # Build HTML list items for external issues
                external_html = "".join(
                        # Create list item for each external issue with escaped text
                        f'<li class="external-issue">{escape(str(issue))}</li>' for issue in external_issues
                )
                # Build HTML table rows for metric values
                values_html = "".join(
                        # Create row div for each metric with escaped key and value
                        f'<div class="values-row"><span>{escape(str(k))}</span><span><strong>{escape(str(v))}</strong></span></div>'
                        for k, v in values.items()
                )

                # Append complete IP section HTML to list
                # Append complete IP section HTML to list
                ip_sections.append(
                        # HTML template for IP analysis section
                        f"""
    <div class="ip-container">
        <!-- IP header with address -->
        <div class="ip-header">📡 IP Address: {ip}</div>

        <!-- Issues grid with internal and external columns -->
        <div class="issues">
            <div class="issue-group">
                <!-- Internal network path issues -->
                <h3>🔴 Internal Issues ({len(internal_issues)})</h3>
                <ul>
                    {internal_html}
                </ul>
            </div>

            <div class="issue-group">
                <!-- External WAN path issues -->
                <h3>🔵 External Issues ({len(external_issues)})</h3>
                <ul>
                    {external_html}
                </ul>
            </div>
        </div>

        <!-- Root cause from cookbook or fallback logic -->
        <div class="root-cause">
            <strong>⚠️ Probable Root Cause:</strong><br>
            {root_cause}
        </div>

        <!-- Recommended remediation steps -->
        <div class="solution">
            <strong>✅ Recommended Solution:</strong><br>
            {solution}
        </div>

        <!-- Metric values for each detected issue -->
        <div class="values">
            <strong>📊 Metric Values:</strong><br>
            {values_html}
        </div>
    </div>
"""
                )

        # Join all IP sections with newlines
        # Join all IP sections with newlines for final HTML body
        body_sections = "\n".join(ip_sections)

        # Return complete HTML document as string
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>TCP Issues Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .ip-container {{
            background: white;
            margin: 20px 0;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .ip-header {{
            background-color: #4CAF50;
            color: white;
            padding: 10px;
            border-radius: 5px;
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 15px;
        }}
        .issues {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 15px;
        }}
        .issue-group h3 {{
            color: #333;
            margin-top: 0;
            border-bottom: 2px solid #ddd;
            padding-bottom: 10px;
        }}
        .issue-group ul {{
            list-style-type: none;
            padding: 0;
        }}
        .issue-group li {{
            background: #f0f0f0;
            padding: 8px 12px;
            margin: 5px 0;
            border-left: 4px solid #4CAF50;
            border-radius: 3px;
        }}
        .internal-issue {{ border-left-color: #FF9800; }}
        .external-issue {{ border-left-color: #2196F3; }}
        .root-cause {{
            background: #fff3cd;
            padding: 12px;
            border-left: 4px solid #ffc107;
            border-radius: 3px;
            margin: 15px 0;
        }}
        .solution {{
            background: #d1ecf1;
            padding: 12px;
            border-left: 4px solid #17a2b8;
            border-radius: 3px;
            margin: 15px 0;
            white-space: pre-wrap;
        }}
        .values {{
            background: #f9f9f9;
            padding: 12px;
            border-radius: 3px;
            margin: 15px 0;
            font-family: monospace;
        }}
        .values-row {{
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }}
        .values-row:last-child {{ border-bottom: none; }}
    </style>
</head>
<body>
    <h1>🔍 TCP Issues Analysis Report</h1>
    <p><strong>Generated:</strong> {escape(generated_text)}</p>
    <hr>
{body_sections}
</body>
</html>
"""


# ========== HTML Report Generator ==========
# Function that reads JSON analysis results and writes HTML report
def generate_html_report_from_json(
        # Input JSON file containing analysis results
        json_path=Path("C:/sri/trisulauto/tcp-analysis-results.json"),
        # Output HTML file path
        html_path=Path("C:/sri/trisulauto/tcp-report.html"),
):
        # Check if input JSON file exists
        if not json_path.exists():
                # Raise error if file is missing
                raise FileNotFoundError(f"JSON input file not found: {json_path}")

        # Open and parse JSON file
        with json_path.open("r", encoding="utf-8") as handle:
                # Load JSON data from file
                data = json.load(handle)

        # Validate that JSON contains an array
        if not isinstance(data, list):
                # Raise error if data structure is wrong
                raise ValueError("Expected tcp-analysis-results.json to contain a JSON array")

        # Generate current timestamp for report
        generated_text = _format_generated_timestamp(datetime.now())
        # Convert analysis data to HTML string
        html_output = _render_tcp_report_html(data, generated_text)
        # Write HTML string to output file
        html_path.write_text(html_output, encoding="utf-8")
        # Return file path, timestamp, and record count for confirmation
        return html_path, generated_text, len(data)


# ========== Main Execution Block ==========
# Entry point when script is run directly
if __name__ == "__main__":
        # Execute smoke tests
        _run_smoke_tests()
        # Print success message for smoke tests
        print("PASS: Smoke tests succeeded")
        # Print success message for parser validation
        print("PASS: Parser and cookbook matching behavior validated")

        # Generate HTML report from JSON data
        report_path, generated_at, record_count = generate_html_report_from_json()
        # Print success message with generation timestamp
        print(f"PASS: HTML report updated at {generated_at}")
        # Print success message with record count
        print(f"PASS: Records rendered: {record_count}")
        # Print output file path for reference
        print(f"PASS: Output file: {report_path}")