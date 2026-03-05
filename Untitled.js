const apiCounterGroupTopper = async ({
  groupId,
  meter = 0,
  from = 0,
  to = 0,
  line = 0,
  maxitems = 1000,
  key_filter = "",
  datacenter = "IN-MUM-WEST-1"
}) => {
  let reqObj;
  let resObj;
  if (typeof from != "undefined" && typeof to != "undefined") {
    reqObj = {
      counter_group: groupId,
      meter: meter,
      maxitems: maxitems,
      time_interval: {
        from: {
          tv_sec: from,
        },
        to: {
          tv_sec: to,
        },
      },
    };
  } else {
    reqObj = {
      counter_group: groupId,
      meter: meter,
      maxitems: maxitems,
    };
  }
  if (key_filter.length > 0 && key_filter != "") {
    reqObj["key_filter"] = key_filter;
  }

  let data;
  try {
    data = await Trisul.getData(3, reqObj, line, datacenter);

    resObj = data.message;
  } catch (error) {
    let message;

    if (error instanceof Error) {
      message = error.message;
    } else if (typeof error === "string") {
      message = error;
    } else {
      message = JSON.stringify(error);
    }

    console.error("Caught error:", message);

    throw new HttpError(message, 500);
  }
  return resObj;
};


const getData = (index, data, line = 0, datacenter = "IN-MUM-WEST-1") => {
  return new Promise((resolve, reject) => {
    try {
      protobuf.parse.defaults.keepCase = true;
      protobuf.load("trp.proto", async function (err, builder) {
        if (err) {
          console.log(err);
          console.log(err);
          reject({ err: 1, err_code: 504, message: "Server Down 0" });
        }

        let TRP;
        try {
          TRP = builder.lookup("TRP");
        } catch (error) {
          console.error("Server Error:", error);

          reject({
            err: 1,
            err_code: 504,
            message: "Server Down",
          });
        }

        let trp_command;
        switch (index) {
          case 1:
            trp_command = TRP.Message.Command.HELLO_REQUEST;
            break;
          case 2:
            trp_command = TRP.Message.Command.COUNTER_GROUP_INFO_REQUEST;
            break;
          case 3:
            trp_command = TRP.Message.Command.COUNTER_GROUP_TOPPER_REQUEST;
            break;
          case 4:
            trp_command = TRP.Message.Command.COUNTER_ITEM_REQUEST;
            break;
          case 5:
            trp_command = TRP.Message.Command.QUERY_SESSIONS_REQUEST;
            break;
          case 6:
            trp_command = TRP.Message.Command.QUERY_ALERTS_REQUEST;
            break;
        }

        let req;
        try {
          req = mk_trp_request(TRP, trp_command, data);
        } catch (error) {
          reject({ err: 1, err_code: 504, message: "Server Down 2" });
        }

        // *** GET Trisul Server Data ***
        let trisulserver;
        try {
          trisulserver = await getTrisulCredentials(datacenter, line);
          if (trisulserver?.code == 500)
            reject({ err: 1, err_code: 500, message: "Datacenter not found" });
        } catch (error) {
          trisulserver = {
            host: "",
            port: "",
            line: 0,
            datacenter: "",
          };
          reject({ err: 1, err_code: error.code, message: error.message });
        }

        if (line == 0) {
          let responseObj;
          try {
            responseObj = await sendZeroMQRequest(
              TRP,
              req,
              trisulserver.host,
              trisulserver.port
            );
            resolve({ err: 0, message: responseObj });
          } catch (error) {
            console.log(error);
            reject({ err: 1, err_code: 504, message: "Server Down 3" });
          }
        } else {
          let responseObj;
          try {
            responseObj = await sendZeroMQRequestLeaseLine(
              TRP,
              req,
              trisulserver.host,
              trisulserver.port
            );
            resolve({ err: 0, message: responseObj });
          } catch (error) {
            console.log(error);
            if (error?.message == "Request timeout")
              reject({ err: 1, err_code: 408, message: "Request timeout" });
            reject({ err: 1, err_code: 504, message: "Server Down 3" });
          }
        }
      });
    } catch (error) {
      console.log(error);
      reject({ err: 1, err_code: 504, message: "Server Down 4" });
    }
  });
};

const sendZeroMQRequest = async (
  TRP,
  req,
  host = "10.192.1.53",
  port = "12001"
) => {
  const sock = new zmq.Request();

  try {
    await sock.connect(`tcp://${host}:${port}`);
    await sock.send(req);

    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => {
        sock.close();
        reject({ message: "Request timeout" });
      }, 40000)
    );

    const receivePromise = (async () => {
      const [msg] = await sock.receive();
      const response = unwrap_response(TRP, msg);
      return response;
    })();

    const result = await Promise.race([receivePromise, timeoutPromise]);
    return result;
  } catch (error) {
    console.error("Error during ZeroMQ communication:", error);
    throw new HttpError("Error during ZeroMQ communication", 500);
  } finally {
    sock.close();
  }
};


// *** TCP Issues Analyzer ***
const analyzeTcpIssues = async ({
  from = 0,
  to = 0,
  datacenter = "IN-MUM-WEST-1",
  line = 0
}) => {
  const fs = require("fs").promises;
  const path = require("path");

  try {
    // Step 1: Get TCP Analyzer Counter Group ID
    let groupId;
    try {
      const result = await getCounterGroupIdFromDB(19, datacenter, line);
      groupId = result;
      if (!groupId) {
        throw new Error("Failed to retrieve TCP Analyzer Counter Group ID");
      }
    } catch (error) {
      throw new HttpError(
        `Failed to get Counter Group ID: ${error.message}`,
        500
      );
    }

    // Step 2: Define TCP Analyzer Meters
    const meterMapping = {
      0: "Avg Latency Internal",
      1: "Avg Latency External",
      2: "Retrans Internal",
      3: "Retrans External",
      4: "Retrans Rate Internal",
      5: "Retrans Rate External",
      6: "Poor Quality Flows",
      7: "Timeouts",
      8: "Unidirectional Flows",
    };

    // Define issue groups
    const internalIssueIndicators = [
      "Avg Latency Internal",
      "Retrans Internal",
      "Retrans Rate Internal",
      "Poor Quality Flows",
      "Timeouts",
      "Unidirectional Flows",
    ];

    const externalIssueIndicators = [
      "Avg Latency External",
      "Retrans External",
      "Retrans Rate External",
      "Poor Quality Flows",
      "Unidirectional Flows",
    ];

    // Step 3: Fetch Top 5 IPs for Each Meter using Promise.all
    const meterPromises = Object.keys(meterMapping).map((meterIndex) =>
      apiCounterGroupTopper({
        groupId,
        meter: parseInt(meterIndex),
        from,
        to,
        line,
        maxitems: 5,
        datacenter,
      })
    );

    let meterResults;
    try {
      meterResults = await Promise.all(meterPromises);
    } catch (error) {
      throw new HttpError(
        `Failed to fetch counter topper data: ${error.message}`,
        500
      );
    }

    // Step 4: Build IP Issue Map
    const ipIssueMap = {};

    meterResults.forEach((result, meterIndex) => {
      const meterName = meterMapping[meterIndex];

      if (!result || !Array.isArray(result)) {
        return;
      }

      result.forEach((item) => {
        const ip = item.key || item.ip; // Adjust based on actual response structure
        if (!ip) return;

        if (!ipIssueMap[ip]) {
          ipIssueMap[ip] = {
            internalIssues: [],
            externalIssues: [],
            values: {},
          };
        }

        // Step 5: Classify Issues
        if (internalIssueIndicators.includes(meterName)) {
          if (!ipIssueMap[ip].internalIssues.includes(meterName)) {
            ipIssueMap[ip].internalIssues.push(meterName);
          }
        }

        if (externalIssueIndicators.includes(meterName)) {
          if (!ipIssueMap[ip].externalIssues.includes(meterName)) {
            ipIssueMap[ip].externalIssues.push(meterName);
          }
        }

        // Store metric value
        ipIssueMap[ip].values[meterName] = item.value || item.val || 0;
      });
    });

    // Step 6: Read and Parse Cookbook
    let cookbookContent;
    try {
      const cookbookPath = path.join(
        "C:\\sri\\trisulauto",
        "Improved_Network_Issues_Detailed.txt"
      );
      cookbookContent = await fs.readFile(cookbookPath, "utf-8");
    } catch (error) {
      console.error(`Failed to read cookbook file: ${error.message}`);
      cookbookContent = "";
    }

    // Step 6: Parse cookbook and build rule engine
    const cookbookRules = parseCookbook(cookbookContent);

    // Step 7: Build final output
    const results = [];

    for (const [ip, issueData] of Object.entries(ipIssueMap)) {
      // Only include IPs with at least one issue
      if (
        issueData.internalIssues.length === 0 &&
        issueData.externalIssues.length === 0
      ) {
        continue;
      }

      const allIssues = [
        ...issueData.internalIssues,
        ...issueData.externalIssues,
      ];

      // Match against cookbook rules
      const {
        probableRootCause,
        recommendedSolution,
      } = matchCookbookRules(
        allIssues,
        cookbookRules,
        issueData.internalIssues,
        issueData.externalIssues
      );

      results.push({
        ip,
        internalIssues: issueData.internalIssues,
        externalIssues: issueData.externalIssues,
        values: issueData.values,
        probableRootCause,
        recommendedSolution,
      });
    }

    return results;
  } catch (error) {
    console.error("Error in analyzeTcpIssues:", error);
    if (error instanceof HttpError) {
      throw error;
    }
    throw new HttpError(
      `TCP Issues Analysis failed: ${error.message}`,
      500
    );
  }
};

// *** Cookbook Parser ***
const parseCookbook = (cookbookContent) => {
  const rules = {};

  // Split by issue combinations (e.g., "LAT + RPKT")
  const sections = cookbookContent.split(/###\s+/);

  sections.forEach((section) => {
    const lines = section.split("\n");
    if (lines.length < 2) return;

    const titleLine = lines[0];
    const issueMatch = titleLine.match(
      /^([A-Z%]+)\s*\+\s*([A-Z%]+)(.*)$/
    );

    if (!issueMatch) return;

    const issue1 = issueMatch[1].trim();
    const issue2 = issueMatch[2].trim();
    const issueKey = [issue1, issue2].sort().join("+");

    // Extract "What's going wrong" section
    let whatsWrong = "";
    const whatsWrongMatch = section.match(
      /\*\*What's going wrong:\*\*\n([\s\S]*?)(?:\n\*\*|$)/
    );
    if (whatsWrongMatch) {
      whatsWrong = whatsWrongMatch[1].trim();
    }

    // Extract "How to fix" section
    let howToFix = "";
    const howToFixMatch = section.match(
      /\*\*How to fix:\*\*\n([\s\S]*?)(?:\n---|\n\n###|$)/
    );
    if (howToFixMatch) {
      howToFix = howToFixMatch[1].trim();
    }

    rules[issueKey] = {
      issues: [issue1, issue2],
      rootCause: whatsWrong,
      solution: howToFix,
    };
  });

  return rules;
};

// *** Issue Abbreviation Mapping ***
const issueAbbreviationMap = {
  LAT: "Avg Latency",
  RPKT: "Retrans",
  R: "Retrans Rate",
  PQF: "Poor Quality Flows",
  TO: "Timeouts",
  UNI: "Unidirectional Flows",
};

// *** Cookbook Rule Matching Engine ***
const matchCookbookRules = (
  allIssues,
  cookbookRules,
  internalIssues,
  externalIssues
) => {
  let probableRootCause = "";
  let recommendedSolution = "";

  // Try to match exact combinations (2 issues, 3 issues, etc.)
  const issueCount = allIssues.length;

  if (issueCount >= 2) {
    // Convert issue names to abbreviations for matching
    const issueAbbreviations = allIssues.map((issue) => {
      if (issue.includes("Latency Internal"))
        return "LAT-INT";
      if (issue.includes("Latency External"))
        return "LAT-EXT";
      if (issue.includes("Retrans Internal"))
        return "RPKT-INT";
      if (issue.includes("Retrans External"))
        return "RPKT-EXT";
      if (issue.includes("Retrans Rate Internal"))
        return "R%-INT";
      if (issue.includes("Retrans Rate External"))
        return "R%-EXT";
      if (issue.includes("Poor Quality"))
        return "PQF";
      if (issue.includes("Timeouts"))
        return "TO";
      if (issue.includes("Unidirectional"))
        return "UNI";
      return issue;
    });

    // Try combinations in order of specificity (more specific first)
    for (let i = 0; i < issueAbbreviations.length; i++) {
      for (let j = i + 1; j < issueAbbreviations.length; j++) {
        const combo = [issueAbbreviations[i], issueAbbreviations[j]]
          .sort()
          .join("+");

        if (cookbookRules[combo]) {
          const rule = cookbookRules[combo];
          probableRootCause = rule.rootCause;
          recommendedSolution = rule.solution;
          return { probableRootCause, recommendedSolution };
        }
      }
    }
  }

  // If no exact match found, try generic patterns
  if (internalIssues.length > 0 && externalIssues.length === 0) {
    probableRootCause =
      "Issues detected in internal network path. Possible causes: server overload, internal link congestion, or security policy delays.";
    recommendedSolution =
      "1. Check internal network capacity and utilization\n2. Verify server resources (CPU, memory, disk I/O)\n3. Review firewall/security appliance logs\n4. Check QoS policies on internal segments\n5. Monitor internal network device health";
  } else if (externalIssues.length > 0 && internalIssues.length === 0) {
    probableRootCause =
      "Issues detected in external/WAN path. Possible causes: WAN congestion, ISP throttling, or connection quality degradation.";
    recommendedSolution =
      "1. Check WAN link utilization and capacity\n2. Review ISP service quality metrics\n3. Verify routing through backup paths\n4. Check external firewall rules\n5. Consider WAN optimization appliances";
  } else if (internalIssues.length > 0 && externalIssues.length > 0) {
    probableRootCause =
      "Issues detected in both internal and external paths. Possible causes: end-to-end network degradation, multiple failure points, or pervasive congestion.";
    recommendedSolution =
      "1. Perform comprehensive network audit\n2. Check both internal and external gateway configurations\n3. Analyze traffic flow end-to-end\n4. Review capacity planning for both segments\n5. Implement monitoring across all network segments";
  }

  return { probableRootCause, recommendedSolution };
};

// *** Module Exports ***
module.exports = {
  apiCounterGroupTopper,
  getData,
  sendZeroMQRequest,
  analyzeTcpIssues,
  parseCookbook,
  matchCookbookRules
};