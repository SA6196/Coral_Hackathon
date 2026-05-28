const { joinSecurityData } = require("./src/coral/joinData");
const { runSecurityAnalysis } = require("./src/coral/queryEngine");

async function main() {
  try {
    console.log("Running joinSecurityData...");
    const result = await joinSecurityData("default");
    console.log("Cache hit:", result.cache_hit);
    console.log("Data length:", result.data.length);
    if (result.data.length > 0) {
      console.log("First joined row sample:", JSON.stringify(result.data[0], null, 2));
      const analyzed = runSecurityAnalysis(result.data);
      console.log("Analyzed first incident sample:", JSON.stringify(analyzed[0], null, 2));
      console.log("Analyzed all incident IDs:", analyzed.map(i => i.incident_id));
    } else {
      console.log("No joined data found!");
    }
  } catch (err) {
    console.error("Error in test run:", err);
  }
}

main();
