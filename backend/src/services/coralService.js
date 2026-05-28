const {
  joinSecurityData
} = require("../coral/joinData");

const runCoralQuery = async (sessionId) => {
  const data = await joinSecurityData(sessionId);

  return {
    success: true,
    total_incidents: data.length,
    data
  };

};

module.exports = {
  runCoralQuery
};