const {
  joinSecurityData
} = require("../coral/joinData");

const runCoralQuery = async () => {

  const data = joinSecurityData();

  return {
    success: true,
    total_incidents: data.length,
    data
  };

};

module.exports = {
  runCoralQuery
};