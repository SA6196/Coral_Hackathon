const calculateRiskScore = (severity) => {
  switch (severity) {
    case "critical":
      return 95;

    case "high":
      return 80;

    case "medium":
      return 60;

    default:
      return 20;
  }
};

module.exports = calculateRiskScore;