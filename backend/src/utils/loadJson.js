const fs = require("fs");
const path = require("path");

const loadJson = (fileName) => {
  const filePath = path.join(
    process.cwd(),
    "mock-data",
    fileName
  );

  return JSON.parse(
    fs.readFileSync(filePath, "utf-8")
  );
};

module.exports = loadJson;