const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./security.db", (err) => {

  if (err) {
    console.log("Database Error:", err.message);
  }

  else {
    console.log("✅ SQLite Connected");
  }

});

module.exports = db;