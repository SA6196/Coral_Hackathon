const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./security.db");

db.all(
  "SELECT name FROM sqlite_master WHERE type='table';",
  [],
  (err, rows) => {
    if (err) {
      return console.error(err);
    }

    console.log(rows);
  }
);