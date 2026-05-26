const db = require("./database");

db.serialize(() => {

  db.run(`
    CREATE TABLE IF NOT EXISTS github (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author TEXT,
      title TEXT,
      package_name TEXT,
      merged_at TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS osv (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      package_name TEXT,
      cve TEXT,
      severity TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS slack (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel TEXT,
      message TEXT
    )
  `);

});

console.log("✅ Tables Initialized");