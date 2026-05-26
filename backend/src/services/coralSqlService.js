const db = require("../config/database");

const getCriticalIncidents = () => {

  return new Promise((resolve, reject) => {

    db.all(
      `
      SELECT
        github.author,
        github.title,
        github.package_name,
        osv.cve,
        osv.severity
      FROM github
      JOIN osv
      ON github.package_name = osv.package_name
      WHERE osv.severity = 'critical'
      `,
      [],
      (err, rows) => {

        if (err) {
          reject(err);
        }

        else {
          resolve(rows);
        }

      }
    );

  });

};

module.exports = {
  getCriticalIncidents
};