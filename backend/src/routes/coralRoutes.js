const express = require("express");

const router = express.Router();

/*
|--------------------------------------------------------------------------
| OLD CORAL SERVICE
|--------------------------------------------------------------------------
*/

const { runCoralQuery } = require("../services/coralService");

/*
|--------------------------------------------------------------------------
| NEW SQLITE CORAL QUERY SERVICE
|--------------------------------------------------------------------------
*/

const {
  getCriticalIncidents
} = require("../services/coralSqlService");

/*
|--------------------------------------------------------------------------
| BASIC CORAL QUERY
|--------------------------------------------------------------------------
*/

router.get("/coral-query", async (req, res) => {

  try {
    const sessionId = req.headers["x-session-id"] || "default";
    const result = await runCoralQuery(sessionId);

    res.json(result);

  }

  catch (error) {

    res.status(500).json({
      success: false,
      message: error.message
    });

  }

});

/*
|--------------------------------------------------------------------------
| REAL CORAL-STYLE SQL JOIN QUERY
|--------------------------------------------------------------------------
*/

router.get("/coral-critical", async (req, res) => {

  try {

    const data = await getCriticalIncidents();

    res.json({
      success: true,
      total_incidents: data.length,
      data
    });

  }

  catch (error) {

    res.status(500).json({
      success: false,
      message: error.message
    });

  }

});

module.exports = router;