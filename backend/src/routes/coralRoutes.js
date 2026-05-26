const express = require("express");

const router = express.Router();

const { runCoralQuery } = require("../services/coralService");

router.get("/coral-query", async (req, res) => {

  const result = await runCoralQuery();

  res.json(result);

});

module.exports = router;