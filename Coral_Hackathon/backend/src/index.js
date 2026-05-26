require("dotenv").config();
require("./config/initDb");
const seedDatabase = require("./services/seedService");

seedDatabase();

const express = require("express");
const cors = require("cors");
const morgan = require("morgan");

const securityRoutes = require("./routes/securityRoutes");
const coralRoutes = require("./routes/coralRoutes");

const app = express();

/*
|--------------------------------------------------------------------------
| MIDDLEWARE
|--------------------------------------------------------------------------
*/

app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

/*
|--------------------------------------------------------------------------
| ROOT
|--------------------------------------------------------------------------
*/

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Backend Running Successfully"
  });
});

/*
|--------------------------------------------------------------------------
| ROUTES
|--------------------------------------------------------------------------
*/

app.use("/api", securityRoutes);
app.use("/api", coralRoutes);

/*
|--------------------------------------------------------------------------
| SERVER
|--------------------------------------------------------------------------
*/

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});