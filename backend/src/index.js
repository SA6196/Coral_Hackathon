require("dotenv").config();
require("./config/initDb");
const seedDatabase = require("./services/seedService");

seedDatabase();

const express = require("express");
const cors = require("cors");
const morgan = require("morgan");

const securityRoutes = require("./routes/securityRoutes");
const coralRoutes    = require("./routes/coralRoutes");
const aiRoutes       = require("./routes/aiRoutes");
const configRoutes   = require("./routes/configRoutes");

const app = express();

app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

app.get("/", (req, res) => {
  res.json({ success: true, message: "Coral Security Backend Running" });
});

app.use("/api", securityRoutes);
app.use("/api", coralRoutes);
app.use("/api", aiRoutes);
app.use("/api", configRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});