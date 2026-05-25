const express = require("express");
const cors = require("cors");

const securityRoutes = require("./routes/securityRoutes");

const app = express();

app.use(cors());
app.use(express.json());

app.use("/api", securityRoutes);

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Coral Command Center Backend Running"
  });
});

const PORT = 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});