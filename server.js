const express = require("express");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");
const bodyParser = require("body-parser");
const cors = require("cors");

dotenv.config();
connectDB();
const app = express();
app.use(cors({ origin: '*' }));
app.use(bodyParser.json());
app.use("/api/auth", authRoutes);

const PORT = 5000
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
