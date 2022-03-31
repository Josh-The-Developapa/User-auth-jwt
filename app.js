const express = require("express");
const cookieParser = require("cookie-parser");
require("dotenv").config({ path: "config.env" });
const mongoose = require("mongoose");
const morgan = require("morgan");
const router = require("./routes/router");
const errorHandler = require("./middleware/err.js");

const app = express();

const dbUrl = process.env.dbUrl

mongoose
  .connect(dbUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to DB"))
  .catch((err) => console.log(err));

app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());
app.use(router);
app.use(errorHandler);

app.listen(8000, () => {
  console.log("Server up and running");
});

// console.log(new Date('2022-03-31T09:25:40.588Z').toTimeString())
