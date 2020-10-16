const express = require("express");
const mysql = require("mysql");
const dotenv = require("dotenv");
const path = require("path");
const session = require("express-session");

dotenv.config({
  path: "./.env",
});

const app = express();

// Connect Database
const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  database: process.env.DATABASE,
});
const publicDirectory = path.join(__dirname, "./public");
app.use("/js", express.static(__dirname + "/public/scripts"));
app.use(express.static(publicDirectory));
//Parse URL-encoded bodies
app.use(express.urlencoded({ extended: false }));
//Parse JSON-bodies
app.use(express.json());

app.set("view engine", "hbs");

db.connect((error) => {
  if (error) {
    console.log(error);
  } else {
    console.log("MYSQL Connected..");
  }
});
// APPLY COOKIE SESSION MIDDLEWARE
app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 },
  })
);

//Define Routes
app.use("/", require("./routes/pages"));
app.use("/auth", require("./routes/auth"));
app.use("/wallet", require("./routes/wallet"));

app.listen(5000, () => {
  console.log("Server starter on Port 5000");
});
