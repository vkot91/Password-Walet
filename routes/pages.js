const express = require("express");
const authController = require("../controllers/auth");
const app = express();
const router = express.Router();
router.get("/", (req, res) => {
  res.render("index");
});

router.get("/register", (req, res) => {
  res.render("register");
});

router.get("/login", (req, res) => {
  res.render("login");
});
router.get("/createUser", (req, res) => {
  if (!req.session.user) {
    res.redirect("/login");
  }
  res.render("createUser");
});
router.get("/resetPassword", (req, res) => {
  if (!req.session.user) {
    res.redirect("/login");
  }
  res.render("resetPassword");
});
router.get("/dashboard", authController.dashboard);
router.get("/logout", authController.logout);

module.exports = router;
