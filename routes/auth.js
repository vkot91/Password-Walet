const express = require("express");
const authController = require("../controllers/auth");
const router = express.Router();
//Route to controllers
router.post("/register", authController.register);
router.post("/login", authController.login);
router.post("/resetPassword", authController.resetPassword);

module.exports = router;
