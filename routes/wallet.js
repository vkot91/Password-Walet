const express = require("express");
const walletController = require("../controllers/wallet");
const router = express.Router();

router.post("/register", walletController.register);
router.get("/delete/:id", walletController.delete);

module.exports = router;
