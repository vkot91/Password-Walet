const express = require("express");
const walletControllet = require("../controllers/wallet");
const router = express.Router();

router.post("/register", walletControllet.register);
router.get("/delete/:id", walletControllet.delete);

module.exports = router;
