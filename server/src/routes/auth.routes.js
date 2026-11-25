const express = require("express");
const authController = require("../controllers/auth.controller");

const router = express.Router();

router.post("/register", authController.registerUser);

router.post("/login", authController.loginUser);

router.post("/refresh-token", authController.refreshToken);

router.post("/logout", authController.logoutUser);

router.post("/logout-all-devices",authController.logoutAllDevices);

router.post("/verify-otp", authController.verifyEmail);


module.exports = router;