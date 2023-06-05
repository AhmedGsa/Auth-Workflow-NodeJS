const express = require('express');
const { login, register, logout, confirmEmail, resendVerificationEmail, forgetPassword } = require('../controllers/auth');
const router = express.Router();

router.route("/register").post(register);
router.route("/login").post(login);
router.route("/logout").get(logout);
router.route("/confirm-email/:token").get(confirmEmail);
router.route("/resend-verification-email").post(resendVerificationEmail);
router.route("/forget-password").post(forgetPassword);

module.exports = router;