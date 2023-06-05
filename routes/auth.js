const express = require('express');
const auth = require('../middlewares/auth');
const { login, register, logout, confirmEmail, resendVerificationEmail, forgetPassword, changePassword, resetPassword, checkPasswordResetToken } = require('../controllers/auth');
const router = express.Router();

router.route("/register").post(register);
router.route("/login").post(login);
router.route("/logout").get(logout);
router.route("/confirm-email/:token").get(confirmEmail);
router.route("/resend-verification-email").post(resendVerificationEmail);
router.route("/forget-password").post(forgetPassword);
router.route("/check-password-reset-token").post(checkPasswordResetToken);
router.route("/reset-password/:token").post(resetPassword);
router.route("/change-password").post(auth, changePassword);

module.exports = router;