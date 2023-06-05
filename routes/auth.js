const express = require('express');
const { login, register, logout, confirmEmail } = require('../controllers/auth');
const router = express.Router();

router.route("/register").post(register);
router.route("/login").post(login);
router.route("/logout").get(logout);
router.route("/confirm-email/:token").get(confirmEmail);

module.exports = router;