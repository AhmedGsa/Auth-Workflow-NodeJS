const express = require('express');
const { login, register, logout } = require('../controllers/auth');
const router = express.Router();

router.route("/register").post(register);
router.route("/login").post(login);
router.route("/logout").get(logout);

module.exports = router;