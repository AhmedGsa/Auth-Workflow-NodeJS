const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const Token = require("../models/VerifyToken");

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    secure: true,
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
})

transporter.verify((err, success) => {
    if (err) {
        console.log(err)
    } else {
        console.log("Ready to send emails");
    }
})

const sendVerificationEmail = async (id, email) => {
    const verifyToken = await jwt.sign({ email, id }, process.env.JWT_VERIFY_SECRET, {
        expiresIn: "15m"
    })
    const token = await Token.create({ token: verifyToken, type: "verify" })
    const link = `${process.env.BASE_URL}/api/v1/auth/confirm-email/${token.token}`
    await transporter.sendMail({
        from: `MyApp <${process.env.EMAIL}>`,
        to: email,
        subject: "Email Verification",
        html: `<h1>Please verify your email by clicking the link bellow</h1><a href="${link}">${link}</a>`
    }, (err, msg) => {
        if (err) {
            console.log(err);
        }
    })
}

const sendPasswordResetEmail = async (email) => {
    const verifyToken = await jwt.sign({ email }, process.env.JWT_VERIFY_SECRET, {
        expiresIn: "15m"
    })
    let token = await Token.create({ token: verifyToken, type: "reset" })
    const link = `${process.env.BASE_URL}/reset-password/${token.token.replaceAll(".", "(-_)")}`
    await transporter.sendMail({
        from: `MyApp <${process.env.EMAIL}>`,
        to: email,
        subject: "MyApp Password Reset",
        html: `<h1>Please reset your password by clicking the link bellow</h1><a href="${link}">${link}</a>`
    }, (err, msg) => {
        if (err) {
            console.log(err);
        }
    })
}

module.exports = {
    sendVerificationEmail,
    sendPasswordResetEmail
}