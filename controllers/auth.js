const User = require("../models/User")
//const Token = require("../models/VerifyToken")
const { BadRequestError, UnauthorizedError, NotFoundError } = require("../errors/index")
const { StatusCodes } = require("http-status-codes")
const { sendVerificationEmail, sendPasswordResetEmail } = require("../utils/send-emails")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")

const login = async (req, res) => {
    const { email, password } = req.body
    const user = await User.findOne({ email: email.toLowerCase() })
    if (!user) {
        throw new BadRequestError("Wrong Credentials!")
    }
    const correctPassword = await user.verifyPass(password)
    if (!correctPassword) {
        throw new BadRequestError("Wrong Credentials!")
    }
    const token = await user.createJWT()
    res.cookie("token", token, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 10 })
    res.status(StatusCodes.OK).json({ userID: user._id, email: user.email, fullName: user.fullName, confirmed: user.confirmed })
}

const register = async (req, res, next) => {
    const { email, password, fullName } = req.body
    if (!email || !password || !fullName ) {
        throw new BadRequestError("Please provide required fields!")
    }
    const user = await User.create({ email: email.toLowerCase(), password, fullName, confirmed: false})
    const token = await user.createJWT()
    sendVerificationEmail(user._id, user.email)
    res.cookie("token", token, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 10 })
    return res.status(StatusCodes.CREATED).json({ userID: user._id, email: user.email, fullName: user.fullName, confirmed: user.confirmed});
}

const logout = (req, res) => {
    res.cookie("token", "", {
        httpOnly: true,
        maxAge: 1
    })
    res.status(StatusCodes.OK).json({ msg: "Logged out successfully" })
}

module.exports = {
    login,
    register,
    logout
}