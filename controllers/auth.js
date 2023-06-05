const User = require("../models/User")
const Token = require("../models/VerifyToken")
const { BadRequestError, UnauthorizedError, NotFoundError } = require("../errors/index")
const { StatusCodes } = require("http-status-codes")
const { sendVerificationEmail, sendPasswordResetEmail } = require("../utils/send-emails")
const isJWT = require("../utils/check-jwt")
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

const confirmEmail = async (req, res) => {
    const { token } = req.params;
    if (isJWT(token)) {
        try {
            const payload = await jwt.verify(token, process.env.JWT_VERIFY_SECRET);
            await User.findOneAndUpdate({ _id: payload.id }, { confirmed: true });
            return res.status(StatusCodes.OK).json({ msg: "Email confirmed successfully!" });
        } catch (error) {
            throw new UnauthorizedError("Your link has expired!")
        }
    } else {
        throw new NotFoundError("Route doesn't exist!")
    }
}

const resendVerificationEmail = async (req, res) => {
    const {email} = req.body;
    if(!email) {
        throw new BadRequestError("Please provide email!");
    }
    const user = await User.findOne({ email });
    if (!user) {
        throw new NotFoundError("There is no user with provided email!");
    }
    if(user.confirmed) {
        throw new BadRequestError("Your account is already confirmed!");
    }
    await sendVerificationEmail(user._id, email);
    return res.status(200).json({ msg: "Email resent successfully!" });
}

const forgetPassword = async (req, res) => {
    const { email } = req.body;
    if (!email) {
        throw new BadRequestError("Please provide an email!");
    }
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
        throw new NotFound("There is no user with provided email!");
    }
    await sendPasswordResetEmail(email);
    return res.status(200).json({ msg: "Email sent successfully!" });
}

const checkPasswordResetToken = async (req, res) => {
    const { token } = req.body;
    if (isJWT(token)) {
        const dbToken = await Token.findOne({ token });
        try {
            const payload = await jwt.verify(token, process.env.JWT_VERIFY_SECRET);
        } catch (error) {
            return res.status(200).json({ valid: false, msg: "Token is invalid!" });
        }
        if (dbToken && dbToken.type === "reset") {
            return res.status(200).json({ valid: true, msg: "Token is valid!" });
        } else {
            return res.status(200).json({ valid: false, msg: "Token is invalid!" });
        }
    } else {
        throw new NotFoundError("Route doesn't exist!");
    }
}

const resetPassword = async (req, res) => {
    const { token } = req.params;
    const { password, confirmPassword } = req.body;
    if (isJWT(token) && password === confirmPassword) {
        let payload;
        try {
            payload = await jwt.verify(token, process.env.JWT_VERIFY_SECRET);
        } catch (error) {
            throw new UnauthorizedError("Link has expired!")
        }
        const salt = await bcrypt.genSalt(10);
        const newPassword = await bcrypt.hash(password, salt);
        await User.findOneAndUpdate({email: payload.email},{password: newPassword});
        return res.status(200).json({msg: "Password Updated Successfully!"});
    } else {
        if(password !== confirmPassword) {
            throw new BadRequestError("Passwords doesn't match!")
        } else {
            throw new UnauthorizedError("Link has expired!")
        }
    }
}

const changePassword = async (req, res) => {
    const { newPassword, currentPassword } = req.body;
    if(!newPassword || !currentPassword) {
        throw new BadRequestError("Please provide required fields!");
    }
    const user = await User.findById(req.user.userID);
    const isMatch = await user.verifyPass(currentPassword);
    if (!isMatch) {
        throw new BadRequestError("Wrong password!");
    } else {
        const salt = await bcrypt.genSalt(10);
        const newPass = await bcrypt.hash(newPassword, salt);
        await User.findOneAndUpdate({ _id: req.user.userID }, { password: newPass });
        res.cookie("token", "");
        return res.status(200).json({ msg: "Password changed successfully!" })
    }
}

module.exports = {
    login,
    register,
    logout,
    confirmEmail,
    resendVerificationEmail,
    forgetPassword,
    checkPasswordResetToken,
    resetPassword,
    changePassword
}