const jwt = require("jsonwebtoken")
const {UnauthorizedError} = require("../errors/index")

const auth = async (req, res, next) => {
    const token = req.cookies.token;
    if(!token) {
        throw new UnauthorizedError("Authentication failed")
    }
    try {
        const payload = await jwt.verify(token, process.env.JWT_SECRET)
        req.user = {userID: payload.userID, email: payload.email}
        next()
    } catch (error) {
        throw new UnauthorizedError("Authentication failed")
    }
}

module.exports = auth