const { NotFoundError } = require("../errors");

const isJWT = (token) => {
    try {
        const header = token.split(".")[0];
        const buff = new Buffer(header, "base64")
        const payload = buff.toString("ascii")
        const jsonPayload = JSON.parse(payload)
        if (jsonPayload && jsonPayload.typ === "JWT") {
            return true;
        } else {
            return false;
        }
    } catch (error) {
        throw new NotFoundError("Route doesn't exist!");
    }

}

module.exports = isJWT;