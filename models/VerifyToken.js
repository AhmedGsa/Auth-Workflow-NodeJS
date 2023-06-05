const mongoose = require("mongoose")

const tokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: [true, "please provide a token"]
    },
    type: {
        enum: ["verify", "reset"],
        type: String,
        required: [true, "please provide a type"]
    }
})

module.exports = mongoose.model("Token", tokenSchema)