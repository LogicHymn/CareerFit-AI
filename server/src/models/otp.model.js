const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        lowercase: true,
        trim: true
    },

    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user",
        required: true
    },

    otpHash: {
        type: String,
        required: true
    },

    verified: {
        type: Boolean,
        default: false
    },

    // MongoDB auto-deletes the document once this time passes
    expiresAt: {
        type: Date,
        required: true,
        index: { expires: 0 }
    }
}, {
    timestamps: true
});

const otpModel = mongoose.model("otp", otpSchema);

module.exports = otpModel;