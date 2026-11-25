const jwt = require("jsonwebtoken");
const config = require("../config/config");
const userModel = require("../models/user.model");
const sessionModel = require("../models/session.model");

async function userAuthMiddleware(req, res, next) {
    try {
        // Access token only comes from the Authorization header
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(token, config.JWT_SECRET);

        // Session must exist and not be revoked (makes logout work instantly)
        const session = await sessionModel.findOne({
            _id: decoded.sessionId,
            user: decoded.id,
            revoked: false
        });

        if (!session) {
            return res.status(401).json({
                message: "Session expired or revoked"
            });
        }

        const user = await userModel.findById(decoded.id).select("-password");

        if (!user) {
            return res.status(401).json({
                message: "User not found"
            });
        }

        req.user = user;
        req.sessionId = session._id;

        next();
    } catch (err) {
        console.warn("User auth verification failed:", err.message);

        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
}

module.exports = { userAuthMiddleware };