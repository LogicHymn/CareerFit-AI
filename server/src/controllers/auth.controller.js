const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const userModel = require("../models/user.model");
const sessionModel = require("../models/session.model");
const otpModel = require("../models/otp.model");
const config = require("../config/config");
const sendEmail = require("../services/email.service");
const { generateOtp, getOtpExpiry, getOtpHtml } = require("../utils/utils");

const isProduction = process.env.NODE_ENV === "production";

// ---------- HELPERS ----------

// PASSWORD
async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

async function comparePassword(password, storedPassword) {
    return await bcrypt.compare(password, storedPassword);
}

// HASHING (OTP / refresh token)
function sha256(value) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

// JWT
function generateAccessToken(userId, sessionId) {
    return jwt.sign({ id: userId, sessionId }, config.JWT_SECRET, {
        expiresIn: "15m"
    });
}

function generateRefreshToken(userId) {
    return jwt.sign({ id: userId }, config.JWT_SECRET, {
        expiresIn: "7d"
    });
}

// COOKIE
const refreshCookieOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    path: "/"
};

function setRefreshTokenCookie(res, refreshToken) {
    res.cookie("refreshToken", refreshToken, {
        ...refreshCookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000
    });
}

function clearRefreshTokenCookie(res) {
    res.clearCookie("refreshToken", refreshCookieOptions);
}

// Creates session + tokens + cookie for a user
async function createSessionAndTokens(req, res, user) {
    const refreshToken = generateRefreshToken(user._id);

    const session = await sessionModel.create({
        user: user._id,
        refreshToken: sha256(refreshToken),
        ip: req.ip,
        userAgent: req.headers["user-agent"],
        revoked: false
    });

    const accessToken = generateAccessToken(user._id, session._id);

    setRefreshTokenCookie(res, refreshToken);

    return accessToken;
}

// ---------- CONTROLLERS ----------

// REGISTER
async function registerUser(req, res) {
    try {
        let { username, email, password } = req.body;

        // Validate input
        if (!username || !email || !password) {
            return res.status(400).json({
                message: "Username, email and password are required"
            });
        }

        // Normalize input
        username = username.trim();
        email = email.trim().toLowerCase();

        if (password.length < 8) {
            return res.status(400).json({
                message: "Password must be at least 8 characters"
            });
        }

        // Check existing email
        const existingEmail = await userModel.findOne({ email });

        if (existingEmail) {
            if (existingEmail.verified) {
                return res.status(409).json({
                    message: "Email already exists"
                });
            }

            // Delete previous unverified registration
            await otpModel.deleteMany({ user: existingEmail._id });
            await userModel.findByIdAndDelete(existingEmail._id);
        }

        // Check existing username
        const existingUsername = await userModel.findOne({ username });

        if (existingUsername) {
            return res.status(409).json({
                message: "Username already exists"
            });
        }

        // Hash password
        const hashedPassword = await hashPassword(password);

        // Create unverified user
        const user = await userModel.create({
            username,
            email,
            password: hashedPassword,
            verified: false
        });

        // Generate + store hashed OTP
        const otp = generateOtp();

        await otpModel.create({
            email,
            user: user._id,
            otpHash: sha256(otp),
            expiresAt: getOtpExpiry()
        });

        // Send OTP
        try {
            await sendEmail(
                email,
                "OTP Verification",
                `Your OTP is ${otp}`,
                getOtpHtml(otp)
            );
        } catch (emailErr) {
            console.error("Failed to send OTP email:", emailErr.message);

            // Cleanup user and OTP
            await otpModel.deleteMany({ user: user._id });
            await userModel.findByIdAndDelete(user._id);

            return res.status(500).json({
                message:
                    "Failed to send verification email. Please try registering again."
            });
        }

        return res.status(201).json({
            message: "User registered. Please verify OTP.",
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                verified: user.verified
            }
        });
    } catch (err) {
        console.error("Register error:", err);

        // MongoDB duplicate key error
        if (err.code === 11000) {
            return res.status(409).json({
                message: "Username or email already exists"
            });
        }

        return res.status(500).json({
            message: "Internal server error"
        });
    }
}

// LOGIN
async function loginUser(req, res) {
    try {
        let { username, email, password } = req.body;

        if ((!username && !email) || !password) {
            return res.status(400).json({
                message: "Username/email and password are required"
            });
        }

        if (username) username = username.trim();
        if (email) email = email.trim().toLowerCase();

        const user = await userModel.findOne({
            $or: [
                ...(username ? [{ username }] : []),
                ...(email ? [{ email }] : [])
            ]
        });

        if (!user) {
            return res.status(401).json({
                message: "Invalid credentials"
            });
        }

        if (!user.verified) {
            return res.status(403).json({
                message: "Please verify your email first"
            });
        }

        const isPasswordValid = await comparePassword(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({
                message: "Invalid credentials"
            });
        }

        const accessToken = await createSessionAndTokens(req, res, user);

        return res.status(200).json({
            message: "User logged in successfully",
            accessToken,
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        });
    } catch (err) {
        console.error(err);

        return res.status(500).json({
            message: "Internal server error"
        });
    }
}

// REFRESH TOKEN
async function refreshToken(req, res) {
    try {
        const currentRefreshToken = req.cookies.refreshToken;

        if (!currentRefreshToken) {
            return res.status(401).json({
                message: "Refresh token required"
            });
        }

        // Verify refresh token
        const decoded = jwt.verify(currentRefreshToken, config.JWT_SECRET);

        // Find session
        const session = await sessionModel.findOne({
            user: decoded.id,
            refreshToken: sha256(currentRefreshToken),
            revoked: false
        });

        if (!session) {
            return res.status(401).json({
                message: "Invalid or revoked refresh token"
            });
        }

        // Rotate refresh token
        const newRefreshToken = generateRefreshToken(decoded.id);

        session.refreshToken = sha256(newRefreshToken);
        await session.save();

        // New access token
        const accessToken = generateAccessToken(decoded.id, session._id);

        setRefreshTokenCookie(res, newRefreshToken);

        return res.status(200).json({
            message: "Access token refreshed successfully",
            accessToken
        });
    } catch (err) {
        console.error(err);

        return res.status(401).json({
            message: "Invalid or expired refresh token"
        });
    }
}

// LOGOUT
async function logoutUser(req, res) {
    try {
        const currentRefreshToken = req.cookies.refreshToken;

        if (!currentRefreshToken) {
            return res.status(400).json({
                message: "Refresh token required"
            });
        }

        // Revoke current session
        await sessionModel.updateOne(
            { refreshToken: sha256(currentRefreshToken) },
            { revoked: true }
        );

        clearRefreshTokenCookie(res);

        return res.status(200).json({
            message: "User logged out successfully"
        });
    } catch (err) {
        console.error(err);

        return res.status(500).json({
            message: "Internal server error"
        });
    }
}

// LOGOUT ALL DEVICES
async function logoutAllDevices(req, res) {
    try {
        const currentRefreshToken = req.cookies.refreshToken;

        if (!currentRefreshToken) {
            return res.status(400).json({
                message: "Refresh token not found"
            });
        }

        // Verify refresh token
        const decoded = jwt.verify(currentRefreshToken, config.JWT_SECRET);

        // Revoke all sessions of this user
        await sessionModel.updateMany(
            { user: decoded.id, revoked: false },
            { revoked: true }
        );

        clearRefreshTokenCookie(res);

        return res.status(200).json({
            message: "Logged out from all devices successfully"
        });
    } catch (err) {
        console.error(err);

        return res.status(401).json({
            message: "Invalid or expired refresh token"
        });
    }
}

// VERIFY OTP
async function verifyEmail(req, res) {
    try {
        let { otp, email } = req.body;

        if (!otp || !email) {
            return res.status(400).json({
                message: "Email and OTP are required"
            });
        }

        email = email.trim().toLowerCase();

        // Find OTP
        const otpDoc = await otpModel.findOne({
            email,
            otpHash: sha256(String(otp)),
            verified: false
        });

        if (!otpDoc) {
            return res.status(400).json({
                message: "Invalid OTP"
            });
        }

        // Check expiry
        if (otpDoc.expiresAt < new Date()) {
            return res.status(400).json({
                message: "OTP has expired"
            });
        }

        // Verify user
        const user = await userModel.findByIdAndUpdate(
            otpDoc.user,
            { verified: true },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        // Delete OTPs
        await otpModel.deleteMany({ user: otpDoc.user });

        const accessToken = await createSessionAndTokens(req, res, user);

        return res.status(200).json({
            message: "Email verified successfully",
            accessToken,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                verified: user.verified
            }
        });
    } catch (err) {
        console.error(err);

        return res.status(500).json({
            message: "Internal server error"
        });
    }
}

module.exports = {
    registerUser,
    verifyEmail,
    loginUser,
    refreshToken,
    logoutUser,
    logoutAllDevices
};