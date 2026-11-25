const mongoose = require("mongoose");
const config = require("./config"); // adjust path to your config file

async function connectDB() {
    try {
        await mongoose.connect(config.MONGO_URI);
        console.log("Database connected successfully");
    } catch (error) {
        console.error("Error connecting to database", error);
        process.exit(1);
    }
}

module.exports = connectDB;