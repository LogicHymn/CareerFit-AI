const app = require("./src/app");
const connectDB = require("./src/config/db");
const config = require("./src/config/config");

connectDB().then(() => {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`Server running on ${PORT}`));
});