const express = require("express");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

require("dotenv").config();
const app = express();

const serverKey = process.env.SERVER_KEY;
const DEFAULT_KEY_SIZE = 32;
const DEFAULT_ENCRYPTION_MODE = "aes-256-cbc";

// Middleware
app.use(helmet());
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
});
app.use("/api/server-key-encrypted", limiter);
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

const isValidUser = (req, res, next) => {
  // assuming this method authenticates user
  next();
};

app.get("/api/server-key-encrypted", isValidUser, (req, res) => {
  try {
    const keySize = req.query.keySize || DEFAULT_KEY_SIZE;
    const encryptionMode = req.query.encryptionMode || DEFAULT_ENCRYPTION_MODE;

    const encryptionKey = crypto.randomBytes(keySize);
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv(encryptionMode, encryptionKey, iv);
    let encryptedKey = cipher.update(serverKey, "utf-8", "hex");
    encryptedKey += cipher.final("hex");

    res.json({ encryptedKey });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Error Handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something went wrong!");
});

app.listen(3000, () => {
  console.log(`Server is running on port ${3000}`);
});
