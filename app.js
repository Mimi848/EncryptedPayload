const express = require("express");
const CryptoJS = require("crypto-js");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

require("dotenv").config();
const app = express();

const serverKey = process.env.SERVER_KEY;
const DEFAULT_KEY_SIZE = 16;
const ALLOWED_ENCRYPTION_MODES = ["CBC", "CFB", "CTR", "OFB", "ECB"];

function generateSecureRandomString(length) {
  const randomArray = CryptoJS.lib.WordArray.random(length);
  return CryptoJS.enc.Base64.stringify(randomArray);
}

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
    const encryptionMode =
      req.query.encryptionMode || ALLOWED_ENCRYPTION_MODES[0];

    if (parseInt(keySize) < 8 && parseInt(keySize) > 1024)
      throw { status: 400, message: "invalid keysize!" };

    if (!ALLOWED_ENCRYPTION_MODES.includes(encryptionMode))
      throw {
        status: 400,
        message:
          "invalid Encryption Mode selected, allowed Encryption Modes are: " +
          ALLOWED_ENCRYPTION_MODES.join(", "),
      };

    const encryptedKey = CryptoJS.AES.encrypt(
      generateSecureRandomString(keySize),
      serverKey
    ).toString();

    res.json({ encryptedKey });
  } catch (error) {
    console.error(error);
    res
      .status(error.status || 500)
      .json({ error: error.message || "Internal Server Error" });
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
