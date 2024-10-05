// utils/encryption.js
import crypto from "crypto";

const algorithm = "aes-256-cbc"; // You can use other algorithms, but AES is commonly used.
const iv = crypto.randomBytes(16); // Initialization vector

// Make sure to set a strong secret key in your .env file
const secretKey = process.env.ENCRYPTION_SECRET_KEY;

export const encryptData = (data) => {
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey), iv);
    let encryptedData = cipher.update(data, "utf8", "hex");
    encryptedData += cipher.final("hex");
    return iv.toString("hex") + ":" + encryptedData; // Store IV with the encrypted data
};

export const decryptData = (encrypted) => {
    const parts = encrypted.split(":");
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(secretKey), Buffer.from(parts.shift(), "hex"));
    let decryptedData = decipher.update(parts.join(":"), "hex", "utf8");
    decryptedData += decipher.final("utf8");
    return decryptedData;
};
