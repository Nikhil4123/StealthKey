import crypto from "crypto";

const algorithm = "aes-256-cbc"; 
const iv = crypto.randomBytes(16); 

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
