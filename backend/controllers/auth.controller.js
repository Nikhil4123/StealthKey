import bcryptjs from "bcryptjs";
import crypto from "crypto";

import { generateTokenAndSetCookie } from "../utils/generateTokenAndSetCookie.js";
import {
	sendPasswordResetEmail,
	sendResetSuccessEmail,
	sendVerificationEmail,
	sendWelcomeEmail,
} from "../mailtrap/emails.js";
import { User } from "../models/user.model.js";
import { encryptData, decryptData } from "../utils/encryption.js"; // Import encryption utilities

const mesg = "User created successfully but cannot be verified by email; need to buy subscription.";

export const signup = async (req, res) => {
	const { email, password, name, role = 'user' } = req.body; // Added role with default value

	try {
		if (!email || !password || !name) {
			throw new Error("All fields are required");
		}

		const userAlreadyExists = await User.findOne({ email });
		console.log("userAlreadyExists", userAlreadyExists);

		if (userAlreadyExists) {
			return res.status(400).json({ success: false, message: "User already exists" });
		}

		// Encrypt password
		const encryptedPassword = encryptData(password);
		const verificationToken = Math.floor(100000 + Math.random() * 900000).toString();

		const user = new User({
			email,
			password: encryptedPassword, // Save encrypted password
			name,
			verificationToken,
			verificationTokenExpiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
			role, // Save user role
		});

		await user.save();

		// jwt
		generateTokenAndSetCookie(res, user._id);

		await sendVerificationEmail(user.email, verificationToken);

		res.status(201).json({
			success: true,
			message: "User created successfully",
			user: {
				...user._doc,
				password: undefined,
			},
		});
	} catch (error) {
		res.status(400).json({ success: true, message: mesg });
	}
};

export const verifyEmail = async (req, res) => {
	const { code } = req.body;
	try {
		const user = await User.findOne({
			verificationToken: code,
			verificationTokenExpiresAt: { $gt: Date.now() },
		});

		if (!user) {
			// Increment failed attempts if verification fails
			const existingUser = await User.findOne({ verificationToken: code });
			if (existingUser) {
				existingUser.failedAttempts += 1; // Increment the failed attempts
				await existingUser.save();

				// Block user if failed attempts exceed 5
				if (existingUser.failedAttempts > 5) {
					return res.status(403).json({
						success: false,
						message: "Your account is locked due to too many failed verification attempts.",
					});
				}
			}
			return res.status(400).json({ success: false, message: "Invalid or expired verification code" });
		}

		// Reset failed attempts on successful verification
		user.failedAttempts = 0; // Reset failed attempts
		user.isVerified = true;
		user.verificationToken = undefined;
		user.verificationTokenExpiresAt = undefined;
		await user.save();

		await sendWelcomeEmail(user.email, user.name);

		res.status(200).json({
			success: true,
			message: "Email verified successfully",
			user: {
				...user._doc,
				password: undefined,
			},
		});
	} catch (error) {
		console.log("error in verifyEmail ", error);
		res.status(500).json({ success: false, message: "Server error" });
	}
};

export const login = async (req, res) => {
	const { email, password } = req.body;
	const maxRetries = 3;

	try {
		const user = await User.findOne({ email });
		if (!user) {
			return res.status(400).json({ success: false, message: "User not found" });
		}

		// Check if account is locked
		if (user.failedLoginAttempts >= maxRetries) {
			return res.status(403).json({ success: false, message: "Account locked due to too many failed login attempts. Please sign up again." });
		}

		// Decrypt password
		const decryptedPassword = decryptData(user.password);
		if (decryptedPassword !== password) {
			user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1; // Increment failed attempts
			await user.save(); // Save updated failed attempts

			if (user.failedLoginAttempts >= maxRetries) {
				return res.status(403).json({ success: false, message: "Account locked due to too many failed login attempts. Please sign up again." });
			}

			return res.status(400).json({ success: false, message: "Invalid credentials" });
		}

		// If login is successful, reset failed attempts
		user.failedLoginAttempts = 0; // Reset failed attempts
		generateTokenAndSetCookie(res, user._id);

		user.lastLogin = new Date();
		await user.save();

		// Send success response
		res.status(200).json({
			success: true,
			message: "Logged in successfully",
			user: {
				...user._doc,
				password: undefined,
			},
		});
	} catch (error) {
		console.log("Error in login: ", error);
		res.status(500).json({ success: false, message: "Server error" });
	}
};


export const logout = async (req, res) => {
	res.clearCookie("token");
	res.status(200).json({ success: true, message: "Logged out successfully" });
};

export const forgotPassword = async (req, res) => {
	const { email } = req.body;
	try {
		const user = await User.findOne({ email });

		if (!user) {
			return res.status(400).json({ success: false, message: "User not found" });
		}

		// Generate reset token
		const resetToken = crypto.randomBytes(20).toString("hex");
		const resetTokenExpiresAt = Date.now() + 1 * 60 * 60 * 1000; // 1 hour

		user.resetPasswordToken = resetToken;
		user.resetPasswordExpiresAt = resetTokenExpiresAt;

		await user.save();

		// send email
		await sendPasswordResetEmail(user.email, `${process.env.CLIENT_URL}/reset-password/${resetToken}`);

		res.status(200).json({ success: true, message: "Password reset link sent to your email" });
	} catch (error) {
		console.log("Error in forgotPassword ", error);
		res.status(400).json({ success: false, message: error.message });
	}
};

export const resetPassword = async (req, res) => {
	try {
		const { token } = req.params;
		const { password } = req.body;

		const user = await User.findOne({
			resetPasswordToken: token,
			resetPasswordExpiresAt: { $gt: Date.now() },
		});

		if (!user) {
			return res.status(400).json({ success: false, message: "Invalid or expired reset token" });
		}

		// Update password with encryption
		const encryptedPassword = encryptData(password);
		user.password = encryptedPassword; // Save encrypted password
		user.resetPasswordToken = undefined;
		user.resetPasswordExpiresAt = undefined;
		await user.save();

		await sendResetSuccessEmail(user.email);

		res.status(200).json({ success: true, message: "Password reset successful" });
	} catch (error) {
		console.log("Error in resetPassword ", error);
		res.status(400).json({ success: true, message: error.message });
	}
};

export const checkAuth = async (req, res) => {
	try {
		const user = await User.findById(req.userId).select("-password");
		if (!user) {
			return res.status(400).json({ success: false, message: "User not found" });
		}

		res.status(200).json({ success: true, user });
	} catch (error) {
		console.log("Error in checkAuth ", error);
		res.status(400).json({ success: false, message: error.message });
	}
};

// Optional: Function to update user role (if needed)
export const updateUserRole = async (req, res) => {
	const { userId, role } = req.body;

	try {
		if (!userId || !role) {
			return res.status(400).json({ success: false, message: "User ID and role are required" });
		}

		const user = await User.findById(userId);
		if (!user) {
			return res.status(404).json({ success: false, message: "User not found" });
		}

		user.role = role;
		await user.save();

		res.status(200).json({ success: true, message: "User role updated successfully", user });
	} catch (error) {
		console.log("Error in updateUserRole ", error);
		res.status(400).json({ success: false, message: error.message });
	}
};
