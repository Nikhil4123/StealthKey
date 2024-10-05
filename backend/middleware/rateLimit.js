import { User } from "../models/user.model.js";

const MAX_FAILED_ATTEMPTS = 5; // Maximum number of allowed failed attempts
const LOCK_TIME = 15 * 60 * 1000; // Lock account for 15 minutes after max attempts

export const rateLimit = async (req, res, next) => {
	const { email } = req.body;

	// Check if the user exists
	const user = await User.findOne({ email });
	if (!user) {
		return next(); // If user doesn't exist, proceed with normal login failure
	}

	// Check if the account is locked
	if (user.lockUntil && user.lockUntil > Date.now()) {
		const lockDuration = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60); // Remaining lock time in minutes
		return res.status(429).json({
			success: false,
			message: `Too many failed login attempts. Account is locked. Try again in ${lockDuration} minutes.`,
		});
	}

	next();
};

export const incrementFailedLogin = async (user) => {
	// Increment failed login attempts
	user.failedLoginAttempts += 1;

	// If maximum failed attempts reached, lock the account
	if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
		user.lockUntil = Date.now() + LOCK_TIME;
	}

	await user.save();
};

export const resetFailedLogin = async (user) => {
	user.failedLoginAttempts = 0;
	user.lockUntil = undefined;
	await user.save();
};
