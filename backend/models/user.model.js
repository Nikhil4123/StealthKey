import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
	{
		email: {
			type: String,
			required: true,
			unique: true,
		},
		password: {
			type: String,
			required: true,
		},
		name: {
			type: String,
			required: true,
		},
		lastLogin: {
			type: Date,
			default: Date.now,
		},
		isVerified: {
			type: Boolean,
			default: false,
		},
		role: {
			type: String,
			enum: ['user', 'admin'],
			default: 'user',
		},
		resetPasswordToken: String,
		resetPasswordExpiresAt: Date,
		verificationToken: String,
		verificationTokenExpiresAt: Date,

		// New fields for rate limiting
		failedLoginAttempts: {
			type: Number,
			default: 0,
		},
		lockUntil: {
			type: Date,
		},
	},
	{ timestamps: true }
);

// Pre-save middleware to clear failed attempts after a successful login
userSchema.pre('save', function (next) {
	if (this.failedLoginAttempts === 0) {
		this.lockUntil = undefined;
	}
	next();
});

export const User = mongoose.model("User", userSchema);
