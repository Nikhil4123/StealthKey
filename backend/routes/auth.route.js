import express from "express";
import rateLimit from "express-rate-limit"; // Step 1: Import the express-rate-limit package
import {
	login,
	logout,
	signup,
	verifyEmail,
	forgotPassword,
	resetPassword,
	checkAuth,
	updateUserRole,
} from "../controllers/auth.controller.js";
import { verifyToken } from "../middleware/verifyToken.js";

const router = express.Router();

// Step 2: Configure rate limiting
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // Limit each IP to 100 requests per windowMs
	message: "Too many requests from this IP, please try again later."
});

// Step 3: Apply the rate limiter to the desired routes
router.get("/check-auth", verifyToken, checkAuth);
router.post("/signup", limiter, signup); // Rate limited
router.post("/login", limiter, login); // Rate limited
router.post("/logout", limiter, logout); // Rate limited
router.post("/verify-email", limiter, verifyEmail); // Rate limited
router.post("/forgot-password", limiter, forgotPassword); // Rate limited
router.post("/reset-password/:token", limiter, resetPassword); // Rate limited
router.post("/update-user-role", verifyToken, limiter, updateUserRole); // Rate limited

export default router;
