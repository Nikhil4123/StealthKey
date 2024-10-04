import jwt from "jsonwebtoken";

export const generateTokenAndSetCookie = (res, userId) => {
	const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
		expiresIn: "3d", // Token expires in 3 days
		algorithm: "HS512", // Use a stronger hashing algorithm
	});

	// Set the secure cookie
	res.cookie("token", token, {
		httpOnly: true,  // Prevent JavaScript access
		secure: process.env.NODE_ENV === "production", // HTTPS only in production
		sameSite: "strict", // Prevent CSRF attacks
		maxAge: 3 * 24 * 60 * 60 * 1000, // Cookie valid for 3 days
		domain: process.env.COOKIE_DOMAIN || "yourdomain.com", // Limit cookie to your domain
	});

	return token;
};
