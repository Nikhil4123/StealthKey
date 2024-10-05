import jwt from 'jsonwebtoken';

export const authenticateUser = (req, res, next) => {
    const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ success: false, message: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Make sure to set JWT_SECRET in your .env file
        req.userId = decoded.id; // Assuming your token contains the user ID
        next(); // Continue to the next middleware/route handler
    } catch (error) {
        res.status(401).json({ success: false, message: 'Token is not valid' });
    }
};
