import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";

export { authMiddleware };

/**
 * @param {...string} allowedRoles - e.g. "TEACHER", "ADMIN"
 */
export function requireRole(...allowedRoles) {
    return roleMiddleware(allowedRoles);
}

/**
 * Get JWT user from request (use after authMiddleware).
 * Returns { userId, email, role } for compatibility with route handlers.
 */
export function getUser(req) {
    if (!req.user) return null;
    return {
        userId: req.user.id,
        email: req.user.email,
        role: req.user.role,
        name: req.user.name,
    };
}
