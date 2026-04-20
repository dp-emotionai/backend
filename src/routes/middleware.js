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
 * Returns normalized user info for compatibility with route handlers.
 */
export function getUser(req) {
    if (!req.user) return null;

    const firstName = req.user.firstName ?? null;
    const lastName = req.user.lastName ?? null;
    const fullName =
        [firstName, lastName].filter(Boolean).join(" ").trim() || null;

    return {
        userId: req.user.id,
        email: req.user.email,
        role: req.user.role,
        firstName,
        lastName,
        fullName,
    };
}