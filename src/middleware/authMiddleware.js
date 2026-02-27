import jwt from "jsonwebtoken";
import prisma from "../utils/prisma.js";

export default async function authMiddleware(req, res, next) {
    try {
        const authHeader =
            req.headers.authorization || req.headers.Authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "No token provided",
            });
        }

        const token = authHeader.split(" ")[1];

        let decoded;

        try {
            decoded = jwt.verify(
                token,
                process.env.JWT_SECRET
            );
        } catch (err) {
            // Если токен истёк — даём понять клиенту
            if (err.name === "TokenExpiredError") {
                return res.status(401).json({
                    message: "Token expired",
                });
            }

            return res.status(401).json({
                message: "Invalid token",
            });
        }

        if (!decoded?.id) {
            return res.status(401).json({
                message: "Invalid token payload",
            });
        }

        const user = await prisma.user.findUnique({
            where: { id: decoded.id },
            select: {
                id: true,
                email: true,
                role: true,
            },
        });

        if (!user) {
            return res.status(401).json({
                message: "User not found",
            });
        }

        // Безопасный объект пользователя
        req.user = {
            id: user.id,
            email: user.email,
            role: user.role,
        };

        req.userId = user.id;

        next();

    } catch (error) {
        console.error("AUTH MIDDLEWARE ERROR:", error);
        return res.status(401).json({
            message: "Authentication failed",
        });
    }
}