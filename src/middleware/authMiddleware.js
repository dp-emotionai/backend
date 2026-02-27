import jwt from "jsonwebtoken";
import prisma from "../utils/prisma.js";

export default async function authMiddleware(req, res, next) {
    try {
        const authHeader =
            req.headers.authorization || req.headers.Authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (!decoded?.id) {
            return res.status(401).json({ message: "Invalid token" });
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
            return res.status(401).json({ message: "User not found" });
        }

        // Добавляем безопасный объект пользователя
        req.user = {
            id: user.id,
            email: user.email,
            role: user.role,
        };

        req.userId = user.id; // если где-то используется

        next();
    } catch (error) {
        console.error("Auth error:", error);
        return res.status(401).json({ message: "Invalid or expired token" });
    }
}