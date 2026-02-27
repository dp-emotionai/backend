import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

// Создать сессию
router.post("/", authMiddleware, async (req, res) => {
    try {
        const { duration, engagement } = req.body;

        const session = await prisma.session.create({
            data: {
                duration,
                engagement,
                userId: req.user.id
            }
        });

        res.status(201).json(session);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to create session" });
    }
});

// Получить свои сессии
router.get("/my", authMiddleware, async (req, res) => {
    try {
        const sessions = await prisma.session.findMany({
            where: {
                userId: req.user.id
            },
            orderBy: {
                createdAt: "desc"
            }
        });

        res.json(sessions);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to fetch sessions" });
    }
});

export default router;