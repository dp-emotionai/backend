import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

// создать сессию
router.post("/", authMiddleware, async (req, res) => {
    const { duration, engagement } = req.body;

    const session = await prisma.session.create({
        data: {
            duration,
            engagement,
            userId: req.user.id
        }
    });

    res.json(session);
});

// получить сессии пользователя
router.get("/user/:id", authMiddleware, async (req, res) => {
    const sessions = await prisma.session.findMany({
        where: {
            userId: parseInt(req.params.id)
        }
    });

    res.json(sessions);
});

export default router;