import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

// получить пользователя по id
router.get("/:id", authMiddleware, async (req, res) => {
    const user = await prisma.user.findUnique({
        where: { id: parseInt(req.params.id) },
        select: {
            id: true,
            email: true,
            createdAt: true
        }
    });

    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
});

// обновить пользователя
router.put("/update", authMiddleware, async (req, res) => {
    const { email } = req.body;

    const updatedUser = await prisma.user.update({
        where: { id: req.user.id },
        data: { email },
        select: {
            id: true,
            email: true,
            createdAt: true
        }
    });

    res.json(updatedUser);
});

export default router;