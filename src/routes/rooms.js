import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

// создать комнату
router.post("/", authMiddleware, async (req, res) => {
    const { title, groupId } = req.body;

    const room = await prisma.room.create({
        data: {
            title,
            groupId: groupId ? parseInt(groupId) : null
        }
    });

    res.json(room);
});

// получить комнаты группы
router.get("/:groupId", authMiddleware, async (req, res) => {
    const rooms = await prisma.room.findMany({
        where: {
            groupId: parseInt(req.params.groupId)
        }
    });

    res.json(rooms);
});

export default router;