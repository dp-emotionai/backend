import express from "express";
import prisma from "../utils/prisma.js";
import auth from "../middleware/authMiddleware.js";

const router = express.Router();

// создать группу
router.post("/", auth, async (req, res) => {
    const { name, description } = req.body;

    const group = await prisma.group.create({
        data: { name, description }
    });

    await prisma.groupMember.create({
        data: { groupId: group.id, userId: req.user.id }
    });

    res.json(group);
});

// получить группы пользователя
router.get("/", auth, async (req, res) => {
    const groups = await prisma.group.findMany({
        where: {
            members: {
                some: { userId: req.user.id }
            }
        },
        include: {
            members: {
                include: { user: true }
            }
        }
    });

    res.json(groups);
});

export default router;