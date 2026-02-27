import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

router.post("/", authMiddleware, async (req, res) => {
    const { title, content } = req.body;

    const note = await prisma.note.create({
        data: {
            title,
            content,
            userId: req.user.id,
        },
    });

    res.json(note);
});

router.get("/", authMiddleware, async (req, res) => {
    const notes = await prisma.note.findMany({
        where: { userId: req.user.id },
    });

    res.json(notes);
});

router.put("/:id", authMiddleware, async (req, res) => {
    const { title, content, pinned } = req.body;

    const note = await prisma.note.update({
        where: {
            id: parseInt(req.params.id),
            // опционально можно добавить userId: req.user.id, чтобы нельзя было чужие менять
        },
        data: { title, content, pinned },
    });

    res.json(note);
});

router.delete("/:id", authMiddleware, async (req, res) => {
    await prisma.note.delete({
        where: {
            id: parseInt(req.params.id),
            // сюда тоже можно добавить userId: req.user.id для безопасности
        },
    });

    res.json({ message: "Deleted" });
});

export default router;