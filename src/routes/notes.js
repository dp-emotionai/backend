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
            userId: req.userId,
        },
    });

    res.json(note);
});

router.get("/", authMiddleware, async (req, res) => {
    const notes = await prisma.note.findMany({
        where: { userId: req.userId },
    });

    res.json(notes);
});

router.put("/:id", authMiddleware, async (req, res) => {
    const { title, content, pinned } = req.body;

    const note = await prisma.note.update({
        where: { id: parseInt(req.params.id) },
        data: { title, content, pinned },
    });

    res.json(note);
});

router.delete("/:id", authMiddleware, async (req, res) => {
    await prisma.note.delete({
        where: { id: parseInt(req.params.id) },
    });

    res.json({ message: "Deleted" });
});

export default router;