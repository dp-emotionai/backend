import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

// Создать заметку
router.post("/", authMiddleware, async (req, res) => {
    try {
        const { title, content } = req.body;

        const note = await prisma.note.create({
            data: {
                title,
                content,
                userId: req.user.id,
            },
        });

        res.status(201).json(note);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to create note" });
    }
});

// Получить свои заметки
router.get("/", authMiddleware, async (req, res) => {
    try {
        const notes = await prisma.note.findMany({
            where: { userId: req.user.id },
            orderBy: { createdAt: "desc" }
        });

        res.json(notes);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to fetch notes" });
    }
});

// Обновить свою заметку
router.put("/:id", authMiddleware, async (req, res) => {
    try {
        const { title, content, pinned } = req.body;
        const noteId = parseInt(req.params.id);

        const updated = await prisma.note.updateMany({
            where: {
                id: noteId,
                userId: req.user.id
            },
            data: { title, content, pinned },
        });

        if (updated.count === 0) {
            return res.status(404).json({ message: "Note not found" });
        }

        res.json({ message: "Note updated" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to update note" });
    }
});

// Удалить свою заметку
router.delete("/:id", authMiddleware, async (req, res) => {
    try {
        const noteId = parseInt(req.params.id);

        const deleted = await prisma.note.deleteMany({
            where: {
                id: noteId,
                userId: req.user.id
            },
        });

        if (deleted.count === 0) {
            return res.status(404).json({ message: "Note not found" });
        }

        res.json({ message: "Deleted" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to delete note" });
    }
});

export default router;