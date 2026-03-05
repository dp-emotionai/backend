import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

router.post("/", authMiddleware, async (req, res) => {
    try {
        const { title = "", content = "", pinned = false } = req.body;

        let orderValue = 0;

        if (pinned) {
            const lastPinned = await prisma.note.findFirst({
                where: {
                    userId: req.user.id,
                    pinned: true,
                },
                orderBy: { order: "desc" },
            });

            orderValue = lastPinned ? lastPinned.order + 1 : 0;
        }

        const note = await prisma.note.create({
            data: {
                title,
                content,
                pinned,
                order: pinned ? orderValue : 0,
                userId: req.user.id,
            },
        });

        res.status(201).json(note);

    } catch (error) {
        console.error("CREATE NOTE ERROR:", error);
        res.status(500).json({
            error: "Failed to create note",
        });
    }
});

router.get("/", authMiddleware, async (req, res) => {
    try {
        const notes = await prisma.note.findMany({
            where: { userId: req.user.id },
            orderBy: [
                { pinned: "desc" },
                { order: "asc" },
                { createdAt: "desc" },
            ],
            include: {
                attachments: true,
            },
        });

        res.json(notes);

    } catch (error) {
        console.error("GET NOTES ERROR:", error);
        res.status(500).json({
            error: "Failed to fetch notes",
        });
    }
});
router.put("/reorder", authMiddleware, async (req, res) => {
    try {
        const { orderedIds } = req.body;

        if (!Array.isArray(orderedIds)) {
            return res.status(400).json({
                message: "Invalid data",
            });
        }

        const updates = orderedIds.map((id, index) =>
            prisma.note.updateMany({
                where: {
                    id,
                    userId: req.user.id,
                    pinned: true,
                },
                data: {
                    order: index,
                },
            })
        );

        await prisma.$transaction(updates);

        res.json({ message: "Reordered successfully" });

    } catch (error) {
        console.error("REORDER ERROR:", error);
        res.status(500).json({
            error: "Failed to reorder",
        });
    }
});

router.get("/:id", authMiddleware, async (req, res) => {
    try {
        const noteId = parseInt(req.params.id);

        const note = await prisma.note.findFirst({
            where: {
                id: noteId,
                userId: req.user.id,
            },
            include: {
                attachments: true,
            },
        });

        if (!note) {
            return res.status(404).json({
                message: "Note not found",
            });
        }

        res.json(note);

    } catch (error) {
        console.error("GET NOTE ERROR:", error);
        res.status(500).json({
            error: "Failed to fetch note",
        });
    }
});

router.put("/:id", authMiddleware, async (req, res) => {
    try {
        const { title, content, pinned } = req.body;
        const noteId = parseInt(req.params.id);

        const existingNote = await prisma.note.findFirst({
            where: {
                id: noteId,
                userId: req.user.id,
            },
        });

        if (!existingNote) {
            return res.status(404).json({
                message: "Note not found",
            });
        }

        let newOrder = existingNote.order;

        if (pinned === true && existingNote.pinned === false) {
            const lastPinned = await prisma.note.findFirst({
                where: {
                    userId: req.user.id,
                    pinned: true,
                },
                orderBy: { order: "desc" },
            });

            newOrder = lastPinned ? lastPinned.order + 1 : 0;
        }

        if (pinned === false && existingNote.pinned === true) {
            newOrder = 0;
        }

        const updated = await prisma.note.update({
            where: { id: noteId },
            data: {
                ...(title !== undefined && { title }),
                ...(content !== undefined && { content }),
                ...(pinned !== undefined && { pinned }),
                order: newOrder,
            },
        });

        res.json(updated);

    } catch (error) {
        console.error("UPDATE NOTE ERROR:", error);
        res.status(500).json({
            error: "Failed to update note",
        });
    }
});

router.delete("/:id", authMiddleware, async (req, res) => {
    try {
        const noteId = parseInt(req.params.id);

        const deleted = await prisma.note.deleteMany({
            where: {
                id: noteId,
                userId: req.user.id,
            },
        });

        if (deleted.count === 0) {
            return res.status(404).json({
                message: "Note not found",
            });
        }

        res.json({ message: "Deleted" });

    } catch (error) {
        console.error("DELETE NOTE ERROR:", error);
        res.status(500).json({
            error: "Failed to delete note",
        });
    }
});
router.delete("/:id/drawing", authMiddleware, async (req, res) => {
    try {
        const noteId = parseInt(req.params.id);

        const note = await prisma.note.findFirst({
            where: {
                id: noteId,
                userId: req.user.id,
            },
        });

        if (!note) {
            return res.status(404).json({
                message: "Note not found",
            });
        }

        const updated = await prisma.note.update({
            where: { id: noteId },
            data: {
                content: "" // удаляем рисунок
            }
        });

        res.json(updated);

    } catch (error) {
        console.error("DELETE DRAWING ERROR:", error);
        res.status(500).json({
            error: "Failed to delete drawing",
        });
    }
});

export default router;