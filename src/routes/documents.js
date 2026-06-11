import express from "express";
import multer from "multer";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";
import {
    makeStorageKey,
    uploadBufferToR2,
    getDownloadUrlFromR2,
    deleteFromR2,
} from "../utils/r2.js";

const router = express.Router();

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
});

const mapDocument = (document) => ({
    id: document.id,
    filename: document.filename,
    url: `/documents/${document.id}/download`,
    downloadUrl: `/documents/${document.id}/download`,
    type: document.type,
    size: document.size,
    userId: document.userId,
    noteId: document.noteId,
    createdAt: document.createdAt,
});

router.post(
    "/upload",
    authMiddleware,
    upload.single("file"),
    async (req, res) => {
        try {
            const { noteId } = req.body;

            if (!req.file) {
                return res.status(400).json({
                    message: "No file uploaded",
                });
            }

            const cleanNoteId = noteId && String(noteId).trim()
                ? String(noteId).trim()
                : null;

            if (cleanNoteId) {
                const note = await prisma.note.findFirst({
                    where: {
                        id: cleanNoteId,
                        userId: req.user.id,
                    },
                });

                if (!note) {
                    return res.status(404).json({
                        message: "Note not found",
                    });
                }
            }

            const storageKey = makeStorageKey(`documents/${req.user.id}`, req.file.originalname);

            await uploadBufferToR2({
                key: storageKey,
                buffer: req.file.buffer,
                contentType: req.file.mimetype || "application/octet-stream",
            });

            const document = await prisma.document.create({
                data: {
                    filename: req.file.originalname,
                    url: storageKey,
                    type: req.file.mimetype,
                    size: req.file.size,
                    userId: req.user.id,
                    noteId: cleanNoteId,
                },
            });

            res.status(201).json(mapDocument(document));

        } catch (error) {
            console.error("UPLOAD ERROR:", error);
            res.status(500).json({
                error: "Upload failed",
            });
        }
    }
);

router.get("/", authMiddleware, async (req, res) => {
    try {
        const { noteId } = req.query;

        const documents = await prisma.document.findMany({
            where: {
                userId: req.user.id,
                ...(noteId
                    ? { noteId: String(noteId).trim() }
                    : { noteId: null }),
            },
            orderBy: { createdAt: "desc" },
            take: 200,
        });

        res.json(documents.map(mapDocument));

    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: "Failed to fetch documents",
        });
    }
});

router.get("/:id/download", authMiddleware, async (req, res) => {
    try {
        const documentId = req.params.id;

        const document = await prisma.document.findFirst({
            where: {
                id: documentId,
                userId: req.user.id,
            },
        });

        if (!document) {
            return res.status(404).json({
                message: "Document not found",
            });
        }

        const downloadUrl = await getDownloadUrlFromR2(document.url, document.filename);

        return res.redirect(downloadUrl);

    } catch (error) {
        console.error("DOWNLOAD ERROR:", error);
        res.status(500).json({
            error: "Failed to download document",
        });
    }
});

router.delete("/:id", authMiddleware, async (req, res) => {
    try {
        const documentId = req.params.id;

        const document = await prisma.document.findFirst({
            where: {
                id: documentId,
                userId: req.user.id,
            },
        });

        if (!document) {
            return res.status(404).json({
                message: "Document not found",
            });
        }

        await deleteFromR2(document.url);

        await prisma.document.delete({
            where: { id: document.id },
        });

        res.json({ message: "Deleted" });

    } catch (error) {
        console.error("DELETE ERROR:", error);
        res.status(500).json({
            error: "Failed to delete document",
        });
    }
});

export default router;