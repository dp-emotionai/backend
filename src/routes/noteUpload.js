import express from "express";
import multer from "multer";
import authMiddleware from "../middleware/authMiddleware.js";
import prisma from "../utils/prisma.js";
import {
    makeStorageKey,
    uploadBufferToR2,
} from "../utils/r2.js";

const router = express.Router();

const storage = multer.memoryStorage();

const upload = multer({
    storage,
    limits: {
        fileSize: 50 * 1024 * 1024
    }
});

router.post("/", authMiddleware, upload.single("file"), async (req, res) => {
    try {
        const { noteId } = req.body;

        if (!req.file) {
            return res.status(400).json({
                message: "No file uploaded"
            });
        }

        const cleanNoteId = noteId && String(noteId).trim()
            ? String(noteId).trim()
            : null;

        if (cleanNoteId) {
            const note = await prisma.note.findFirst({
                where: {
                    id: cleanNoteId,
                    userId: req.user.id
                }
            });

            if (!note) {
                return res.status(404).json({
                    message: "Note not found"
                });
            }
        }

        const file = req.file;

        const storageKey = makeStorageKey(`notes/${req.user.id}`, file.originalname);

        await uploadBufferToR2({
            key: storageKey,
            buffer: file.buffer,
            contentType: file.mimetype || "application/octet-stream",
        });

        const document = await prisma.document.create({
            data: {
                filename: file.originalname,
                url: storageKey,
                type: file.mimetype,
                size: file.size,
                userId: req.user.id,
                noteId: cleanNoteId
            }
        });

        res.json({
            ...document,
            downloadUrl: `/documents/${document.id}/download`
        });
    } catch (error) {
        console.error("NOTE UPLOAD ERROR:", error);

        res.status(500).json({
            error: "Upload failed"
        });
    }
});

export default router;