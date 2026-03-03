import express from "express";
import multer from "multer";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import cloudinary from "../utils/cloudinary.js";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

/* ===============================
   CLOUDINARY STORAGE
================================ */

const storage = new CloudinaryStorage({
    cloudinary,
    params: async (req, file) => {
        return {
            folder: "elas_documents",
            resource_type: "auto",
            public_id: Date.now() + "-" + file.originalname,
        };
    },
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
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

            const document = await prisma.document.create({
                data: {
                    filename: req.file.originalname,
                    url: req.file.path,
                    type: req.file.mimetype,
                    size: req.file.size,
                    userId: req.user.id,
                    noteId: noteId ? parseInt(noteId) : null,
                },
            });

            res.status(201).json(document);

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
                    ? { noteId: parseInt(noteId) }
                    : { noteId: null }),
            },
            orderBy: { createdAt: "desc" },
        });

        res.json(documents);

    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: "Failed to fetch documents",
        });
    }
});


router.delete("/:id", authMiddleware, async (req, res) => {
    try {
        const documentId = parseInt(req.params.id);

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

        const parts = document.url.split("/");
        const filename = parts[parts.length - 1];
        const publicId = filename.split(".")[0];

        await cloudinary.uploader.destroy(
            "elas_documents/" + publicId,
            { resource_type: "auto" }
        );

        await prisma.document.delete({
            where: { id: documentId },
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