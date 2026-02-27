import express from "express";
import multer from "multer";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

/* ===============================
   MULTER CONFIG
================================ */

const storage = multer.diskStorage({
    destination: "uploads/",
    filename: (req, file, cb) => {
        cb(null, Date.now() + "-" + file.originalname);
    },
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = [
        "application/pdf",
        "image/png",
        "image/jpeg",
    ];

    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error("Invalid file type"), false);
    }
};

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter,
});

/* ===============================
   UPLOAD DOCUMENT
================================ */

router.post(
    "/upload",
    authMiddleware,
    upload.single("file"),
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({ message: "No file uploaded" });
            }

            const document = await prisma.document.create({
                data: {
                    filename: req.file.filename,
                    url: `/uploads/${req.file.filename}`,
                    userId: req.user.id,
                },
            });

            res.status(201).json(document);
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: "Upload failed" });
        }
    }
);

/* ===============================
   GET MY DOCUMENTS
================================ */

router.get("/", authMiddleware, async (req, res) => {
    try {
        const documents = await prisma.document.findMany({
            where: { userId: req.user.id },
            orderBy: { createdAt: "desc" },
        });

        res.json(documents);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to fetch documents" });
    }
});

/* ===============================
   DELETE MY DOCUMENT
================================ */

router.delete("/:id", authMiddleware, async (req, res) => {
    try {
        const documentId = parseInt(req.params.id);

        const deleted = await prisma.document.deleteMany({
            where: {
                id: documentId,
                userId: req.user.id,
            },
        });

        if (deleted.count === 0) {
            return res.status(404).json({ message: "Document not found" });
        }

        res.json({ message: "Deleted" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to delete document" });
    }
});

export default router;