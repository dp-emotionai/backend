import express from "express";
import multer from "multer";
import cloudinary from "../utils/cloudinary.js";
import authMiddleware from "../middleware/authMiddleware.js";

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

        const file = req.file;

        const base64 = file.buffer.toString("base64");

        const result = await cloudinary.uploader.upload(
            `data:${file.mimetype};base64,${base64}`,
            {
                folder: "notes",
                resource_type: "auto"
            }
        );

        const document = await prisma.document.create({
            data: {
                filename: file.originalname,
                url: result.secure_url,
                type: file.mimetype,
                size: file.size,
                userId: req.user.id,
                noteId: noteId ? parseInt(noteId) : null
            }
        });

        res.json(document);

    } catch (error) {

        console.error("NOTE UPLOAD ERROR:", error);

        res.status(500).json({
            error: "Upload failed"
        });

    }
});

export default router;