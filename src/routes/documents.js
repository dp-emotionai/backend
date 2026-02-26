import express from "express";
import multer from "multer";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

const storage = multer.diskStorage({
    destination: "uploads/",
    filename: (req, file, cb) => {
        cb(null, Date.now() + "-" + file.originalname);
    },
});

const upload = multer({ storage });

router.post(
    "/upload",
    authMiddleware,
    upload.single("file"),
    async (req, res) => {
        const document = await prisma.document.create({
            data: {
                filename: req.file.filename,
                url: `/uploads/${req.file.filename}`,
                userId: req.userId,
            },
        });

        res.json(document);
    }
);

router.get("/", authMiddleware, async (req, res) => {
    const documents = await prisma.document.findMany({
        where: { userId: req.userId },
    });

    res.json(documents);
});

router.delete("/:id", authMiddleware, async (req, res) => {
    await prisma.document.delete({
        where: { id: parseInt(req.params.id) },
    });

    res.json({ message: "Deleted" });
});

export default router;