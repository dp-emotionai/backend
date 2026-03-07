import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

router.use(authMiddleware);

router.post("/", async (req, res) => {
    try {
        const { score, emotion } = req.body ?? {};
        const data = await prisma.analytics.create({
            data: {
                score: typeof score === "number" ? score : 0,
                emotion: emotion ?? null,
                userId: req.user.id,
            },
        });
        res.status(201).json(data);
    } catch (e) {
        console.error("POST /analytics", e);
        res.status(500).json({ error: "Failed to create analytics" });
    }
});

router.get("/user/:id", async (req, res) => {
    try {
        const targetId = req.params.id;
        if (req.user.id !== targetId && req.user.role !== "ADMIN") {
            return res.status(403).json({ error: "Forbidden" });
        }
        const analytics = await prisma.analytics.findMany({
            where: { userId: targetId },
            orderBy: { createdAt: "desc" },
        });
        res.json(analytics);
    } catch (e) {
        console.error("GET /analytics/user/:id", e);
        res.status(500).json({ error: "Failed to fetch analytics" });
    }
});

export default router;