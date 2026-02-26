import express from "express";
import prisma from "../utils/prisma.js";
import auth from "../middleware/authMiddleware.js";

const router = express.Router();

router.post("/", auth, async (req, res) => {
    const data = await prisma.analytics.create({
        data: {
            score: req.body.score,
            emotion: req.body.emotion,
            userId: req.user.id
        }
    });

    res.json(data);
});

router.get("/user/:id", auth, async (req, res) => {
    const analytics = await prisma.analytics.findMany({
        where: { userId: parseInt(req.params.id) }
    });

    res.json(analytics);
});

export default router;