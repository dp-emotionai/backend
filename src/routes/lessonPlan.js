import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";
import { broadcastSessionEvent } from "../socket/server.js";

const router = express.Router();

function startOfDay(value) {
    const date = new Date(value);
    date.setHours(0, 0, 0, 0);
    return date;
}

function nextDay(value) {
    const date = startOfDay(value);
    date.setDate(date.getDate() + 1);
    return date;
}

function canEditPlan(user) {
    return user?.role === "TEACHER" || user?.role === "ADMIN";
}

function planPayload(type, plan) {
    return {
        type,
        plan,
        sessionId: plan.sessionId,
        planId: plan.id,
        date: plan.date instanceof Date ? plan.date.toISOString() : plan.date,
        ts: new Date().toISOString(),
    };
}

router.get("/session/:sessionId", authMiddleware, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { date } = req.query;

        if (!date) {
            return res.status(400).json({ message: "date is required" });
        }

        const plan = await prisma.lessonPlan.findFirst({
            where: {
                sessionId,
                date: {
                    gte: startOfDay(date),
                    lt: nextDay(date),
                },
            },
        });

        res.json(plan);
    } catch (error) {
        console.error("Get lesson plan error:", error);
        res.status(500).json({ message: "Failed to get lesson plan" });
    }
});

router.get("/session/:sessionId/all", authMiddleware, async (req, res) => {
    try {
        const { sessionId } = req.params;

        const plans = await prisma.lessonPlan.findMany({
            where: { sessionId },
            orderBy: { date: "asc" },
        });

        res.json(plans);
    } catch (error) {
        console.error("Get lesson plans error:", error);
        res.status(500).json({ message: "Failed to get lesson plans" });
    }
});

router.post("/session/:sessionId", authMiddleware, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { date, title, description } = req.body;

        if (!canEditPlan(req.user)) {
            return res.status(403).json({ message: "Only teacher can create lesson plan" });
        }

        if (!date || !title) {
            return res.status(400).json({ message: "date and title are required" });
        }

        const planDate = startOfDay(date);

        const plan = await prisma.lessonPlan.upsert({
            where: {
                sessionId_date: {
                    sessionId,
                    date: planDate,
                },
            },
            update: {
                title,
                description,
            },
            create: {
                sessionId,
                teacherId: req.user.id,
                date: planDate,
                title,
                description,
            },
        });

        broadcastSessionEvent(sessionId, planPayload("lesson-plan.updated", plan));

        res.json(plan);
    } catch (error) {
        console.error("Save lesson plan error:", error);
        res.status(500).json({ message: "Failed to save lesson plan" });
    }
});

router.patch("/:planId", authMiddleware, async (req, res) => {
    try {
        const { planId } = req.params;
        const { date, title, description } = req.body;

        if (!canEditPlan(req.user)) {
            return res.status(403).json({ message: "Only teacher can update lesson plan" });
        }

        const plan = await prisma.lessonPlan.update({
            where: { id: planId },
            data: {
                ...(date ? { date: startOfDay(date) } : {}),
                ...(title !== undefined ? { title } : {}),
                ...(description !== undefined ? { description } : {}),
            },
        });

        broadcastSessionEvent(plan.sessionId, planPayload("lesson-plan.updated", plan));

        res.json(plan);
    } catch (error) {
        console.error("Update lesson plan error:", error);
        res.status(500).json({ message: "Failed to update lesson plan" });
    }
});

router.delete("/:planId", authMiddleware, async (req, res) => {
    try {
        const { planId } = req.params;

        if (!canEditPlan(req.user)) {
            return res.status(403).json({ message: "Only teacher can delete lesson plan" });
        }

        const plan = await prisma.lessonPlan.findUnique({
            where: { id: planId },
        });

        if (!plan) {
            return res.status(404).json({ message: "Lesson plan not found" });
        }

        await prisma.lessonPlan.delete({
            where: { id: planId },
        });

        broadcastSessionEvent(plan.sessionId, planPayload("lesson-plan.deleted", plan));

        res.json({ ok: true });
    } catch (error) {
        console.error("Delete lesson plan error:", error);
        res.status(500).json({ message: "Failed to delete lesson plan" });
    }
});

export default router;