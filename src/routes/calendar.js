import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";

const router = express.Router();

router.use(authMiddleware);

router.get("/events", async (req, res) => {
    try {
        const userId = req.user.id;
        const role = req.user.role;

        if (role === "ADMIN") {
            const events = await prisma.calendarEvent.findMany({
                orderBy: { startsAt: "asc" },
            });
            return res.json(events);
        }

        if (role === "TEACHER") {
            const groups = await prisma.group.findMany({
                where: { teacherId: userId },
                select: { id: true },
            });

            const groupIds = groups.map(g => g.id);

            const events = await prisma.calendarEvent.findMany({
                where: {
                    OR: [
                        { groupId: { in: groupIds } },
                        { createdById: userId }
                    ]
                },
                orderBy: { startsAt: "asc" },
            });

            return res.json(events);
        }

        const memberships = await prisma.groupMember.findMany({
            where: { userId },
            select: { groupId: true },
        });

        const groupIds = memberships.map(m => m.groupId);

        const events = await prisma.calendarEvent.findMany({
            where: {
                groupId: { in: groupIds }
            },
            orderBy: { startsAt: "asc" },
        });

        return res.json(events);

    } catch (e) {
        console.error("GET /calendar/events", e);
        return res.status(500).json({ error: "Failed to get events" });
    }
});

router.post("/events", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const userId = req.user.id;
        const role = req.user.role;

        const {
            title,
            kind,
            groupId,
            sessionId,
            startsAt,
            endsAt
        } = req.body || {};

        if (!title || !String(title).trim()) {
            return res.status(400).json({ error: "title is required" });
        }

        if (!startsAt) {
            return res.status(400).json({ error: "startsAt is required" });
        }

        let validatedGroupId = null;

        if (groupId) {
            const group = await prisma.group.findUnique({
                where: { id: groupId },
            });

            if (!group) {
                return res.status(404).json({ error: "Group not found" });
            }

            if (role !== "ADMIN" && group.teacherId !== userId) {
                return res.status(403).json({ error: "Forbidden" });
            }

            validatedGroupId = group.id;
        }

        const event = await prisma.calendarEvent.create({
            data: {
                title: String(title).trim(),
                kind: kind || "session",
                groupId: validatedGroupId,
                sessionId: sessionId || null,
                startsAt: new Date(startsAt),
                endsAt: endsAt ? new Date(endsAt) : null,
                createdById: userId,
            },
        });

        return res.status(201).json(event);

    } catch (e) {
        console.error("POST /calendar/events", e);
        return res.status(500).json({ error: "Failed to create event" });
    }
});

router.patch("/events/:eventId", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const eventId = req.params.eventId;
        const userId = req.user.id;
        const role = req.user.role;

        const event = await prisma.calendarEvent.findUnique({
            where: { id: eventId },
        });

        if (!event) {
            return res.status(404).json({ error: "Event not found" });
        }

        if (role !== "ADMIN" && event.createdById !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const {
            title,
            kind,
            startsAt,
            endsAt
        } = req.body || {};

        const updates = {};

        if (title !== undefined) updates.title = String(title).trim();
        if (kind !== undefined) updates.kind = String(kind);
        if (startsAt !== undefined) updates.startsAt = new Date(startsAt);
        if (endsAt !== undefined) updates.endsAt = endsAt ? new Date(endsAt) : null;

        const updated = await prisma.calendarEvent.update({
            where: { id: eventId },
            data: updates,
        });

        return res.json(updated);

    } catch (e) {
        console.error("PATCH /calendar/events/:eventId", e);
        return res.status(500).json({ error: "Failed to update event" });
    }
});

router.delete("/events/:eventId", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const eventId = req.params.eventId;
        const userId = req.user.id;
        const role = req.user.role;

        const event = await prisma.calendarEvent.findUnique({
            where: { id: eventId },
        });

        if (!event) {
            return res.status(404).json({ error: "Event not found" });
        }

        if (role !== "ADMIN" && event.createdById !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        await prisma.calendarEvent.delete({
            where: { id: eventId },
        });

        return res.json({ ok: true, id: eventId });

    } catch (e) {
        console.error("DELETE /calendar/events/:eventId", e);
        return res.status(500).json({ error: "Failed to delete event" });
    }
});

export default router;