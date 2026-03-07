import express from "express";
import prisma from "../utils/prisma.js";
import {logAudit} from "../utils/audit.js";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";

const router = express.Router();

router.use(authMiddleware);
router.use(roleMiddleware(["TEACHER", "ADMIN"]));

function randomCode() {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let s = "ELAS-";
    for (let i = 0; i < 4; i++) s += chars[Math.floor(Math.random() * chars.length)];
    return s;
}

async function ensureUniqueCode() {
    for (let i = 0; i < 20; i++) {
        const code = randomCode();
        const exists = await prisma.session.findUnique({ where: { code } });
        if (!exists) return code;
    }
    return "ELAS-" + Date.now().toString(36).toUpperCase().slice(-4);
}

// GET /api/teacher/groups — teacher's groups
router.get("/groups", async (req, res) => {
    try {
        const userId = req.user.id;
        const groups = await prisma.group.findMany({
            where: { teacherId: userId },
            include: {
                teacher: { select: { email: true, name: true } },
                _count: { select: { sessions: true } },
            },
            orderBy: { createdAt: "desc" },
        });
        return res.json(
            groups.map((g) => ({
                id: g.id,
                name: g.name,
                teacherId: g.teacherId,
                teacher: g.teacher.email,
                teacherName: g.teacher.name,
                sessionCount: g._count.sessions,
                createdAt: g.createdAt,
            }))
        );
    } catch (e) {
        console.error("GET /teacher/groups", e);
        res.status(500).json({ error: "Failed to list groups" });
    }
});

// POST /api/teacher/groups — create group
router.post("/groups", async (req, res) => {
    try {
        const { name } = req.body;
        if (!name || !String(name).trim()) {
            return res.status(400).json({ error: "Name required" });
        }
        const userId = req.user.id;
        const group = await prisma.group.create({
            data: { name: String(name).trim(), teacherId: userId },
        });
        await logAudit(userId, "group_created", "group", group.id, JSON.stringify({ name: group.name }));
        res.status(201).json({
            id: group.id,
            name: group.name,
            teacherId: group.teacherId,
            createdAt: group.createdAt,
        });
    } catch (e) {
        console.error("POST /teacher/groups", e);
        res.status(500).json({ error: "Failed to create group" });
    }
});

// POST /api/teacher/sessions — create session (teacher or admin)
router.post("/sessions", async (req, res) => {
    try {
        const userId = req.user.id;
        const { title, type, groupId } = req.body;
        if (!title || !String(title).trim()) {
            return res.status(400).json({ error: "Title required" });
        }
        const gId = groupId && String(groupId).trim() ? String(groupId).trim() : null;
        if (!gId) {
            return res.status(400).json({ error: "groupId required" });
        }
        const group = await prisma.group.findFirst({
            where: { id: gId, teacherId: userId },
        });
        if (!group) {
            return res.status(404).json({ error: "Group not found" });
        }
        const sessionType = type === "exam" ? "exam" : "lecture";
        const code = await ensureUniqueCode();
        const session = await prisma.session.create({
            data: {
                title: String(title).trim(),
                type: sessionType,
                groupId: gId,
                createdById: userId,
                code,
            },
        });
        await logAudit(userId, "session_created", "session", session.id, JSON.stringify({ title: session.title, type: sessionType, groupId: gId }));
        res.status(201).json({
            id: session.id,
            title: session.title,
            type: session.type,
            status: session.status,
            code: session.code,
            groupId: session.groupId,
            createdAt: session.createdAt,
        });
    } catch (e) {
        console.error("POST /teacher/sessions", e);
        res.status(500).json({ error: "Failed to create session" });
    }
});

// PUT /api/teacher/sessions/:id/start
router.put("/sessions/:id/start", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;
        const session = await prisma.session.findUnique({ where: { id: sessionId } });
        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }
        if (session.createdById !== userId && req.user.role !== "ADMIN") {
            return res.status(403).json({ error: "Forbidden" });
        }
        const updated = await prisma.session.update({
            where: { id: sessionId },
            data: {
                status: "active",
                startedAt: session.startedAt || new Date(),
            },
            include: { group: true },
        });
        await logAudit(userId, "session_started", "session", sessionId, null);
        res.json({
            id: updated.id,
            title: updated.title,
            type: updated.type,
            status: updated.status,
            code: updated.code,
            groupId: updated.groupId,
            groupName: updated.group.name,
            startedAt: updated.startedAt,
            endedAt: updated.endedAt,
        });
    } catch (e) {
        console.error("PUT /teacher/sessions/:id/start", e);
        res.status(500).json({ error: "Failed to start session" });
    }
});

// PUT /api/teacher/sessions/:id/end
router.put("/sessions/:id/end", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;
        const session = await prisma.session.findUnique({ where: { id: sessionId } });
        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }
        if (session.createdById !== userId && req.user.role !== "ADMIN") {
            return res.status(403).json({ error: "Forbidden" });
        }
        const updated = await prisma.session.update({
            where: { id: sessionId },
            data: {
                status: "finished",
                endedAt: new Date(),
            },
            include: { group: true },
        });
        await logAudit(userId, "session_ended", "session", sessionId, null);
        res.json({
            id: updated.id,
            title: updated.title,
            type: updated.type,
            status: updated.status,
            code: updated.code,
            groupId: updated.groupId,
            groupName: updated.group.name,
            startedAt: updated.startedAt,
            endedAt: updated.endedAt,
        });
    } catch (e) {
        console.error("PUT /teacher/sessions/:id/end", e);
        res.status(500).json({ error: "Failed to end session" });
    }
});

export default router;
