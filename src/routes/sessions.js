import express from "express";
import fetch from "node-fetch";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";
import { getIO } from "../ws/server.js";
import { broadcastSessionChatMessage } from "../ws/raw.js";

const router = express.Router();

function randomCode() {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let s = "konilAI-";
    for (let i = 0; i < 4; i++) s += chars[Math.floor(Math.random() * chars.length)];
    return s;
}

async function ensureUniqueCode() {
    for (let i = 0; i < 20; i++) {
        const code = randomCode();
        const exists = await prisma.session.findUnique({ where: { code } });
        if (!exists) return code;
    }
    return "konilAI-" + Date.now().toString(36).toUpperCase().slice(-4);
}

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || null;
const BUCKET_SECONDS = 60;

async function aggregateSessionAnalytics(sessionId, startedAt, endedAt) {
    const samples = await prisma.sessionEmotionSample.findMany({
        where: { sessionId },
        orderBy: { timestamp: "asc" },
    });

    if (samples.length === 0) {
        const durationMs = startedAt && endedAt ? endedAt - startedAt : 0;
        const durationMinutes = durationMs ? durationMs / 60000 : null;

        await prisma.sessionSummary.upsert({
            where: { sessionId },
            create: {
                sessionId,
                avgEngagement: 0,
                attentionDrops: 0,
                quality: "medium",
                avgStress: 0,
                durationMinutes,
            },
            update: {
                avgEngagement: 0,
                attentionDrops: 0,
                quality: "medium",
                avgStress: 0,
                durationMinutes,
            },
        });

        return;
    }

    const avgRisk = samples.reduce((s, x) => s + x.risk, 0) / samples.length;
    const avgEngagement = Math.max(0, Math.min(1, 1 - avgRisk));
    const attentionDrops = samples.filter(
        (x) => x.state === "HIGH_RISK" || x.risk > 0.7
    ).length;
    const avgStress = avgRisk;
    const durationMs = startedAt && endedAt ? endedAt - startedAt : 0;
    const durationMinutes = durationMs ? durationMs / 60000 : null;

    let quality = "medium";
    if (avgEngagement >= 0.7) quality = "good";
    else if (avgEngagement < 0.4) quality = "poor";

    await prisma.sessionSummary.upsert({
        where: { sessionId },
        create: {
            sessionId,
            avgEngagement,
            attentionDrops,
            quality,
            avgStress,
            durationMinutes,
        },
        update: {
            avgEngagement,
            attentionDrops,
            quality,
            avgStress,
            durationMinutes,
        },
    });

    const startTs = startedAt ? startedAt.getTime() : samples[0].timestamp.getTime();
    const bucketsByIndex = new Map();

    for (const s of samples) {
        const elapsedSec = (s.timestamp.getTime() - startTs) / 1000;
        const index = Math.floor(elapsedSec / BUCKET_SECONDS);
        if (index < 0) continue;

        if (!bucketsByIndex.has(index)) {
            bucketsByIndex.set(index, []);
        }

        bucketsByIndex.get(index).push(s);
    }

    await prisma.sessionTimelineBucket.deleteMany({ where: { sessionId } });

    const sortedIndices = Array.from(bucketsByIndex.keys()).sort((a, b) => a - b);

    for (const index of sortedIndices) {
        const list = bucketsByIndex.get(index);
        const avgR = list.reduce((sum, x) => sum + x.risk, 0) / list.length;
        const avgEng = Math.max(0, Math.min(1, 1 - avgR));

        await prisma.sessionTimelineBucket.create({
            data: {
                sessionId,
                index,
                fromSec: index * BUCKET_SECONDS,
                toSec: (index + 1) * BUCKET_SECONDS,
                avgEngagement: avgEng,
                avgStress: avgR,
                avgRisk: avgR,
            },
        });
    }
}

async function analyzeFrameWithML(image) {
    if (!ML_SERVICE_URL || !image) return null;

    try {
        const res = await fetch(`${ML_SERVICE_URL}/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ image }),
        });

        if (!res.ok) {
            console.error("ML service error:", res.status);
            return null;
        }

        const data = await res.json();
        console.log("ML service ok for frame");
        return data;
    } catch (e) {
        console.error("ML service error:", e);
        return null;
    }
}

router.use(authMiddleware);

function buildFullName(user) {
    return [user?.firstName, user?.lastName].filter(Boolean).join(" ").trim();
}

async function getSessionWithAccessContext(sessionId, userId, role) {
    const session = await prisma.session.findUnique({
        where: { id: sessionId },
        include: {
            group: true,
            teacher: {
                select: {
                    id: true,
                    email: true,
                    firstName: true,
                    lastName: true,
                },
            },
        },
    });

    if (!session) {
        return { error: { status: 404, body: { error: "Session not found" } } };
    }

    const isOwner = session.createdById === userId;
    const isAdmin = role === "ADMIN";
    let isMember = false;

    if (role === "STUDENT") {
        const gm = await prisma.groupMember.findUnique({
            where: {
                groupId_userId: {
                    groupId: session.groupId,
                    userId,
                },
            },
        });
        isMember = !!gm;
    }

    return {
        session,
        isOwner,
        isAdmin,
        isMember,
        canAccess: isOwner || isAdmin || isMember,
    };
}

function mapSessionNote(note) {
    return {
        id: note.id,
        sessionId: note.sessionId,
        author: {
            id: note.user.id,
            email: note.user.email,
            firstName: note.user.firstName,
            lastName: note.user.lastName,
            fullName: buildFullName(note.user),
            role: note.user.role,
        },
        text: note.text,
        pinned: note.pinned,
        createdAt: note.createdAt,
        updatedAt: note.updatedAt,
    };
}

router.get("/", async (req, res) => {
    try {
        const role = req.user.role;
        const userId = req.user.id;

        if (role === "ADMIN") {
            const sessions = await prisma.session.findMany({
                select: {
                    id: true,
                    title: true,
                    type: true,
                    status: true,
                    code: true,
                    groupId: true,
                    startedAt: true,
                    endedAt: true,
                    createdAt: true,
                    group: { select: { name: true } },
                    teacher: { select: { email: true, firstName: true, lastName: true } },
                },
                orderBy: { createdAt: "desc" },
                take: 100,
            });

            return res.json(
                sessions.map((s) => ({
                    id: s.id,
                    title: s.title,
                    type: s.type,
                    status: s.status,
                    code: s.code,
                    groupId: s.groupId,
                    groupName: s.group.name,
                    teacher: s.teacher.email,
                    teacherName: [s.teacher.firstName, s.teacher.lastName].filter(Boolean).join(" "),
                    startedAt: s.startedAt,
                    endedAt: s.endedAt,
                    createdAt: s.createdAt,
                }))
            );
        }

        if (role === "TEACHER") {
            const sessions = await prisma.session.findMany({
                where: { createdById: userId },
                select: {
                    id: true,
                    title: true,
                    type: true,
                    status: true,
                    code: true,
                    groupId: true,
                    startedAt: true,
                    endedAt: true,
                    createdAt: true,
                    group: { select: { name: true } },
                },
                orderBy: { createdAt: "desc" },
                take: 100,
            });

            return res.json(
                sessions.map((s) => ({
                    id: s.id,
                    title: s.title,
                    type: s.type,
                    status: s.status,
                    code: s.code,
                    groupId: s.groupId,
                    groupName: s.group.name,
                    teacher: req.user.email,
                    startedAt: s.startedAt,
                    endedAt: s.endedAt,
                    createdAt: s.createdAt,
                }))
            );
        }

        const memberGroups = await prisma.groupMember.findMany({
            where: { userId },
            select: { groupId: true },
        });

        const groupIds = memberGroups.map((m) => m.groupId);

        const sessions = await prisma.session.findMany({
            where: {
                groupId: { in: groupIds },
                status: { in: ["draft", "active"] },
            },
            select: {
                id: true,
                title: true,
                type: true,
                status: true,
                code: true,
                groupId: true,
                startedAt: true,
                endedAt: true,
                createdAt: true,
                group: { select: { name: true } },
                teacher: { select: { email: true } },
            },
            orderBy: { createdAt: "desc" },
            take: 100,
        });

        return res.json(
            sessions.map((s) => ({
                id: s.id,
                title: s.title,
                type: s.type,
                status: s.status === "active" ? "live" : "upcoming",
                code: s.code,
                groupName: s.group.name,
                teacher: s.teacher.email,
                date: s.startedAt || s.createdAt,
            }))
        );
    } catch (e) {
        console.error("GET /sessions", e);
        res.status(500).json({ error: "Failed to list sessions" });
    }
});

router.get("/:id/join-info", async (req, res) => {
    try {
        const id = req.params.id;
        const userId = req.user.id;

        const session = await prisma.session.findUnique({
            where: { id },
            include: { group: true },
        });

        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }

        const isTeacherOrAdmin = req.user.role === "TEACHER" || req.user.role === "ADMIN";
        const isOwner = session.createdById === userId;
        const consentRequired = true;
        const isLive = session.status === "active";

        if (req.user.role === "STUDENT") {
            const isMember = await prisma.groupMember.findUnique({
                where: { groupId_userId: { groupId: session.groupId, userId } },
            });

            if (!isMember) {
                return res.status(404).json({ error: "Session not found" });
            }
        }

        if (isTeacherOrAdmin || isOwner) {
            return res.json({
                title: session.title,
                type: session.type,
                status: session.status,
                consentRequired,
                allowedToJoin: true,
                groupName: session.group.name,
            });
        }

        const hasConsent = await prisma.consentRecord.findUnique({
            where: { userId_sessionId: { userId, sessionId: id } },
        });

        const allowedToJoin = isLive && !!hasConsent;
        let reason;

        if (!isLive) reason = session.status === "finished" ? "session_ended" : "session_not_started";
        else if (!hasConsent) reason = "consent_required";

        return res.json({
            title: session.title,
            type: session.type,
            status: session.status,
            consentRequired,
            allowedToJoin,
            reason,
            groupName: session.group.name,
        });
    } catch (e) {
        console.error("GET /sessions/:id/join-info", e);
        res.status(500).json({ error: "Failed to get join info" });
    }
});

router.get("/:id/messages", async (req, res) => {
    const userId = req.user.id;
    const sessionId = req.params.id;
    const channel = (req.query.channel || "public").toString();
    const take = 100;

    try {
        const session = await prisma.session.findUnique({ where: { id: sessionId } });

        if (!session) {
            res.status(404).json({ error: "Session not found" });
            return;
        }

        const isOwner = session.createdById === userId;
        const isAdmin = req.user.role === "ADMIN";
        let isMember = false;

        if (req.user.role === "STUDENT") {
            const gm = await prisma.groupMember.findUnique({
                where: { groupId_userId: { groupId: session.groupId, userId } },
            });
            isMember = !!gm;
        }

        if (!isOwner && !isAdmin && !isMember) {
            res.status(403).json({ error: "Forbidden" });
            return;
        }

        const messages = await prisma.sessionMessage.findMany({
            where: { sessionId, channel: channel === "help" ? "help" : "public" },
            orderBy: { createdAt: "desc" },
            take,
            include: {
                sender: {
                    select: {
                        id: true,
                        email: true,
                        role: true,
                        firstName: true,
                        lastName: true,
                    },
                },
            },
        });

        res.json(
            messages
                .map((m) => ({
                    id: m.id,
                    sessionId: m.sessionId,
                    senderId: m.senderId,
                    senderName:
                        [m.sender?.firstName, m.sender?.lastName].filter(Boolean).join(" ") ||
                        m.sender?.email ||
                        m.senderId,
                    senderRole: m.sender?.role ? String(m.sender.role).toLowerCase() : null,
                    type: m.type,
                    text: m.text,
                    channel: m.channel,
                    createdAt: m.createdAt,
                    editedAt: m.editedAt,
                    deletedAt: m.deletedAt,
                }))
                .reverse()
        );
    } catch (e) {
        console.error("GET /sessions/:id/messages", e);
        res.status(500).json({ error: "Failed to load messages" });
    }
});

router.post("/:id/messages", async (req, res) => {
    const userId = req.user.id;
    const sessionId = req.params.id;
    const { type, text, channel } = req.body || {};

    if (!type || !text || !String(text).trim()) {
        res.status(400).json({ error: "type and text required" });
        return;
    }

    try {
        const session = await prisma.session.findUnique({ where: { id: sessionId } });

        if (!session) {
            res.status(404).json({ error: "Session not found" });
            return;
        }

        const isOwner = session.createdById === userId;
        const isAdmin = req.user.role === "ADMIN";
        let isMember = false;

        if (req.user.role === "STUDENT") {
            const gm = await prisma.groupMember.findUnique({
                where: { groupId_userId: { groupId: session.groupId, userId } },
            });
            isMember = !!gm;
        }

        if (!isOwner && !isAdmin && !isMember) {
            res.status(403).json({ error: "Forbidden" });
            return;
        }

        const ch = channel === "help" ? "help" : "public";

        const msg = await prisma.sessionMessage.create({
            data: {
                sessionId,
                senderId: userId,
                type,
                text: String(text).trim(),
                channel: ch,
            },
        });

        const senderName =
            req.user.fullName ||
            [req.user.firstName, req.user.lastName].filter(Boolean).join(" ") ||
            req.user.email ||
            msg.senderId;

        const payload = {
            id: msg.id,
            sessionId: msg.sessionId,
            senderId: msg.senderId,
            senderName,
            senderRole: String(req.user.role || "").toLowerCase(),
            type: msg.type,
            text: msg.text,
            channel: msg.channel,
            createdAt: msg.createdAt,
        };

        const wsPayload = {
            type: "message.new",
            scope: "session",
            sessionId,
            channel: ch,
            event: {
                id: msg.id,
                text: msg.text,
                senderId: msg.senderId,
                senderName,
                senderRole: String(req.user.role || "").toLowerCase(),
                createdAt: msg.createdAt,
                channel: msg.channel,
            },
        };

        try {
            broadcastSessionChatMessage(sessionId, wsPayload);
        } catch (wsError) {
            console.error("POST /sessions/:id/messages broadcast error", wsError);
        }

        res.status(201).json(payload);
    } catch (e) {
        console.error("POST /sessions/:id/messages", e);
        res.status(500).json({ error: "Failed to create message" });
    }
});

router.get("/:id/notes", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;
        const role = req.user.role;

        const access = await getSessionWithAccessContext(sessionId, userId, role);

        if (access.error) {
            return res.status(access.error.status).json(access.error.body);
        }

        if (!access.canAccess) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const notes = await prisma.sessionNote.findMany({
            where: { sessionId },
            include: {
                user: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                        role: true,
                    },
                },
            },
            orderBy: [
                { pinned: "desc" },
                { createdAt: "desc" },
            ],
            take: 500,
        });

        return res.json({
            notes: notes.map(mapSessionNote),
        });
    } catch (e) {
        console.error("GET /sessions/:id/notes", e);
        return res.status(500).json({ error: "Failed to fetch notes" });
    }
});

router.post("/:id/notes", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;
        const role = req.user.role;
        const { text } = req.body || {};

        const textValue = String(text || "").trim();

        if (!textValue) {
            return res.status(400).json({ error: "Text is required" });
        }

        const access = await getSessionWithAccessContext(sessionId, userId, role);

        if (access.error) {
            return res.status(access.error.status).json(access.error.body);
        }

        if (!access.canAccess) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const note = await prisma.sessionNote.create({
            data: {
                sessionId,
                userId,
                text: textValue,
            },
            include: {
                user: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                        role: true,
                    },
                },
            },
        });

        try {
            const io = getIO();
            io.to(`session:${sessionId}`).emit("session:note_created", mapSessionNote(note));
        } catch (wsError) {
            console.error("POST /sessions/:id/notes emit error", wsError);
        }

        return res.status(201).json(mapSessionNote(note));
    } catch (e) {
        console.error("POST /sessions/:id/notes", e);
        return res.status(500).json({ error: "Failed to create note" });
    }
});

router.patch("/:id/notes/:noteId", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const noteId = req.params.noteId;
        const userId = req.user.id;
        const role = req.user.role;
        const { text, pinned } = req.body || {};

        const access = await getSessionWithAccessContext(sessionId, userId, role);

        if (access.error) {
            return res.status(access.error.status).json(access.error.body);
        }

        if (!access.canAccess) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const note = await prisma.sessionNote.findUnique({
            where: { id: noteId },
            include: {
                user: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                        role: true,
                    },
                },
            },
        });

        if (!note || note.sessionId !== sessionId) {
            return res.status(404).json({ error: "Note not found" });
        }

        const isAuthor = note.userId === userId;
        const canModerate = access.isOwner || access.isAdmin;

        if (!isAuthor && !canModerate) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const data = {};

        if (text !== undefined) {
            const textValue = String(text).trim();
            if (!textValue) {
                return res.status(400).json({ error: "Text cannot be empty" });
            }
            data.text = textValue;
        }

        if (pinned !== undefined) {
            if (!canModerate) {
                return res.status(403).json({ error: "Only teacher or admin can pin notes" });
            }
            data.pinned = !!pinned;
        }

        if (Object.keys(data).length === 0) {
            return res.status(400).json({ error: "No fields to update" });
        }

        const updated = await prisma.sessionNote.update({
            where: { id: noteId },
            data,
            include: {
                user: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                        role: true,
                    },
                },
            },
        });

        try {
            const io = getIO();
            io.to(`session:${sessionId}`).emit("session:note_updated", mapSessionNote(updated));
        } catch (wsError) {
            console.error("PATCH /sessions/:id/notes/:noteId emit error", wsError);
        }

        return res.json(mapSessionNote(updated));
    } catch (e) {
        console.error("PATCH /sessions/:id/notes/:noteId", e);
        return res.status(500).json({ error: "Failed to update note" });
    }
});

router.delete("/:id/notes/:noteId", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const noteId = req.params.noteId;
        const userId = req.user.id;
        const role = req.user.role;

        const access = await getSessionWithAccessContext(sessionId, userId, role);

        if (access.error) {
            return res.status(access.error.status).json(access.error.body);
        }

        if (!access.canAccess) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const note = await prisma.sessionNote.findUnique({
            where: { id: noteId },
        });

        if (!note || note.sessionId !== sessionId) {
            return res.status(404).json({ error: "Note not found" });
        }

        const isAuthor = note.userId === userId;
        const canModerate = access.isOwner || access.isAdmin;

        if (!isAuthor && !canModerate) {
            return res.status(403).json({ error: "Forbidden" });
        }

        await prisma.sessionNote.delete({
            where: { id: noteId },
        });

        try {
            const io = getIO();
            io.to(`session:${sessionId}`).emit("session:note_deleted", {
                id: noteId,
                sessionId,
            });
        } catch (wsError) {
            console.error("DELETE /sessions/:id/notes/:noteId emit error", wsError);
        }

        return res.json({ ok: true, id: noteId });
    } catch (e) {
        console.error("DELETE /sessions/:id/notes/:noteId", e);
        return res.status(500).json({ error: "Failed to delete note" });
    }
});

router.post("/", roleMiddleware(["TEACHER"]), async (req, res) => {
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

        return res.status(201).json({
            id: session.id,
            title: session.title,
            type: session.type,
            status: session.status,
            code: session.code,
            groupId: session.groupId,
            createdAt: session.createdAt,
        });
    } catch (e) {
        console.error("POST /sessions", e);
        res.status(500).json({ error: "Failed to create session" });
    }
});

router.patch("/:id", async (req, res) => {
    try {
        const id = req.params.id;
        const userId = req.user.id;

        const session = await prisma.session.findUnique({ where: { id } });

        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }

        const isOwner = session.createdById === userId;
        const isAdmin = req.user.role === "ADMIN";

        if (!isOwner && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const body = req.body;
        const updates = {};

        if (body.title !== undefined) updates.title = String(body.title).trim();
        if (body.type === "lecture" || body.type === "exam") updates.type = body.type;

        if (body.status === "active") {
            updates.status = "active";
            updates.startedAt = session.startedAt || new Date();
        } else if (body.status === "finished") {
            updates.status = "finished";
            updates.endedAt = new Date();
        } else if (body.status === "draft") {
            updates.status = "draft";
        }

        const updated = await prisma.session.update({
            where: { id },
            data: updates,
            include: { group: true },
        });

        if (updated.status === "finished") {
            try {
                await aggregateSessionAnalytics(
                    updated.id,
                    updated.startedAt,
                    updated.endedAt
                );
            } catch (aggErr) {
                console.error("PATCH /sessions/:id — aggregateSessionAnalytics", aggErr);
            }
        }

        return res.json({
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
        console.error("PATCH /sessions/:id", e);
        res.status(500).json({ error: "Failed to update session" });
    }
});

router.post("/:id/metrics", roleMiddleware(["STUDENT"]), async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;

        const session = await prisma.session.findUnique({ where: { id: sessionId } });

        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }

        if (session.status !== "active") {
            return res.status(400).json({ error: "Session is not live" });
        }

        const isMember = await prisma.groupMember.findUnique({
            where: { groupId_userId: { groupId: session.groupId, userId } },
        });

        if (!isMember) {
            return res.status(403).json({ error: "Not a member of this session's group" });
        }

        const body = req.body;

        let emotion = typeof body.emotion === "string" ? body.emotion : "Neutral";
        let confidence = typeof body.confidence === "number" ? body.confidence : 0;
        let risk = typeof body.risk === "number" ? body.risk : 0;
        let state = typeof body.state === "string" ? body.state : "NORMAL";
        let dominantEmotion =
            typeof body.dominant_emotion === "string"
                ? body.dominant_emotion
                : typeof body.dominantEmotion === "string"
                    ? body.dominantEmotion
                    : "Neutral";

        if (body && body.image) {
            const ml = await analyzeFrameWithML(body.image);

            if (ml) {
                emotion = ml.emotion ?? emotion;
                confidence = typeof ml.confidence === "number" ? ml.confidence : confidence;
                risk = typeof ml.risk === "number" ? ml.risk : risk;
                state = typeof ml.state === "string" ? ml.state : state;
                dominantEmotion =
                    typeof ml.dominant_emotion === "string"
                        ? ml.dominant_emotion
                        : typeof ml.dominantEmotion === "string"
                            ? ml.dominantEmotion
                            : dominantEmotion;
            }
        }

        await prisma.sessionEmotionSample.create({
            data: {
                sessionId,
                userId,
                emotion,
                confidence,
                risk,
                state,
                dominantEmotion,
            },
        });

        return res.json({ ok: true });
    } catch (e) {
        console.error("POST /sessions/:id/metrics", e);
        res.status(500).json({ error: "Failed to store metrics" });
    }
});

router.get("/:id/live-metrics", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;

        const session = await prisma.session.findUnique({
            where: { id: sessionId },
            include: { group: true },
        });

        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }

        const isOwner = session.createdById === userId;
        const isAdmin = req.user.role === "ADMIN";

        if (!isOwner && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const samples = await prisma.sessionEmotionSample.findMany({
            where: { sessionId },
            orderBy: { timestamp: "desc" },
            take: 1000,
        });

        if (!samples.length) {
            return res.json({ participants: [], avgRisk: 0, avgConfidence: 0 });
        }

        const latestByUser = new Map();

        for (const s of samples) {
            if (!latestByUser.has(s.userId)) {
                latestByUser.set(s.userId, s);
            }
        }

        const userIds = Array.from(latestByUser.keys());

        const users = await prisma.user.findMany({
            where: { id: { in: userIds } },
            select: { id: true, email: true, firstName: true, lastName: true },
        });

        const userMap = new Map(users.map((u) => [u.id, u]));

        const participants = userIds.map((uid) => {
            const s = latestByUser.get(uid);
            const u = userMap.get(uid);

            return {
                userId: uid,
                email: u?.email,
                firstName: u?.firstName ?? null,
                lastName: u?.lastName ?? null,
                fullName: [u?.firstName, u?.lastName].filter(Boolean).join(" ") || u?.email || uid,
                emotion: s.emotion,
                confidence: s.confidence,
                risk: s.risk,
                state: s.state,
                dominant_emotion: s.dominantEmotion,
                updatedAt: s.timestamp.toISOString(),
            };
        });

        const avgRisk = participants.reduce((s, p) => s + p.risk, 0) / participants.length;
        const avgConfidence = participants.reduce((s, p) => s + p.confidence, 0) / participants.length;

        return res.json({ participants, avgRisk, avgConfidence });
    } catch (e) {
        console.error("GET /sessions/:id/live-metrics", e);
        res.status(500).json({ error: "Failed to get live metrics" });
    }
});

router.post("/:id/consent", roleMiddleware(["STUDENT"]), async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;

        const session = await prisma.session.findUnique({ where: { id: sessionId } });

        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }

        await prisma.consentRecord.upsert({
            where: { userId_sessionId: { userId, sessionId } },
            create: { userId, sessionId },
            update: {},
        });

        return res.status(201).json({ ok: true, sessionId });
    } catch (e) {
        console.error("POST /sessions/:id/consent", e);
        res.status(500).json({ error: "Failed to record consent" });
    }
});

router.get("/:id/chat-policy", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;

        const session = await prisma.session.findUnique({
            where: { id: sessionId },
            include: { group: true },
        });

        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }

        const isOwner = session.createdById === userId;
        const isAdmin = req.user.role === "ADMIN";
        let isMember = false;

        if (req.user.role === "STUDENT") {
            const gm = await prisma.groupMember.findUnique({
                where: { groupId_userId: { groupId: session.groupId, userId } },
            });
            isMember = !!gm;
        }

        if (!isOwner && !isAdmin && !isMember) {
            return res.status(403).json({ error: "Forbidden" });
        }

        return res.json({
            sessionId: session.id,
            chatEnabled: true,
            studentCanWrite: true,
            studentCanSeeOthers: true,
        });
    } catch (e) {
        console.error("GET /sessions/:id/chat-policy", e);
        res.status(500).json({ error: "Failed to get chat policy" });
    }
});

router.get("/:id/summary", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;

        const session = await prisma.session.findUnique({
            where: { id: sessionId },
        });

        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }

        const isOwner = session.createdById === userId;
        const isAdmin = req.user.role === "ADMIN";

        if (!isOwner && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const summary = await prisma.sessionSummary.findUnique({
            where: { sessionId },
        });

        if (!summary) {
            return res.json({
                sessionId,
                avgEngagement: 0,
                attentionDrops: 0,
                quality: "medium",
                avgStress: 0,
                durationMinutes: null,
            });
        }

        return res.json({
            sessionId,
            avgEngagement: summary.avgEngagement,
            attentionDrops: summary.attentionDrops,
            quality: summary.quality,
            avgStress: summary.avgStress ?? 0,
            durationMinutes: summary.durationMinutes ?? null,
        });
    } catch (e) {
        console.error("GET /sessions/:id/summary", e);
        res.status(500).json({ error: "Failed to get session summary" });
    }
});

router.get("/:id/timeline", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;

        const session = await prisma.session.findUnique({
            where: { id: sessionId },
        });

        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }

        const isOwner = session.createdById === userId;
        const isAdmin = req.user.role === "ADMIN";

        if (!isOwner && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const buckets = await prisma.sessionTimelineBucket.findMany({
            where: { sessionId },
            orderBy: { index: "asc" },
        });

        return res.json({
            sessionId,
            buckets: buckets.map((b) => ({
                index: b.index,
                fromSec: b.fromSec,
                toSec: b.toSec,
                avgEngagement: b.avgEngagement,
                avgStress: b.avgStress,
                avgRisk: b.avgRisk,
            })),
        });
    } catch (e) {
        console.error("GET /sessions/:id/timeline", e);
        res.status(500).json({ error: "Failed to get session timeline" });
    }
});

router.get("/:id", async (req, res) => {
    try {
        const id = req.params.id;
        const userId = req.user.id;

        const session = await prisma.session.findUnique({
            where: { id },
            include: {
                group: true,
                teacher: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                    },
                },
            },
        });

        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }

        const isOwner = session.createdById === userId;
        const isAdmin = req.user.role === "ADMIN";

        if (!isOwner && !isAdmin && req.user.role === "STUDENT") {
            if (session.status !== "active") {
                return res.status(404).json({ error: "Session not found" });
            }
        } else if (!isOwner && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }

        return res.json({
            id: session.id,
            title: session.title,
            type: session.type,
            status: session.status,
            code: session.code,
            groupId: session.groupId,
            groupName: session.group.name,
            teacher: session.teacher.email,
            teacherName: [session.teacher.firstName, session.teacher.lastName].filter(Boolean).join(" "),
            startedAt: session.startedAt,
            endedAt: session.endedAt,
            createdAt: session.createdAt,
        });
    } catch (e) {
        console.error("GET /sessions/:id", e);
        res.status(500).json({ error: "Failed to get session" });
    }
});

export default router;