import express from "express";
import fetch from "node-fetch";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";

const router = express.Router();

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

// GET /api/sessions — list (admin: all; teacher: own; student: by group membership)
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
                    teacher: { select: { email: true, name: true } },
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
                    teacherName: s.teacher.name,
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
            where: { groupId: { in: groupIds }, status: { in: ["draft", "active"] } },
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

// GET /api/sessions/:id/join-info
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

// --- Чат сессии: сообщения (из PDF) ---
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
        });
        res.json(
            messages
                .map((m) => ({
                    id: m.id,
                    sessionId: m.sessionId,
                    senderId: m.senderId,
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
        res.status(201).json({
            id: msg.id,
            sessionId: msg.sessionId,
            senderId: msg.senderId,
            type: msg.type,
            text: msg.text,
            channel: msg.channel,
            createdAt: msg.createdAt,
        });
    } catch (e) {
        console.error("POST /sessions/:id/messages", e);
        res.status(500).json({ error: "Failed to create message" });
    }
});

// GET /api/sessions/:id
router.get("/:id", async (req, res) => {
    try {
        const id = req.params.id;
        const userId = req.user.id;
        const session = await prisma.session.findUnique({
            where: { id },
            include: { group: true, teacher: { select: { id: true, email: true, name: true } } },
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
            teacherName: session.teacher.name,
            startedAt: session.startedAt,
            endedAt: session.endedAt,
            createdAt: session.createdAt,
        });
    } catch (e) {
        console.error("GET /sessions/:id", e);
        res.status(500).json({ error: "Failed to get session" });
    }
});

// POST /api/sessions — create (teacher)
router.post("/", roleMiddleware("TEACHER"), async (req, res) => {
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

// PATCH /api/sessions/:id
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

// POST /api/sessions/:id/metrics — student sends metrics for live session
router.post("/:id/metrics", roleMiddleware("STUDENT"), async (req, res) => {
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

// GET /api/sessions/:id/live-metrics
router.get("/:id/live-metrics", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;
        const session = await prisma.session.findUnique({ where: { id: sessionId }, include: { group: true } });
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
            select: { id: true, email: true, name: true },
        });
        const userMap = new Map(users.map((u) => [u.id, u]));
        const participants = userIds.map((uid) => {
            const s = latestByUser.get(uid);
            const u = userMap.get(uid);
            return {
                userId: uid,
                name: u?.name ?? u?.email ?? uid,
                email: u?.email,
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

// POST /api/sessions/:id/consent
router.post("/:id/consent", roleMiddleware("STUDENT"), async (req, res) => {
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

// GET /api/sessions/:id/chat-policy
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

// GET /api/sessions/:id/summary
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

// GET /api/sessions/:id/timeline
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

export default router;
