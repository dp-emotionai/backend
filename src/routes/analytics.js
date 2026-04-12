import express from "express";
import PDFDocument from "pdfkit";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

router.use(authMiddleware);

function requireTeacherOrAdmin(req, res, next) {
    const role = req.user?.role;
    if (role !== "TEACHER" && role !== "ADMIN") {
        return res.status(403).json({ error: "Forbidden: teacher or admin only" });
    }
    next();
}

async function ensureSessionAccess(sessionId, userId, role) {
    const session = await prisma.session.findUnique({
        where: { id: sessionId },
        include: { group: true },
    });
    if (!session) return { ok: false, status: 404, error: "Session not found" };
    if (role !== "ADMIN" && session.createdById !== userId) {
        return { ok: false, status: 403, error: "Forbidden" };
    }
    return { ok: true, session };
}

async function ensureGroupAccess(groupId, userId, role) {
    const group = await prisma.group.findUnique({ where: { id: groupId } });
    if (!group) return { ok: false, status: 404, error: "Group not found" };
    if (role !== "ADMIN" && group.teacherId !== userId) {
        return { ok: false, status: 403, error: "Forbidden" };
    }
    return { ok: true, group };
}

router.get("/session/:id/export", requireTeacherOrAdmin, async (req, res) => {
    try {
        const sessionId = req.params.id;
        const format = (req.query.format || "json").toLowerCase();
        const userId = req.user.id;
        const role = req.user.role;
        const access = await ensureSessionAccess(sessionId, userId, role);
        if (!access.ok) {
            return res.status(access.status).json({ error: access.error });
        }
        const { session } = access;

        const summary = await prisma.sessionSummary.findUnique({ where: { sessionId } });
        const timeline = await prisma.sessionTimelineBucket.findMany({
            where: { sessionId },
            orderBy: { index: "asc" },
        });
        const samples = await prisma.sessionEmotionSample.findMany({
            where: { sessionId },
            orderBy: { timestamp: "asc" },
        });
        const stressEvents = samples.filter(
            (s) => s.state === "HIGH_RISK" || s.risk > 0.7
        ).length;
        const avgEngagement = summary?.avgEngagement ?? (samples.length
            ? 1 - samples.reduce((a, s) => a + s.risk, 0) / samples.length
            : 0);

        const payload = {
            sessionId,
            title: session.title,
            avgEngagement,
            stressEvents,
            attentionDrops: summary?.attentionDrops ?? stressEvents,
            timeline: timeline.map((b) => ({
                index: b.index,
                fromSec: b.fromSec,
                toSec: b.toSec,
                avgEngagement: b.avgEngagement,
                avgStress: b.avgStress,
                avgRisk: b.avgRisk,
            })),
        };

        if (format === "json") {
            res.setHeader("Content-Type", "application/json");
            res.setHeader("Content-Disposition", `attachment; filename="session-${sessionId}.json"`);
            return res.json(payload);
        }
        if (format === "csv") {
            res.setHeader("Content-Type", "text/csv");
            res.setHeader("Content-Disposition", `attachment; filename="session-${sessionId}.csv"`);
            res.flushHeaders();
            const rows = [
                ["metric", "value"],
                ["sessionId", sessionId],
                ["title", session.title],
                ["avgEngagement", String(payload.avgEngagement)],
                ["stressEvents", String(payload.stressEvents)],
                ["attentionDrops", String(payload.attentionDrops)],
            ];
            const stream = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n") + "\n";
            res.write(stream);
            if (payload.timeline.length) {
                res.write("index,fromSec,toSec,avgEngagement,avgStress,avgRisk\n");
                for (const t of payload.timeline) {
                    res.write(`${t.index},${t.fromSec},${t.toSec},${t.avgEngagement},${t.avgStress},${t.avgRisk}\n`);
                }
            }
            return res.end();
        }
        if (format === "pdf") {
            res.setHeader("Content-Type", "application/pdf");
            res.setHeader("Content-Disposition", `attachment; filename="session-${sessionId}.pdf"`);
            const doc = new PDFDocument({ margin: 50 });
            doc.pipe(res);
            doc.fontSize(18).text(`Session: ${session.title}`, { continued: false });
            doc.fontSize(12).text(`Session ID: ${sessionId}`, { continued: false });
            doc.text(`Avg engagement: ${(payload.avgEngagement * 100).toFixed(1)}%`, { continued: false });
            doc.text(`Stress events: ${payload.stressEvents}`, { continued: false });
            doc.text(`Attention drops: ${payload.attentionDrops}`, { continued: false });
            doc.moveDown().fontSize(14).text("Timeline", { continued: false });
            for (const t of payload.timeline.slice(0, 20)) {
                doc.fontSize(10).text(
                    `[${t.fromSec}s–${t.toSec}s] engagement ${(t.avgEngagement * 100).toFixed(0)}%`,
                    { continued: false }
                );
            }
            if (payload.timeline.length > 20) {
                doc.text(`… and ${payload.timeline.length - 20} more buckets`, { continued: false });
            }
            doc.end();
            return;
        }
        return res.status(400).json({ error: "Unsupported format. Use json, csv, or pdf" });
    } catch (e) {
        console.error("GET /analytics/session/:id/export", e);
        return res.status(500).json({ error: "Export failed" });
    }
});

router.get("/group/:id/export", requireTeacherOrAdmin, async (req, res) => {
    try {
        const groupId = req.params.id;
        const format = (req.query.format || "csv").toLowerCase();
        const userId = req.user.id;
        const role = req.user.role;
        const access = await ensureGroupAccess(groupId, userId, role);
        if (!access.ok) {
            return res.status(access.status).json({ error: access.error });
        }

        const sessions = await prisma.session.findMany({
            where: { groupId },
            include: { summary: true },
            orderBy: { createdAt: "desc" },
        });
        const totalSessions = sessions.length;
        const withSummary = sessions.filter((s) => s.summary != null);
        const avgEngagement = withSummary.length
            ? withSummary.reduce((a, s) => a + (s.summary?.avgEngagement ?? 0), 0) / withSummary.length
            : 0;
        const engagementTrend = withSummary.slice(0, 10).map((s) => s.summary?.avgEngagement ?? 0).reverse();
        const payload = {
            groupId,
            groupName: access.group.name,
            totalSessions,
            avgEngagement,
            engagementTrend,
        };

        if (format === "json") {
            res.setHeader("Content-Type", "application/json");
            res.setHeader("Content-Disposition", `attachment; filename="group-${groupId}.json"`);
            return res.json(payload);
        }
        if (format === "csv") {
            res.setHeader("Content-Type", "text/csv");
            res.setHeader("Content-Disposition", `attachment; filename="group-${groupId}.csv"`);
            res.flushHeaders();
            res.write(`"groupId","${groupId}"\n`);
            res.write(`"groupName","${String(access.group.name).replace(/"/g, '""')}"\n`);
            res.write(`"totalSessions","${totalSessions}"\n`);
            res.write(`"avgEngagement","${avgEngagement}"\n`);
            res.write("engagementTrend\n");
            engagementTrend.forEach((v) => res.write(`${v}\n`));
            return res.end();
        }
        if (format === "pdf") {
            res.setHeader("Content-Type", "application/pdf");
            res.setHeader("Content-Disposition", `attachment; filename="group-${groupId}.pdf"`);
            const doc = new PDFDocument({ margin: 50 });
            doc.pipe(res);
            doc.fontSize(18).text(`Group: ${access.group.name}`, { continued: false });
            doc.text(`Group ID: ${groupId}`, { continued: false });
            doc.text(`Total sessions: ${totalSessions}`, { continued: false });
            doc.text(`Avg engagement: ${(avgEngagement * 100).toFixed(1)}%`, { continued: false });
            doc.end();
            return;
        }
        return res.status(400).json({ error: "Unsupported format. Use json, csv, or pdf" });
    } catch (e) {
        console.error("GET /analytics/group/:id/export", e);
        return res.status(500).json({ error: "Export failed" });
    }
});

router.get("/teacher/export", requireTeacherOrAdmin, async (req, res) => {
    try {
        const format = (req.query.format || "json").toLowerCase();
        const userId = req.user.id;
        const role = req.user.role;
        const whereSession = role === "ADMIN" ? {} : { createdById: userId };

        const sessions = await prisma.session.findMany({
            where: whereSession,
            include: { summary: true, group: true },
        });
        const totalSessions = sessions.length;
        const withSummary = sessions.filter((s) => s.summary != null);
        const avgEngagement = withSummary.length
            ? withSummary.reduce((a, s) => a + (s.summary?.avgEngagement ?? 0), 0) / withSummary.length
            : 0;
        const stressEvents = withSummary.reduce(
            (a, s) => a + (s.summary?.attentionDrops ?? 0),
            0
        );
        const byGroup = new Map();
        for (const s of sessions) {
            const gid = s.groupId;
            if (!byGroup.has(gid)) byGroup.set(gid, { groupName: s.group?.name ?? gid, count: 0 });
            byGroup.get(gid).count += 1;
        }
        const sessionDistribution = Array.from(byGroup.entries()).map(([id, v]) => ({
            groupId: id,
            groupName: v.groupName,
            sessionCount: v.count,
        }));
        const payload = {
            totalSessions,
            avgEngagement,
            stressEvents,
            sessionDistribution,
        };

        if (format === "json") {
            res.setHeader("Content-Type", "application/json");
            res.setHeader("Content-Disposition", 'attachment; filename="teacher-analytics.json"');
            return res.json(payload);
        }
        if (format === "csv") {
            res.setHeader("Content-Type", "text/csv");
            res.setHeader("Content-Disposition", 'attachment; filename="teacher-analytics.csv"');
            res.flushHeaders();
            res.write("metric,value\n");
            res.write(`totalSessions,${totalSessions}\n`);
            res.write(`avgEngagement,${avgEngagement}\n`);
            res.write(`stressEvents,${stressEvents}\n`);
            res.write("groupId,groupName,sessionCount\n");
            for (const d of sessionDistribution) {
                res.write(`${d.groupId},"${String(d.groupName).replace(/"/g, '""')}",${d.sessionCount}\n`);
            }
            return res.end();
        }
        if (format === "pdf") {
            res.setHeader("Content-Type", "application/pdf");
            res.setHeader("Content-Disposition", 'attachment; filename="teacher-analytics.pdf"');
            const doc = new PDFDocument({ margin: 50 });
            doc.pipe(res);
            doc.fontSize(18).text("Teacher analytics", { continued: false });
            doc.fontSize(12).text(`Total sessions: ${totalSessions}`, { continued: false });
            doc.text(`Avg engagement: ${(avgEngagement * 100).toFixed(1)}%`, { continued: false });
            doc.text(`Stress events: ${stressEvents}`, { continued: false });
            doc.moveDown().text("Session distribution by group", { continued: false });
            for (const d of sessionDistribution) {
                doc.fontSize(10).text(`${d.groupName}: ${d.sessionCount} sessions`, { continued: false });
            }
            doc.end();
            return;
        }
        return res.status(400).json({ error: "Unsupported format. Use json, csv, or pdf" });
    } catch (e) {
        console.error("GET /analytics/teacher/export", e);
        return res.status(500).json({ error: "Export failed" });
    }
});
router.get("/session/:sessionId", requireTeacherOrAdmin, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const userId = req.user.id;
        const role = req.user.role;
        const access = await ensureSessionAccess(sessionId, userId, role);
        if (!access.ok) {
            return res.status(access.status).json({ error: access.error });
        }
        const { session } = access;

        const summary = await prisma.sessionSummary.findUnique({
            where: { sessionId },
        });
        const timeline = await prisma.sessionTimelineBucket.findMany({
            where: { sessionId },
            orderBy: { index: "asc" },
        });

        const samples = await prisma.sessionEmotionSample.findMany({
            where: { sessionId },
            orderBy: { timestamp: "asc" },
        });
        const stressEvents = samples.filter(
            (s) => s.state === "HIGH_RISK" || s.risk > 0.7
        ).length;

        const avgEngagement = summary?.avgEngagement ?? (samples.length
            ? Math.max(0, 1 - samples.reduce((a, s) => a + s.risk, 0) / samples.length)
            : 0);
        const attentionDrops = summary?.attentionDrops ?? stressEvents;

        return res.json({
            sessionId,
            title: session.title,
            avgEngagement,
            stressEvents,
            attentionDrops,
            timeline: timeline.map((b) => ({
                index: b.index,
                fromSec: b.fromSec,
                toSec: b.toSec,
                avgEngagement: b.avgEngagement,
                avgStress: b.avgStress,
                avgRisk: b.avgRisk,
            })),
        });
    } catch (e) {
        console.error("GET /analytics/session/:sessionId", e);
        return res.status(500).json({ error: "Failed to fetch session analytics" });
    }
});

router.get("/group/:groupId", requireTeacherOrAdmin, async (req, res) => {
    try {
        const { groupId } = req.params;
        const userId = req.user.id;
        const role = req.user.role;
        const access = await ensureGroupAccess(groupId, userId, role);
        if (!access.ok) {
            return res.status(access.status).json({ error: access.error });
        }

        const sessions = await prisma.session.findMany({
            where: { groupId },
            include: { summary: true },
            orderBy: { createdAt: "desc" },
        });
        const totalSessions = sessions.length;
        const withEngagement = sessions.filter((s) => s.summary != null);
        const avgEngagement = withEngagement.length
            ? withEngagement.reduce((a, s) => a + (s.summary?.avgEngagement ?? 0), 0) / withEngagement.length
            : 0;
        const engagementTrend = withEngagement
            .slice(0, 10)
            .map((s) => s.summary?.avgEngagement ?? 0)
            .reverse();

        return res.json({
            groupId,
            groupName: access.group.name,
            totalSessions,
            avgEngagement,
            engagementTrend,
        });
    } catch (e) {
        console.error("GET /analytics/group/:groupId", e);
        return res.status(500).json({ error: "Failed to fetch group analytics" });
    }
});

router.get("/teacher", requireTeacherOrAdmin, async (req, res) => {
    try {
        const userId = req.user.id;
        const role = req.user.role;
        const whereSession = role === "ADMIN" ? {} : { createdById: userId };

        const sessions = await prisma.session.findMany({
            where: whereSession,
            include: { summary: true, group: true },
            orderBy: { createdAt: "desc" },
        });
        const totalSessions = sessions.length;
        const withSummary = sessions.filter((s) => s.summary != null);
        const avgEngagement = withSummary.length
            ? withSummary.reduce((a, s) => a + (s.summary?.avgEngagement ?? 0), 0) / withSummary.length
            : 0;
        const stressEvents = withSummary.reduce(
            (a, s) => a + (s.summary?.attentionDrops ?? 0),
            0
        );
        const byGroup = new Map();
        for (const s of sessions) {
            const gid = s.groupId;
            if (!byGroup.has(gid)) byGroup.set(gid, { groupName: s.group?.name ?? gid, count: 0 });
            byGroup.get(gid).count += 1;
        }
        const sessionDistribution = Array.from(byGroup.entries()).map(([id, v]) => ({
            groupId: id,
            groupName: v.groupName,
            sessionCount: v.count,
        }));

        return res.json({
            totalSessions,
            avgEngagement,
            stressEvents,
            sessionDistribution,
        });
    } catch (e) {
        console.error("GET /analytics/teacher", e);
        return res.status(500).json({ error: "Failed to fetch teacher analytics" });
    }
});

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