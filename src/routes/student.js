import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";

const router = express.Router();

router.use(authMiddleware);
router.use(roleMiddleware("STUDENT"));

router.get("/analytics/sessions", async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit, 10) || 10, 50);
        const userId = req.user.id;

        const analytics = await prisma.analytics.findMany({
            where: { userId },
            orderBy: { createdAt: "desc" },
            take: limit,
        });

        const sessions = analytics.map((a) => ({
            sessionId: a.id,
            sessionTitle: "Session",
            date: a.createdAt.toISOString(),
            averageEngagement: a.score ?? 0,
            peakEngagement: a.score ?? 0,
            lowEngagement: a.score ?? 0,
            duration: 0,
            totalDataPoints: 1,
            trend: "stable",
        }));

        return res.json({ sessions });
    } catch (e) {
        console.error("GET /student/analytics/sessions", e);
        res.status(500).json({ error: "Failed to fetch session performance" });
    }
});

router.get("/sessions/upcoming", async (req, res) => {
    try {
        const userId = req.user.id;
        const memberGroups = await prisma.groupMember.findMany({
            where: { userId },
            select: { groupId: true },
        });
        const groupIds = memberGroups.map((m) => m.groupId);
        const now = new Date();

        const sessions = await prisma.session.findMany({
            where: {
                groupId: { in: groupIds },
                status: { in: ["draft", "active"] },
                OR: [{ startedAt: null }, { startedAt: { gt: now } }],
            },
            include: { group: true, teacher: { select: { id: true, firstName: true, lastName: true, email: true } } },
            orderBy: { createdAt: "asc" },
        });

        const list = sessions.map((s) => ({
            id: s.id,
            title: s.title,
            description: null,
            startTime: (s.startedAt || s.createdAt).toISOString(),
            endTime: s.endedAt?.toISOString() ?? null,
            instructorId: s.teacher.id,
            instructorName: [s.teacher.firstName, s.teacher.lastName].filter(Boolean).join(" ") || s.teacher.email,
            room: s.group.name,
            isOnline: true,
            status: s.status === "active" ? "active" : "scheduled",
            averageEngagement: null,
            participantCount: null,
        }));

        return res.json({ sessions: list });
    } catch (e) {
        console.error("GET /student/sessions/upcoming", e);
        res.status(500).json({ error: "Failed to fetch upcoming sessions" });
    }
});

router.get("/sessions/current", async (req, res) => {
    try {
        const userId = req.user.id;
        const memberGroups = await prisma.groupMember.findMany({
            where: { userId },
            select: { groupId: true },
        });
        const groupIds = memberGroups.map((m) => m.groupId);

        const session = await prisma.session.findFirst({
            where: {
                groupId: { in: groupIds },
                status: "active",
            },
            include: { group: true, teacher: { select: { id: true, firstName: true, lastName: true, email: true } } },
        });

        if (!session) {
            return res.json({ session: null });
        }

        const out = {
            id: session.id,
            title: session.title,
            description: null,
            startTime: (session.startedAt || session.createdAt).toISOString(),
            endTime: session.endedAt?.toISOString() ?? null,
            instructorId: session.teacher.id,
            instructorName: [session.teacher.firstName, session.teacher.lastName].filter(Boolean).join(" ") || session.teacher.email,
            room: session.group.name,
            isOnline: true,
            status: "active",
            averageEngagement: null,
            participantCount: null,
        };

        return res.json({ session: out });
    } catch (e) {
        console.error("GET /student/sessions/current", e);
        res.status(500).json({ error: "Failed to fetch current session" });
    }
});

router.get("/sessions/history", async (req, res) => {
    try {
        const userId = req.user.id;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const skip = (page - 1) * limit;

        const memberGroups = await prisma.groupMember.findMany({
            where: { userId },
            select: { groupId: true },
        });
        const groupIds = memberGroups.map((m) => m.groupId);

        const [sessions, total] = await Promise.all([
            prisma.session.findMany({
                where: { groupId: { in: groupIds }, status: "finished" },
                include: { group: true, teacher: { select: { id: true, firstName: true, lastName: true, email: true } } },
                orderBy: { endedAt: "desc" },
                skip,
                take: limit,
            }),
            prisma.session.count({
                where: { groupId: { in: groupIds }, status: "finished" },
            }),
        ]);

        const list = sessions.map((s) => ({
            id: s.id,
            title: s.title,
            description: null,
            startTime: (s.startedAt || s.createdAt).toISOString(),
            endTime: s.endedAt?.toISOString() ?? null,
            instructorId: s.teacher.id,
            instructorName: [s.teacher.firstName, s.teacher.lastName].filter(Boolean).join(" ") || s.teacher.email,
            room: s.group.name,
            isOnline: false,
            status: "completed",
            averageEngagement: null,
            participantCount: null,
        }));

        return res.json({ sessions: list, total });
    } catch (e) {
        console.error("GET /student/sessions/history", e);
        res.status(500).json({ error: "Failed to fetch session history" });
    }
});

router.post("/sessions/:id/join", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;
        const session = await prisma.session.findUnique({ where: { id: sessionId } });
        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }
        const isMember = await prisma.groupMember.findUnique({
            where: { groupId_userId: { groupId: session.groupId, userId } },
        });
        if (!isMember) {
            return res.status(403).json({ error: "Not a member of this session's group" });
        }
        if (session.status !== "active") {
            return res.status(400).json({ error: "Session is not live" });
        }
        return res.json({ ok: true });
    } catch (e) {
        console.error("POST /student/sessions/:id/join", e);
        res.status(500).json({ error: "Failed to join session" });
    }
});

router.post("/sessions/:id/leave", async (req, res) => {
    try {
        return res.json({ ok: true });
    } catch (e) {
        console.error("POST /student/sessions/:id/leave", e);
        res.status(500).json({ error: "Failed to leave session" });
    }
});

router.get("/sessions/:id/engagement", async (req, res) => {
    try {
        const sessionId = req.params.id;
        const userId = req.user.id;

        const session = await prisma.session.findUnique({ where: { id: sessionId } });
        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }
        const isMember = await prisma.groupMember.findUnique({
            where: { groupId_userId: { groupId: session.groupId, userId } },
        });
        if (!isMember) {
            return res.status(403).json({ error: "Not a member of this session's group" });
        }

        const analytics = await prisma.analytics.findMany({
            where: { userId },
            orderBy: { createdAt: "asc" },
            take: 5000,
        });

        const dataPoints = analytics.map((a) => ({
            timestamp: a.createdAt.toISOString(),
            engagement: a.score ?? 0,
            emotion: a.emotion ?? null,
        }));

        const scores = dataPoints.map((d) => d.engagement);
        const sum = scores.reduce((a, b) => a + b, 0);
        const avg = scores.length ? sum / scores.length : 0;
        const max = scores.length ? Math.max(...scores) : 0;
        const min = scores.length ? Math.min(...scores) : 0;

        const history = {
            sessionId,
            dataPoints,
            averageEngagement: avg,
            maxEngagement: max,
            minEngagement: min,
            totalDuration: 0,
        };

        return res.json({ history });
    } catch (e) {
        console.error("GET /student/sessions/:id/engagement", e);
        res.status(500).json({ error: "Failed to fetch engagement" });
    }
});

router.get("/analytics", async (req, res) => {
    try {
        const userId = req.user.id;
        const start = req.query.start ? new Date(req.query.start) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const end = req.query.end ? new Date(req.query.end) : new Date();

        const analytics = await prisma.analytics.findMany({
            where: {
                userId,
                createdAt: { gte: start, lte: end },
            },
            orderBy: { createdAt: "asc" },
            take: 10000,
        });

        const byDay = new Map();
        for (const a of analytics) {
            const day = a.createdAt.toISOString().slice(0, 10);
            if (!byDay.has(day)) byDay.set(day, []);
            byDay.get(day).push(a.score ?? 0);
        }

        const dailyEngagement = Array.from(byDay.entries()).map(([date, scores]) => ({
            date: new Date(date + "T00:00:00Z").toISOString(),
            averageEngagement: scores.reduce((a, b) => a + b, 0) / scores.length,
            sessionCount: scores.length,
        }));

        const weekStart = new Date(end);
        weekStart.setDate(weekStart.getDate() - 7);
        const weekScores = analytics.filter((a) => a.createdAt >= weekStart).map((a) => a.score ?? 0);
        const weeklySummary = {
            averageEngagement: weekScores.length ? weekScores.reduce((a, b) => a + b, 0) / weekScores.length : 0,
            totalSessions: weekScores.length,
            improvementRate: 0,
            weekStart: weekStart.toISOString(),
            weekEnd: end.toISOString(),
        };

        const recentSessions = analytics.slice(0, 10).map((a) => ({
            sessionId: a.id,
            sessionTitle: "Session",
            date: a.createdAt.toISOString(),
            averageEngagement: a.score ?? 0,
            peakEngagement: a.score ?? 0,
            lowEngagement: a.score ?? 0,
            duration: 0,
            totalDataPoints: 1,
            trend: "stable",
        }));

        const allScores = analytics.map((a) => a.score ?? 0);
        const overallStats = {
            overallAverage: allScores.length ? allScores.reduce((a, b) => a + b, 0) / allScores.length : 0,
            bestSession: allScores.length ? Math.max(...allScores) : 0,
            worstSession: allScores.length ? Math.min(...allScores) : 0,
            totalSessions: allScores.length,
            totalTimeSpent: 0,
        };

        return res.json({
            dailyEngagement,
            weeklySummary,
            recentSessions,
            overallStats,
        });
    } catch (e) {
        console.error("GET /student/analytics", e);
        res.status(500).json({ error: "Failed to fetch analytics" });
    }
});

router.get("/me/emotions-summary", async (req, res) => {
    try {
        const userId = req.user.id;

        const samples = await prisma.sessionEmotionSample.findMany({
            where: { userId },
            orderBy: { timestamp: "desc" },
            take: 5000,
        });

        if (!samples.length) {
            return res.json({
                analyzedSessions: 0,
                avgEngagement: 0,
                stressPeaks: 0,
                bestTimeWindow: null,
                engagementSeries: [],
                dropsSeries: [],
                weekCompare: {
                    thisWeek: 0,
                    prevWeek: 0,
                    delta: 0,
                },
                emotionsDistribution: {},
            });
        }

        const sessionsSet = new Set(samples.map((s) => s.sessionId));
        const analyzedSessions = sessionsSet.size;

        const avgEngagement = 1 - samples.reduce((sum, s) => sum + (s.risk ?? 0), 0) / samples.length;

        const stressPeaks = samples.filter(
            (s) => s.state === "HIGH_RISK" || (s.risk ?? 0) > 0.7
        ).length;

        const byHour = new Map();
        for (const s of samples) {
            const h = s.timestamp.getUTCHours();
            if (!byHour.has(h)) byHour.set(h, []);
            byHour.get(h).push(1 - (s.risk ?? 0));
        }
        let bestHour = null;
        let bestScore = -1;
        for (const [h, vals] of byHour.entries()) {
            const score = vals.reduce((a, b) => a + b, 0) / vals.length;
            if (score > bestScore) {
                bestScore = score;
                bestHour = h;
            }
        }
        const pad = (n) => String(n).padStart(2, "0");
        const bestTimeWindow =
            bestHour === null ? null : `${pad(bestHour)}:00-${pad((bestHour + 2) % 24)}:00`;

        const sessionList = Array.from(sessionsSet);
        const engagementSeries = [];
        const dropsSeries = [];
        for (let i = 0; i < Math.min(6, sessionList.length); i++) {
            const sid = sessionList[i];
            const ss = samples.filter((s) => s.sessionId === sid);
            const eng = 1 - ss.reduce((sum, s) => sum + (s.risk ?? 0), 0) / ss.length;
            const drops = ss.filter(
                (s) => s.state === "HIGH_RISK" || (s.risk ?? 0) > 0.7
            ).length;
            engagementSeries.push(Math.round(eng * 100));
            dropsSeries.push(drops);
        }

        const now = new Date();
        const thisWeekStart = new Date(now);
        thisWeekStart.setDate(thisWeekStart.getDate() - 7);
        const prevWeekStart = new Date(thisWeekStart);
        prevWeekStart.setDate(prevWeekStart.getDate() - 7);

        const thisWeekSamples = samples.filter(
            (s) => s.timestamp >= thisWeekStart && s.timestamp <= now
        );
        const prevWeekSamples = samples.filter(
            (s) => s.timestamp >= prevWeekStart && s.timestamp < thisWeekStart
        );

        const thisWeek =
            thisWeekSamples.length
                ? 1 -
                thisWeekSamples.reduce((sum, s) => sum + (s.risk ?? 0), 0) / thisWeekSamples.length
                : 0;
        const prevWeek =
            prevWeekSamples.length
                ? 1 -
                prevWeekSamples.reduce((sum, s) => sum + (s.risk ?? 0), 0) / prevWeekSamples.length
                : 0;

        const emotionsCount = new Map();
        for (const s of samples) {
            const key = s.dominantEmotion || s.emotion || "unknown";
            emotionsCount.set(key, (emotionsCount.get(key) || 0) + 1);
        }
        const totalEmotions = Array.from(emotionsCount.values()).reduce((a, b) => a + b, 0);
        const emotionsDistribution = {};
        for (const [k, v] of emotionsCount.entries()) {
            emotionsDistribution[k] = v / totalEmotions;
        }

        return res.json({
            analyzedSessions,
            avgEngagement,
            stressPeaks,
            bestTimeWindow,
            engagementSeries,
            dropsSeries,
            weekCompare: {
                thisWeek,
                prevWeek,
                delta: thisWeek - prevWeek,
            },
            emotionsDistribution,
        });
    } catch (e) {
        console.error("GET /student/me/emotions-summary", e);
        res.status(500).json({ error: "Failed to fetch emotions summary" });
    }
});

export default router;