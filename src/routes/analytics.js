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


function pct(value, digits = 0) {
    const n = Number(value) || 0;
    const clamped = Math.max(0, Math.min(100, n));
    return Number(clamped.toFixed(digits));
}

function safeDivide(a, b) {
    return b ? a / b : 0;
}

function formatDate(value) {
    if (!value) return "—";
    return new Date(value).toISOString().slice(0, 10);
}

async function buildGroupAnalyticsPayload(groupId, group) {
    const [members, sessions, materialAssignments, tasks, tests] = await Promise.all([
        prisma.groupMember.findMany({
            where: { groupId, status: "active", removedAt: null },
            include: { user: { select: { id: true, firstName: true, lastName: true, email: true } } },
            orderBy: { addedAt: "asc" },
        }),
        prisma.session.findMany({
            where: { groupId },
            include: { summary: true, participantStates: true },
            orderBy: { createdAt: "asc" },
        }),
        prisma.materialAssignment.findMany({
            where: { groupId },
            include: { material: { select: { kind: true, mimeType: true } } },
            orderBy: { createdAt: "asc" },
        }),
        prisma.task.findMany({
            where: { groupId, status: { not: "archived" } },
            include: { submissions: true },
            orderBy: { createdAt: "asc" },
        }),
        prisma.test.findMany({
            where: { groupId, status: { not: "draft" } },
            include: { submissions: true },
            orderBy: { createdAt: "asc" },
        }),
    ]);

    const memberCount = members.length;
    const sessionsWithSummary = sessions.filter((s) => s.summary);
    const avgEngagement = sessionsWithSummary.length
        ? sessionsWithSummary.reduce((a, s) => a + (s.summary?.avgEngagement ?? 0), 0) / sessionsWithSummary.length
        : 0;

    const attendanceRows = sessions.map((s, index) => {
        const joined = new Set(
            s.participantStates
                .filter((p) => p.joinedAt || p.status === "joined" || p.status === "online")
                .map((p) => p.userId)
        ).size;
        return {
            sessionId: s.id,
            title: s.title,
            label: s.title || `Session ${index + 1}`,
            date: formatDate(s.startedAt ?? s.createdAt),
            joined,
            total: memberCount,
            rate: pct(safeDivide(joined, memberCount) * 100),
        };
    });

    const avgAttendance = attendanceRows.length
        ? pct(attendanceRows.reduce((a, r) => a + r.rate, 0) / attendanceRows.length)
        : 0;

    const taskSubmissions = tasks.flatMap((t) => t.submissions);
    const taskCompletionRate = pct(safeDivide(taskSubmissions.length, tasks.length * Math.max(memberCount, 1)) * 100);

    const gradedTaskScores = taskSubmissions
        .filter((s) => typeof s.score === "number")
        .map((s) => Number(s.score));

    const testSubmissions = tests.flatMap((t) => t.submissions);
    const testPercents = testSubmissions
        .filter((s) => typeof s.score === "number" && typeof s.maxScore === "number" && Number(s.maxScore) > 0)
        .map((s) => (Number(s.score) / Number(s.maxScore)) * 100);

    const averageScore = pct(
        testPercents.length
            ? testPercents.reduce((a, v) => a + v, 0) / testPercents.length
            : gradedTaskScores.length
                ? gradedTaskScores.reduce((a, v) => a + v, 0) / gradedTaskScores.length
                : 0
    );

    const materialKindMap = new Map();
    for (const assignment of materialAssignments) {
        const mime = assignment.material?.mimeType || "";
        const kind = assignment.material?.kind || "file";
        let label = "Файл";
        if (kind === "video" || mime.startsWith("video/")) label = "Видео";
        else if (kind === "image" || mime.startsWith("image/")) label = "Сурет";
        else if (mime.includes("pdf")) label = "PDF";
        else if (mime.includes("presentation") || mime.includes("powerpoint")) label = "Презентация";
        materialKindMap.set(label, (materialKindMap.get(label) || 0) + 1);
    }

    const materialBreakdown = Array.from(materialKindMap.entries()).map(([kind, count]) => ({ kind, count }));

    const studentStats = members.map((member) => {
        const userId = member.userId;
        const attended = attendanceRows.filter((r) => {
            const session = sessions.find((s) => s.id === r.sessionId);
            return session?.participantStates.some((p) => p.userId === userId && (p.joinedAt || p.status === "joined" || p.status === "online"));
        }).length;
        const submittedTasks = taskSubmissions.filter((s) => s.studentId === userId).length;
        const ownTestPercents = testSubmissions
            .filter((s) => s.studentId === userId && typeof s.score === "number" && typeof s.maxScore === "number" && Number(s.maxScore) > 0)
            .map((s) => (Number(s.score) / Number(s.maxScore)) * 100);
        const score = ownTestPercents.length
            ? ownTestPercents.reduce((a, v) => a + v, 0) / ownTestPercents.length
            : 0;
        return {
            userId,
            fullName: `${member.user.firstName || ""} ${member.user.lastName || ""}`.trim() || member.user.email,
            email: member.user.email,
            attendanceRate: pct(safeDivide(attended, sessions.length) * 100),
            taskCompletionRate: pct(safeDivide(submittedTasks, tasks.length) * 100),
            averageScore: pct(score),
        };
    });

    const topStudents = [...studentStats]
        .sort((a, b) => (b.averageScore + b.attendanceRate + b.taskCompletionRate) - (a.averageScore + a.attendanceRate + a.taskCompletionRate))
        .slice(0, 8);

    return {
        groupId,
        groupName: group.name,
        totalSessions: sessions.length,
        studentCount: memberCount,
        materialCount: materialAssignments.length,
        taskCount: tasks.length,
        testCount: tests.length,
        averageEngagement: pct(avgEngagement * 100),
        averageAttendance: avgAttendance,
        taskCompletionRate,
        averageScore,
        engagementTrend: sessionsWithSummary.slice(-10).map((s, index) => ({
            sessionId: s.id,
            label: s.title || `Session ${index + 1}`,
            date: formatDate(s.startedAt ?? s.createdAt),
            engagement: pct((s.summary?.avgEngagement ?? 0) * 100),
        })),
        attendanceTrend: attendanceRows.slice(-10),
        materialBreakdown,
        assignmentStatus: [
            { status: "Орындалды", count: taskSubmissions.length },
            { status: "Орындалмады", count: Math.max(tasks.length * memberCount - taskSubmissions.length, 0) },
        ],
        topStudents,
        students: studentStats,
    };
}

function drawBar(doc, label, value, x, y, width, height) {
    const clamped = Math.max(0, Math.min(100, Number(value) || 0));
    doc.fontSize(9).fillColor("#334155").text(label, x, y - 2, { width: 160 });
    doc.roundedRect(x + 165, y, width, height, 5).fill("#e2e8f0");
    doc.roundedRect(x + 165, y, (width * clamped) / 100, height, 5).fill("#2563eb");
    doc.fillColor("#0f172a").fontSize(9).text(`${clamped}%`, x + 170 + width, y - 1, { width: 45, align: "right" });
}

function drawKpi(doc, label, value, x, y, w) {
    doc.roundedRect(x, y, w, 58, 14).fill("#f8fafc").strokeColor("#e2e8f0").stroke();
    doc.fillColor("#64748b").fontSize(8).text(label, x + 14, y + 12, { width: w - 28 });
    doc.fillColor("#0f172a").fontSize(18).text(String(value), x + 14, y + 28, { width: w - 28 });
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
        const format = (req.query.format || "pdf").toLowerCase();
        const userId = req.user.id;
        const role = req.user.role;
        const access = await ensureGroupAccess(groupId, userId, role);
        if (!access.ok) {
            return res.status(access.status).json({ error: access.error });
        }

        const payload = await buildGroupAnalyticsPayload(groupId, access.group);

        if (format === "json") {
            res.setHeader("Content-Type", "application/json");
            res.setHeader("Content-Disposition", `attachment; filename="group-${groupId}-analytics.json"`);
            return res.json(payload);
        }
        if (format === "csv") {
            res.setHeader("Content-Type", "text/csv; charset=utf-8");
            res.setHeader("Content-Disposition", `attachment; filename="group-${groupId}-analytics.csv"`);
            res.flushHeaders();
            res.write("metric,value\n");
            res.write(`groupName,"${String(payload.groupName).replace(/"/g, '""')}"\n`);
            res.write(`students,${payload.studentCount}\n`);
            res.write(`sessions,${payload.totalSessions}\n`);
            res.write(`materials,${payload.materialCount}\n`);
            res.write(`tasks,${payload.taskCount}\n`);
            res.write(`tests,${payload.testCount}\n`);
            res.write(`averageEngagement,${payload.averageEngagement}\n`);
            res.write(`averageAttendance,${payload.averageAttendance}\n`);
            res.write(`taskCompletionRate,${payload.taskCompletionRate}\n`);
            res.write(`averageScore,${payload.averageScore}\n\n`);
            res.write("student,email,attendanceRate,taskCompletionRate,averageScore\n");
            for (const st of payload.students) {
                res.write(`"${String(st.fullName).replace(/"/g, '""')}","${String(st.email).replace(/"/g, '""')}",${st.attendanceRate},${st.taskCompletionRate},${st.averageScore}\n`);
            }
            return res.end();
        }
        if (format === "pdf") {
            res.setHeader("Content-Type", "application/pdf");
            res.setHeader("Content-Disposition", `attachment; filename="group-${groupId}-analytics.pdf"`);
            const doc = new PDFDocument({ margin: 42, size: "A4" });
            doc.pipe(res);

            doc.rect(0, 0, doc.page.width, 96).fill("#0f172a");
            doc.fillColor("#ffffff").fontSize(22).text("Group analytics report", 42, 30);
            doc.fillColor("#cbd5e1").fontSize(11).text(`${payload.groupName} • ${new Date().toISOString().slice(0, 10)}`, 42, 60);

            let y = 126;
            const w = 158;
            drawKpi(doc, "Students", payload.studentCount, 42, y, w);
            drawKpi(doc, "Sessions", payload.totalSessions, 215, y, w);
            drawKpi(doc, "Materials", payload.materialCount, 388, y, w);
            y += 78;
            drawKpi(doc, "Avg engagement", `${payload.averageEngagement}%`, 42, y, w);
            drawKpi(doc, "Attendance", `${payload.averageAttendance}%`, 215, y, w);
            drawKpi(doc, "Task completion", `${payload.taskCompletionRate}%`, 388, y, w);

            y += 92;
            doc.fillColor("#0f172a").fontSize(15).text("Progress charts", 42, y);
            y += 28;
            drawBar(doc, "Engagement", payload.averageEngagement, 42, y, 260, 12); y += 25;
            drawBar(doc, "Attendance", payload.averageAttendance, 42, y, 260, 12); y += 25;
            drawBar(doc, "Task completion", payload.taskCompletionRate, 42, y, 260, 12); y += 25;
            drawBar(doc, "Average score", payload.averageScore, 42, y, 260, 12);

            y += 50;
            doc.fillColor("#0f172a").fontSize(15).text("Recent sessions", 42, y);
            y += 24;
            doc.fillColor("#64748b").fontSize(9).text("Session", 42, y).text("Engagement", 330, y).text("Attendance", 430, y);
            y += 14;
            const attendanceBySessionId = new Map(payload.attendanceTrend.map((r) => [r.sessionId, r]));
            for (const item of payload.engagementTrend.slice(-8)) {
                if (y > 730) { doc.addPage(); y = 48; }
                const attendance = attendanceBySessionId.get(item.sessionId);
                doc.fillColor("#0f172a").fontSize(9).text(`${item.date} ${item.label}`, 42, y, { width: 260 });
                doc.text(`${item.engagement}%`, 330, y, { width: 70 });
                doc.text(`${attendance?.rate ?? 0}%`, 430, y, { width: 70 });
                y += 18;
            }

            doc.addPage();
            y = 48;
            doc.fillColor("#0f172a").fontSize(18).text("Student summary", 42, y);
            y += 32;
            doc.fillColor("#64748b").fontSize(9).text("Student", 42, y).text("Attendance", 285, y).text("Tasks", 370, y).text("Score", 455, y);
            y += 16;
            for (const st of payload.students) {
                if (y > 760) { doc.addPage(); y = 48; }
                doc.fillColor("#0f172a").fontSize(9).text(st.fullName, 42, y, { width: 220 });
                doc.fillColor("#475569").text(`${st.attendanceRate}%`, 285, y, { width: 70 });
                doc.text(`${st.taskCompletionRate}%`, 370, y, { width: 70 });
                doc.text(`${st.averageScore}%`, 455, y, { width: 70 });
                y += 18;
            }

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

        const payload = await buildGroupAnalyticsPayload(groupId, access.group);
        return res.json(payload);
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