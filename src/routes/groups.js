import express from "express";
import prisma from "../utils/prisma.js";
import { logAudit } from "../utils/audit.js";
import { getIO } from "../ws/server.js";

import { authMiddleware, requireRole, getUser } from "./middleware.js";

const router = express.Router();

router.use(authMiddleware);

// GET /groups
router.get("/", async (req, res) => {
    const user = getUser(req);

    try {
        if (user.role === "ADMIN") {
            const groups = await prisma.group.findMany({
                include: {
                    teacher: { select: { email: true, firstName: true, lastName: true } },
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
                    teacherName: [g.teacher.firstName, g.teacher.lastName].filter(Boolean).join(" "),
                    sessionCount: g._count.sessions,
                    createdAt: g.createdAt,
                }))
            );
        }

        if (user.role === "TEACHER") {
            const groups = await prisma.group.findMany({
                where: { teacherId: user.userId },
                include: {
                    teacher: { select: { email: true, firstName: true, lastName: true } },
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
                    teacherName: [g.teacher.firstName, g.teacher.lastName].filter(Boolean).join(" "),
                    sessionCount: g._count.sessions,
                    createdAt: g.createdAt,
                }))
            );
        }

        const memberships = await prisma.groupMember.findMany({
            where: { userId: user.userId },
            include: {
                group: {
                    include: {
                        teacher: { select: { email: true, firstName: true, lastName: true } },
                        _count: { select: { sessions: true } },
                    },
                },
            },
        });

        res.json(
            memberships.map((m) => ({
                id: m.group.id,
                name: m.group.name,
                teacherId: m.group.teacherId,
                teacher: m.group.teacher.email,
                teacherName: [m.group.teacher.firstName, m.group.teacher.lastName].filter(Boolean).join(" "),
                sessionCount: m.group._count.sessions,
                createdAt: m.group.createdAt,
            }))
        );
    } catch (e) {
        console.error("GET /groups", e);
        res.status(500).json({ error: "Failed to list groups" });
    }
});

// GET /groups/:id — details with access check
router.get("/:id", async (req, res) => {
    const user = getUser(req);
    const groupId = req.params.id;

    try {
        const group = await prisma.group.findUnique({
            where: { id: groupId },
            include: {
                teacher: { select: { email: true, firstName: true, lastName: true } },
                _count: { select: { sessions: true } },
            },
        });

        if (!group) {
            return res.status(404).json({ error: "Group not found" });
        }

        const isOwner = group.teacherId === user.userId;
        const isAdmin = user.role === "ADMIN";

        const membership = await prisma.groupMember.findUnique({
            where: { groupId_userId: { groupId, userId: user.userId } },
        });

        const isMember = !!membership;

        if (!isOwner && !isAdmin && !isMember) {
            return res.status(404).json({ error: "Group not found" });
        }

        return res.json({
            id: group.id,
            name: group.name,
            teacherId: group.teacherId,
            teacher: group.teacher.email,
            teacherName: [group.teacher.firstName, group.teacher.lastName].filter(Boolean).join(" "),
            sessionCount: group._count.sessions,
            createdAt: group.createdAt,
        });
    } catch (e) {
        console.error("GET /groups/:id", e);
        res.status(500).json({ error: "Failed to get group" });
    }
});

// GET /groups/:id/members?includeRemoved=true
router.get("/:id/members", async (req, res) => {
    const user = getUser(req);
    const groupId = req.params.id;
    const includeRemoved = String(req.query.includeRemoved || "").toLowerCase() === "true";

    try {
        const group = await prisma.group.findUnique({ where: { id: groupId } });
        if (!group) {
            return res.status(404).json({ error: "Group not found" });
        }

        const isOwner = group.teacherId === user.userId;
        const isAdmin = user.role === "ADMIN";
        const membership = await prisma.groupMember.findUnique({
            where: { groupId_userId: { groupId, userId: user.userId } },
        });
        const isMember = !!membership;

        if (!isOwner && !isAdmin && !isMember) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const members = await prisma.groupMember.findMany({
            where: { groupId },
            include: {
                user: {
                    select: { id: true, firstName: true, lastName: true, email: true, role: true },
                },
            },
        });

        // Сейчас delete делает hard delete, поэтому removed всегда false.
        // Параметр includeRemoved зарезервирован под будущий soft delete.
        const result = members.map((m) => ({
            id: m.user.id,
            name: [m.user.firstName, m.user.lastName].filter(Boolean).join(" "),
            email: m.user.email,
            role: m.user.role,
            removed: false,
        }));

        return res.json(result);
    } catch (e) {
        console.error("GET /groups/:id/members", e);
        res.status(500).json({ error: "Failed to list members" });
    }
});

router.get("/:id/messages", async (req, res) => {
    const user = getUser(req);
    const groupId = req.params.id;
    const cursor = typeof req.query.cursor === "string" ? req.query.cursor.trim() || null : null;
    const tab = (req.query.tab || "chat").toString();
    const take = 50;

    try {
        const group = await prisma.group.findUnique({ where: { id: groupId } });

        if (!group) {
            return res.status(404).json({ error: "Group not found" });
        }

        const isOwner = group.teacherId === user.userId;
        const isAdmin = user.role === "ADMIN";

        const isMember = await prisma.groupMember.findUnique({
            where: { groupId_userId: { groupId, userId: user.userId } },
        });

        if (!isOwner && !isAdmin && !isMember) {
            return res.status(404).json({ error: "Group not found" });
        }

        let typeFilter;
        if (tab === "announcements") typeFilter = ["announcement", "system"];
        else if (tab === "qa") typeFilter = ["question", "answer"];

        const messages = await prisma.groupMessage.findMany({
            where: {
                groupId,
                ...(typeFilter ? { type: { in: typeFilter } } : {}),
            },
            orderBy: [{ createdAt: "desc" }, { id: "desc" }],
            take,
            ...(cursor && { cursor: { id: cursor }, skip: 1 }),
        });

        const list = messages.map((m) => ({
            id: m.id,
            groupId: m.groupId,
            senderId: m.senderId,
            type: m.type,
            text: m.text,
            replyToId: m.replyToId,
            qaStatus: m.qaStatus,
            pinnedAt: m.pinnedAt,
            createdAt: m.createdAt,
            editedAt: m.editedAt,
            deletedAt: m.deletedAt,
        }));

        res.json({
            messages: list.reverse(),
            nextCursor: list.length > 0 ? list[0].id : null,
        });
    } catch (e) {
        console.error("GET /groups/:id/messages", e);
        res.status(500).json({ error: "Failed to load messages" });
    }
});

// POST message
router.post("/:id/messages", async (req, res) => {
    const user = getUser(req);
    const groupId = req.params.id;
    const { type, text, replyToId } = req.body || {};

    if (!type || !text || !String(text).trim()) {
        return res.status(400).json({ error: "type and text required" });
    }

    try {
        const group = await prisma.group.findUnique({ where: { id: groupId } });

        if (!group) {
            return res.status(404).json({ error: "Group not found" });
        }

        const isOwner = group.teacherId === user.userId;
        const isAdmin = user.role === "ADMIN";

        const membership = await prisma.groupMember.findUnique({
            where: { groupId_userId: { groupId, userId: user.userId } },
        });

        const isMember = !!membership;

        if (!isOwner && !isAdmin && !isMember) {
            return res.status(403).json({ error: "Forbidden" });
        }

        if (type === "announcement" && !isOwner && !isAdmin) {
            return res.status(403).json({ error: "Only teacher can post announcements" });
        }

        if (type === "question" && user.role !== "STUDENT") {
            return res.status(403).json({ error: "Only students can create questions" });
        }

        const msg = await prisma.groupMessage.create({
            data: {
                groupId,
                senderId: user.userId,
                type,
                text: String(text).trim(),
                replyToId: replyToId || null,
                qaStatus: type === "question" ? "open" : null,
            },
        });

        const io = getIO();
        io.to(`group:${groupId}`).emit("group:message", {
            id: msg.id,
            groupId: msg.groupId,
            senderId: msg.senderId,
            type: msg.type,
            text: msg.text,
            replyToId: msg.replyToId,
            qaStatus: msg.qaStatus,
            pinnedAt: msg.pinnedAt,
            createdAt: msg.createdAt,
        });

        res.status(201).json(msg);
    } catch (e) {
        console.error("POST /groups/:id/messages", e);
        res.status(500).json({ error: "Failed to create message" });
    }
});

// GET /groups/:id/invitations — list invitations (teacher/admin)
router.get("/:id/invitations", requireRole("TEACHER", "ADMIN"), async (req, res) => {
    const user = getUser(req);
    const id = req.params.id;
    try {
        const group = await prisma.group.findUnique({ where: { id } });
        if (!group) return res.status(404).json({ error: "Group not found" });
        if (user.role !== "ADMIN" && group.teacherId !== user.userId) {
            return res.status(403).json({ error: "Forbidden" });
        }
        const list = await prisma.invitation.findMany({
            where: { groupId: id },
            orderBy: { createdAt: "desc" },
            take: 200,
        });
        res.json(list.map((i) => ({
            id: i.id,
            inviteeEmail: i.inviteeEmail,
            inviteeUserId: i.inviteeUserId,
            status: i.status,
            createdAt: i.createdAt,
        })));
    } catch (e) {
        console.error("GET /groups/:id/invitations", e);
        res.status(500).json({ error: "Failed to list invitations" });
    }
});

// POST /groups/:id/invitations — invite by emails (batch + transaction, no N+1, no race)
router.post("/:id/invitations", requireRole("TEACHER", "ADMIN"), async (req, res) => {
    const user = getUser(req);
    const id = req.params.id;
    const emails = Array.isArray(req.body.emails)
        ? req.body.emails.map((e) => String(e).trim().toLowerCase()).filter(Boolean)
        : [];
    if (emails.length === 0) {
        return res.status(400).json({ error: "emails array required" });
    }
    try {
        const group = await prisma.group.findUnique({ where: { id } });
        if (!group) return res.status(404).json({ error: "Group not found" });
        if (user.role !== "ADMIN" && group.teacherId !== user.userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const users = await prisma.user.findMany({
            where: { email: { in: emails } },
            select: { id: true, email: true },
        });
        const usersMap = new Map(users.map((u) => [u.email, u]));

        const userIds = users.map((u) => u.id);
        const [existingMembers, existingInvitations] = await Promise.all([
            userIds.length > 0
                ? prisma.groupMember.findMany({
                    where: { groupId: id, userId: { in: userIds } },
                    select: { userId: true },
                })
                : [],
            prisma.invitation.findMany({
                where: { groupId: id, inviteeEmail: { in: emails }, status: "pending" },
                select: { inviteeEmail: true },
            }),
        ]);
        const memberUserIdSet = new Set(existingMembers.map((m) => m.userId));
        const invitedEmailSet = new Set(existingInvitations.map((i) => i.inviteeEmail));

        const toCreate = [];
        for (const email of emails) {
            const existingUser = usersMap.get(email);
            if (existingUser && memberUserIdSet.has(existingUser.id)) continue;
            if (invitedEmailSet.has(email)) continue;
            toCreate.push({
                groupId: id,
                inviteeEmail: email,
                inviteeUserId: existingUser?.id ?? null,
                status: "pending",
            });
        }

        const created = await prisma.$transaction(async (tx) => {
            const out = [];
            for (const data of toCreate) {
                try {
                    const inv = await tx.invitation.create({ data });
                    out.push({ email: data.inviteeEmail, userId: data.inviteeUserId ?? undefined, invitationId: inv.id });
                } catch (err) {
                    if (err.code === "P2002") continue;
                    throw err;
                }
            }
            return out;
        });

        await logAudit(user.userId, "invitations_created", "group", id, { count: created.length });
        res.status(201).json({ created });
    } catch (e) {
        console.error("POST /groups/:id/invitations", e);
        res.status(500).json({ error: "Failed to create invitations" });
    }
});

// DELETE member
router.delete("/:id/members/:userId", requireRole("TEACHER", "ADMIN"), async (req, res) => {
    const user = getUser(req);
    const { id: groupId, userId: targetUserId } = req.params;

    try {
        const group = await prisma.group.findUnique({ where: { id: groupId } });

        if (!group) {
            return res.status(404).json({ error: "Group not found" });
        }

        if (user.role !== "ADMIN" && group.teacherId !== user.userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        await prisma.groupMember.delete({
            where: { groupId_userId: { groupId, userId: targetUserId } },
        });

        await logAudit(user.userId, "member_removed", "group", groupId, {
            removedUserId: targetUserId,
        });

        res.json({ ok: true });
    } catch (e) {
        console.error("DELETE member", e);
        res.status(500).json({ error: "Failed to remove member" });
    }
});

// CREATE group
router.post("/", requireRole("TEACHER", "ADMIN"), async (req, res) => {
    const user = getUser(req);
    const { name } = req.body;

    try {
        if (!name || !String(name).trim()) {
            return res.status(400).json({ error: "Name required" });
        }

        const group = await prisma.group.create({
            data: {
                name: String(name).trim(),
                teacherId: user.userId,
            },
        });

        await logAudit(user.userId, "group_created", "group", group.id, {
            name: group.name,
        });

        res.status(201).json(group);
    } catch (e) {
        console.error("POST /groups", e);
        res.status(500).json({ error: "Failed to create group" });
    }
});

// UPDATE group
router.patch("/:id", requireRole("TEACHER", "ADMIN"), async (req, res) => {
    const user = getUser(req);
    const id = req.params.id;

    try {
        const isAdmin = user.role === "ADMIN";

        const existing = await prisma.group.findFirst({
            where: {
                id,
                ...(isAdmin ? {} : { teacherId: user.userId }),
            },
        });

        if (!existing) {
            return res.status(404).json({ error: "Group not found" });
        }

        const { name } = req.body;

        const group = await prisma.group.update({
            where: { id },
            data: name !== undefined ? { name: String(name).trim() } : {},
        });

        res.json(group);
    } catch (e) {
        console.error("PATCH /groups/:id", e);
        res.status(500).json({ error: "Failed to update group" });
    }
});

export default router;