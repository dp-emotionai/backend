import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();
const MIN_QUERY_LENGTH = 2;
const DEFAULT_LIMIT = 10;
const MAX_LIMIT = 20;

router.get("/", authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
        const typesRaw = req.query.types;
        const types = Array.isArray(typesRaw)
            ? typesRaw
            : typeof typesRaw === "string"
                ? typesRaw.split(",").map((t) => t.trim())
                : ["sessions", "groups"];
        const limit = Math.min(
            MAX_LIMIT,
            typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) || DEFAULT_LIMIT : DEFAULT_LIMIT
        );

        const includeSessions = types.includes("sessions");
        const includeGroups = types.includes("groups");
        const includeUsers = types.includes("users") && user.role === "ADMIN";

        const results = {
            sessions: [],
            groups: [],
        };
        if (includeUsers) results.users = [];

        if (q.length < MIN_QUERY_LENGTH) {
            return res.json({ q, results });
        }

        if (includeSessions) {
            if (user.role === "ADMIN") {
                const sessions = await prisma.session.findMany({
                    where: { title: { contains: q, mode: "insensitive" } },
                    select: { id: true, title: true, status: true, startedAt: true, group: { select: { name: true } } },
                    take: limit,
                    orderBy: { updatedAt: "desc" },
                });
                results.sessions = sessions.map((s) => ({
                    id: s.id,
                    title: s.title,
                    status: s.status,
                    startAt: s.startedAt?.toISOString(),
                    groupName: s.group.name,
                }));
            } else if (user.role === "TEACHER") {
                const sessions = await prisma.session.findMany({
                    where: { createdById: user.id, title: { contains: q, mode: "insensitive" } },
                    select: { id: true, title: true, status: true, startedAt: true, group: { select: { name: true } } },
                    take: limit,
                    orderBy: { updatedAt: "desc" },
                });
                results.sessions = sessions.map((s) => ({
                    id: s.id,
                    title: s.title,
                    status: s.status,
                    startAt: s.startedAt?.toISOString(),
                    groupName: s.group.name,
                }));
            } else {
                const memberGroups = await prisma.groupMember.findMany({
                    where: { userId: user.id },
                    select: { groupId: true },
                });
                const groupIds = memberGroups.map((m) => m.groupId);
                const sessions = await prisma.session.findMany({
                    where: {
                        groupId: { in: groupIds },
                        title: { contains: q, mode: "insensitive" },
                    },
                    select: { id: true, title: true, status: true, startedAt: true, group: { select: { name: true } } },
                    take: limit,
                    orderBy: { updatedAt: "desc" },
                });
                results.sessions = sessions.map((s) => ({
                    id: s.id,
                    title: s.title,
                    status: s.status,
                    startAt: s.startedAt?.toISOString(),
                    groupName: s.group.name,
                }));
            }
        }

        if (includeGroups) {
            if (user.role === "ADMIN") {
                const groups = await prisma.group.findMany({
                    where: { name: { contains: q, mode: "insensitive" } },
                    include: { _count: { select: { members: true } } },
                    take: limit,
                    orderBy: { updatedAt: "desc" },
                });
                results.groups = groups.map((g) => ({
                    id: g.id,
                    name: g.name,
                    membersCount: g._count.members,
                }));
            } else if (user.role === "TEACHER") {
                const groups = await prisma.group.findMany({
                    where: { teacherId: user.id, name: { contains: q, mode: "insensitive" } },
                    include: { _count: { select: { members: true } } },
                    take: limit,
                    orderBy: { updatedAt: "desc" },
                });
                results.groups = groups.map((g) => ({
                    id: g.id,
                    name: g.name,
                    membersCount: g._count.members,
                }));
            } else {
                const memberGroups = await prisma.groupMember.findMany({
                    where: { userId: user.id },
                    select: { groupId: true },
                });
                const groupIds = memberGroups.map((m) => m.groupId);
                const groups = await prisma.group.findMany({
                    where: { id: { in: groupIds }, name: { contains: q, mode: "insensitive" } },
                    include: { _count: { select: { members: true } } },
                    take: limit,
                    orderBy: { updatedAt: "desc" },
                });
                results.groups = groups.map((g) => ({
                    id: g.id,
                    name: g.name,
                    membersCount: g._count.members,
                }));
            }
        }

        if (includeUsers && user.role === "ADMIN") {
            const users = await prisma.user.findMany({
                where: {
                    OR: [
                        { email: { contains: q, mode: "insensitive" } },
                        { name: { contains: q, mode: "insensitive" } },
                    ],
                },
                take: limit,
                orderBy: { updatedAt: "desc" },
                select: { id: true, name: true, email: true, role: true },
            });
            results.users = users.map((u) => ({
                id: u.id,
                name: u.name ?? "",
                email: u.email,
                role: u.role,
            }));
        }

        res.json({ q, results });
    } catch (e) {
        console.error("Search error", e);
        res.status(500).json({ error: "Search failed" });
    }
});

export default router;
