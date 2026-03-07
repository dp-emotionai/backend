import express from "express";
import prisma from "../utils/prisma.js";
import {logAudit} from "../utils/audit.js";
import { authMiddleware, requireRole, getUser } from "./middleware.js";

const router = express.Router();

// GET / — для студента: свои pending приглашения
router.get("/", authMiddleware, requireRole("STUDENT"), async (req, res) => {
    const user = getUser(req);
    try {
        const list = await prisma.invitation.findMany({
            where: {
                OR: [{ inviteeUserId: user.userId }, { inviteeEmail: user.email ?? "" }],
                status: "pending",
            },
            include: { group: { select: { id: true, name: true } } },
            orderBy: { createdAt: "desc" },
        });
        res.json(
            list.map((i) => ({
                id: i.id,
                groupId: i.groupId,
                groupName: i.group.name,
                inviteeEmail: i.inviteeEmail,
                status: i.status,
                createdAt: i.createdAt,
            }))
        );
    } catch (e) {
        console.error("GET /invitations", e);
        res.status(500).json({ error: "Failed to list invitations" });
    }
});

router.post("/:id/accept", authMiddleware, requireRole("STUDENT"), async (req, res) => {
    const user = getUser(req);
    try {
        const id = req.params.id;
        const inv = await prisma.invitation.findFirst({
            where: { id, status: "pending" },
            select: { id: true, groupId: true, inviteeEmail: true, inviteeUserId: true, group: { select: { id: true, name: true } } },
        });
        if (!inv) {
            res.status(404).json({ error: "Invitation not found or already used" });
            return;
        }
        const isForMe =
            inv.inviteeUserId === user.userId ||
            inv.inviteeEmail.toLowerCase() === (user.email ?? "").toLowerCase();
        if (!isForMe) {
            res.status(403).json({ error: "This invitation is not for you" });
            return;
        }
        await prisma.$transaction([
            prisma.groupMember.upsert({
                where: { groupId_userId: { groupId: inv.groupId, userId: user.userId } },
                create: { groupId: inv.groupId, userId: user.userId, role: "student" },
                update: {},
            }),
            prisma.invitation.update({
                where: { id },
                data: { status: "accepted", inviteeUserId: user.userId },
            }),
        ]);
        await logAudit(user.userId, "invitation_accepted", "invitation", id, JSON.stringify({ groupId: inv.groupId }));
        res.json({ ok: true, groupId: inv.groupId, groupName: inv.group.name });
    } catch (e) {
        console.error("POST /invitations/:id/accept", e);
        res.status(500).json({ error: "Failed to accept invitation" });
    }
});

router.post("/:id/decline", authMiddleware, requireRole("STUDENT"), async (req, res) => {
    const user = getUser(req);
    try {
        const id = req.params.id;
        const inv = await prisma.invitation.findFirst({
            where: { id, status: "pending" },
        });
        if (!inv) {
            res.status(404).json({ error: "Invitation not found or already used" });
            return;
        }
        const isForMe =
            inv.inviteeUserId === user.userId ||
            inv.inviteeEmail.toLowerCase() === (user.email ?? "").toLowerCase();
        if (!isForMe) {
            res.status(403).json({ error: "This invitation is not for you" });
            return;
        }
        await prisma.invitation.update({
            where: { id },
            data: { status: "declined", inviteeUserId: user.userId },
        });
        res.json({ ok: true });
    } catch (e) {
        console.error("POST /invitations/:id/decline", e);
        res.status(500).json({ error: "Failed to decline invitation" });
    }
});

router.post("/:id/revoke", authMiddleware, requireRole("TEACHER", "ADMIN"), async (req, res) => {
    const user = getUser(req);
    try {
        const id = req.params.id;
        const inv = await prisma.invitation.findUnique({
            where: { id },
            select: { id: true, groupId: true, status: true, group: { select: { teacherId: true } } },
        });
        if (!inv) {
            res.status(404).json({ error: "Invitation not found" });
            return;
        }
        if (inv.status !== "pending") {
            res.status(400).json({ error: "Only pending invitations can be revoked" });
            return;
        }
        const isAdmin = user.role === "ADMIN";
        if (!isAdmin && inv.group.teacherId !== user.userId) {
            res.status(403).json({ error: "Forbidden" });
            return;
        }
        await prisma.invitation.update({ where: { id }, data: { status: "revoked" } });
        await logAudit(user.userId, "invitation_revoked", "invitation", id, JSON.stringify({ groupId: inv.groupId }));
        res.json({ ok: true });
    } catch (e) {
        console.error("POST /invitations/:id/revoke", e);
        res.status(500).json({ error: "Failed to revoke invitation" });
    }
});

export default router;
