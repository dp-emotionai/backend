import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";
import { sendUserApprovedEmail } from "../utils/email.js";
import { logAudit } from "../utils/audit.js";

const router = express.Router();

router.use(authMiddleware);
router.use(roleMiddleware(["ADMIN"]));

router.get("/users", async (req, res) => {
    try {
        const users = await prisma.user.findMany({
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                status: true,
                organization: true,
                createdAt: true,
            },
            orderBy: { createdAt: "desc" },
        });
        const order = { PENDING: 0, LIMITED: 1, APPROVED: 2, BLOCKED: 3 }
        users.sort((a,b)=>{
            const sa = order[a.status] ?? 99
            const sb = order[b.status] ?? 99
            if (sa !== sb) return sa - sb
            return b.createdAt - a.createdAt
        })
        res.json(
            users.map((u)=>({
                id: u.id,
                email: u.email,
                name: u.name,
                role: u.role === "ADMIN" ? "admin" : u.role === "TEACHER" ? "teacher" : "student",
                status: u.status,
                organization: u.organization,
                createdAt: u.createdAt,
            }))
        );
    } catch (e) {
        console.error("GET /admin/users", e);
        res.status(500).json({ error: "Failed to list users" });
    }
});

// PUT /api/admin/users/:id/approve — activate / update user (admin only)
router.put("/users/:id/approve", async (req, res) => {
    try {
        const id = req.params.id;
        const { role, status } = req.body || {};

        const user = await prisma.user.findUnique({ where: { id } });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // Маппим строковую роль с фронта в enum Prisma
        let nextRole = user.role;
        if (typeof role === "string") {
            const lower = role.toLowerCase();
            if (lower === "teacher") nextRole = "TEACHER";
            else if (lower === "student") nextRole = "STUDENT";
            else if (lower === "admin") nextRole = "ADMIN";
        }

        // Статус по умолчанию — APPROVED, можно переопределить из тела
        let nextStatus = "APPROVED";
        if (typeof status === "string" && status.trim()) {
            nextStatus = status.trim().toUpperCase();
        }

        const updated = await prisma.user.update({
            where: { id },
            data: {
                status: nextStatus,
                role: nextRole,
            },
        });

        try {
            await sendUserApprovedEmail(updated);
        } catch (e) {
            console.error("EMAIL approve user failed", e);
        }
        try {
            await logAudit(
                req.user.id,
                "user.approved",
                "User",
                updated.id,
                { email: updated.email, role: updated.role, status: updated.status }
            );
        } catch (e) {
            console.error("AUDIT approve user failed", e);
        }
        res.json({
            id: updated.id,
            email: updated.email,
            role: updated.role === "ADMIN" ? "admin" : updated.role === "TEACHER" ? "teacher" : "student",
            status: updated.status,
        });
    } catch (e) {
        console.error("PUT /admin/users/:id/approve", e);
        res.status(500).json({ error: "Failed to approve user" });
    }
});

router.delete("/users/:id", async (req, res) => {
    try {
        const id = req.params.id;
        const user = await prisma.user.findUnique({ where: { id } });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        await prisma.user.delete({ where: { id } });
        res.json({ message: "User deleted" });
    } catch (e) {
        console.error("DELETE /admin/users/:id", e);
        res.status(500).json({ error: "Failed to delete user" });
    }
});

// PUT /api/admin/users/:id/block — block user (admin only)
router.put("/users/:id/block", async (req, res) => {
    try {
        const id = req.params.id;
        const user = await prisma.user.findUnique({ where: { id } });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        const updated = await prisma.user.update({
            where: { id },
            data: { status: "BLOCKED" },
        });
        res.json({
            id: updated.id,
            email: updated.email,
            status: updated.status,
        });
    } catch (e) {
        console.error("PUT /admin/users/:id/block", e);
        res.status(500).json({ error: "Failed to block user" });
    }
});

router.get("/audit", async (req, res) => {
    try {
        const logs = await prisma.auditLog.findMany({
            orderBy: { createdAt: "desc" },
            take: 200,
        });
        res.json(
            logs.map((l) => ({
                id: l.id,
                actorId: l.actorId,
                action: l.action,
                entityType: l.entityType,
                entityId: l.entityId,
                meta: l.meta,
                createdAt: l.createdAt,
            }))
        );
    } catch (e) {
        console.error("GET /admin/audit", e);
        res.status(500).json({ error: "Failed to list audit logs" });
    }
});

export default router;
