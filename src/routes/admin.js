import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";
import { sendUserApprovedEmail } from "../utils/email.js";
import { logAudit } from "../utils/audit.js";

const router = express.Router();

router.use(authMiddleware);
router.use(roleMiddleware(["ADMIN"]));

// GET /api/admin/users — list all users (admin only)
router.get("/users", async (req, res) => {
    try {
        const users = await prisma.user.findMany({
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                status: true,
                createdAt: true,
                updatedAt: true,
            },
            orderBy: { createdAt: "desc" },
        });
        res.json(users);
    } catch (e) {
        console.error("GET /admin/users", e);
        res.status(500).json({ error: "Failed to list users" });
    }
});

// PUT /api/admin/users/:id/approve — activate pending user (admin only)
router.put("/users/:id/approve", async (req, res) => {
    try {
        const id = req.params.id;
        const user = await prisma.user.findUnique({ where: { id } });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        const updated = await prisma.user.update({
            where: { id },
            data: { status: "active" },
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
                { email: updated.email }
            );
        } catch (e) {
            console.error("AUDIT approve user failed", e);
        }
        res.json({
            id: updated.id,
            email: updated.email,
            status: updated.status,
        });
    } catch (e) {
        console.error("PUT /admin/users/:id/approve", e);
        res.status(500).json({ error: "Failed to approve user" });
    }
});

// DELETE /api/admin/users/:id — delete user (admin only)
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
            data: { status: "blocked" },
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

// GET /api/admin/audit — audit log (admin only)
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
