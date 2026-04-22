import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

router.use(authMiddleware);

router.get("/", async (req, res) => {
    try {
        const userId = req.user.id;

        const notifications = await prisma.notification.findMany({
            where: { userId },
            orderBy: { createdAt: "desc" },
            take: 100,
        });

        return res.json(
            notifications.map(n => ({
                id: n.id,
                type: n.type,
                title: n.title,
                body: n.body,
                data: n.data,
                readAt: n.readAt,
                createdAt: n.createdAt,
                isRead: !!n.readAt,
            }))
        );

    } catch (e) {
        console.error("GET /notifications", e);
        return res.status(500).json({ error: "Failed to get notifications" });
    }
});

router.patch("/:id/read", async (req, res) => {
    try {
        const notificationId = req.params.id;
        const userId = req.user.id;

        const notification = await prisma.notification.findUnique({
            where: { id: notificationId },
        });

        if (!notification) {
            return res.status(404).json({ error: "Notification not found" });
        }

        if (notification.userId !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const updated = await prisma.notification.update({
            where: { id: notificationId },
            data: {
                readAt: new Date(),
            },
        });

        return res.json({
            id: updated.id,
            readAt: updated.readAt,
            isRead: true,
        });

    } catch (e) {
        console.error("PATCH /notifications/:id/read", e);
        return res.status(500).json({ error: "Failed to mark notification as read" });
    }
});

export default router;