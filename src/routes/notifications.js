import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

const TASK_NOTIFICATION_TYPES = [
    "task_assigned",
];

const getAuthUserId = (req) =>
    req.user?.id || req.user?.userId;

const mapNotification = (notification) => ({
    id: notification.id,
    type: notification.type,
    title: notification.title,
    body: notification.body,
    data: notification.data,
    readAt: notification.readAt,
    createdAt: notification.createdAt,
    isRead: Boolean(notification.readAt),
});

async function getUnreadCounts(userId) {
    const [
        totalUnread,
        taskUnread,
    ] = await prisma.$transaction([
        prisma.notification.count({
            where: {
                userId,
                readAt: null,
            },
        }),
        prisma.notification.count({
            where: {
                userId,
                readAt: null,
                type: {
                    in: TASK_NOTIFICATION_TYPES,
                },
            },
        }),
    ]);

    return {
        totalUnread,
        taskUnread,
    };
}

router.use(authMiddleware);

router.get("/", async (req, res) => {
    try {
        const userId = getAuthUserId(req);

        if (!userId) {
            return res.status(401).json({
                error: "Unauthorized",
            });
        }

        const notifications =
            await prisma.notification.findMany({
                where: {
                    userId,
                },
                orderBy: {
                    createdAt: "desc",
                },
                take: 100,
            });

        return res.json(
            notifications.map(mapNotification)
        );
    } catch (error) {
        console.error(
            "GET /notifications",
            error
        );

        return res.status(500).json({
            error:
                "Failed to get notifications",
        });
    }
});

router.get("/counts", async (req, res) => {
    try {
        const userId = getAuthUserId(req);

        if (!userId) {
            return res.status(401).json({
                error: "Unauthorized",
            });
        }

        const counts =
            await getUnreadCounts(userId);

        return res.json(counts);
    } catch (error) {
        console.error(
            "GET /notifications/counts",
            error
        );

        return res.status(500).json({
            error:
                "Failed to get notification counts",
        });
    }
});

router.patch(
    "/read-all",
    async (req, res) => {
        try {
            const userId =
                getAuthUserId(req);

            if (!userId) {
                return res.status(401).json({
                    error: "Unauthorized",
                });
            }

            const result =
                await prisma.notification.updateMany({
                    where: {
                        userId,
                        readAt: null,
                    },
                    data: {
                        readAt: new Date(),
                    },
                });

            return res.json({
                ok: true,
                updatedCount:
                result.count,
                totalUnread: 0,
                taskUnread: 0,
            });
        } catch (error) {
            console.error(
                "PATCH /notifications/read-all",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to mark all notifications as read",
            });
        }
    }
);

router.patch(
    "/task/:taskId/read",
    async (req, res) => {
        try {
            const userId =
                getAuthUserId(req);

            const taskId =
                String(
                    req.params.taskId ||
                    ""
                ).trim();

            if (!userId) {
                return res.status(401).json({
                    error: "Unauthorized",
                });
            }

            if (!taskId) {
                return res.status(400).json({
                    error:
                        "taskId is required",
                });
            }

            const unreadTaskNotifications =
                await prisma.notification.findMany({
                    where: {
                        userId,
                        readAt: null,
                        type: {
                            in: TASK_NOTIFICATION_TYPES,
                        },
                    },
                    select: {
                        id: true,
                        data: true,
                    },
                });

            const notificationIds =
                unreadTaskNotifications
                    .filter(
                        (notification) =>
                            notification.data &&
                            typeof notification.data ===
                            "object" &&
                            (
                                String(
                                    notification.data
                                        .taskId || ""
                                ) === taskId ||
                                String(
                                    notification.data
                                        .testId || ""
                                ) === taskId
                            )
                    )
                    .map(
                        (notification) =>
                            notification.id
                    );

            const result =
                notificationIds.length > 0
                    ? await prisma.notification.updateMany({
                        where: {
                            id: {
                                in: notificationIds,
                            },
                            userId,
                            readAt: null,
                        },
                        data: {
                            readAt: new Date(),
                        },
                    })
                    : {
                        count: 0,
                    };

            const counts =
                await getUnreadCounts(userId);

            return res.json({
                ok: true,
                updatedCount:
                result.count,
                ...counts,
            });
        } catch (error) {
            console.error(
                "PATCH /notifications/task/:taskId/read",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to mark task notifications as read",
            });
        }
    }
);

router.patch(
    "/:id/read",
    async (req, res) => {
        try {
            const notificationId =
                req.params.id;

            const userId =
                getAuthUserId(req);

            if (!userId) {
                return res.status(401).json({
                    error: "Unauthorized",
                });
            }

            const notification =
                await prisma.notification.findFirst({
                    where: {
                        id: notificationId,
                        userId,
                    },
                });

            if (!notification) {
                return res.status(404).json({
                    error:
                        "Notification not found",
                });
            }

            const updated =
                notification.readAt
                    ? notification
                    : await prisma.notification.update({
                        where: {
                            id: notificationId,
                        },
                        data: {
                            readAt: new Date(),
                        },
                    });

            const counts =
                await getUnreadCounts(userId);

            return res.json({
                notification:
                    mapNotification(updated),
                ...counts,
            });
        } catch (error) {
            console.error(
                "PATCH /notifications/:id/read",
                error
            );

            return res.status(500).json({
                error:
                    "Failed to mark notification as read",
            });
        }
    }
);

export default router;