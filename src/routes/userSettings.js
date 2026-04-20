import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

router.use(authMiddleware);

/* ===============================
   NOTIFICATION SETTINGS
================================ */

router.get("/notifications/settings", async (req, res) => {
    try {
        const settings = await prisma.userNotificationSettings.upsert({
            where: { userId: req.user.id },
            update: {},
            create: { userId: req.user.id },
        });

        res.json(settings);
    } catch (e) {
        console.error("GET /user/notifications/settings", e);
        res.status(500).json({ error: "Failed to fetch notification settings" });
    }
});

router.patch("/notifications/settings", async (req, res) => {
    try {
        const {
            emailNotifications,
            pushNotifications,
            dailyDigestEnabled,
            dailyDigestTime,
            quietHoursEnabled,
            quietHoursStart,
            quietHoursEnd,
            scheduleNotifications,
            assignmentNotifications,
            messageNotifications,
            groupNotifications,
            systemNotifications,
            reportNotifications,
        } = req.body || {};

        const data = {};

        if (emailNotifications !== undefined) data.emailNotifications = !!emailNotifications;
        if (pushNotifications !== undefined) data.pushNotifications = !!pushNotifications;
        if (dailyDigestEnabled !== undefined) data.dailyDigestEnabled = !!dailyDigestEnabled;
        if (dailyDigestTime !== undefined) data.dailyDigestTime = dailyDigestTime ? String(dailyDigestTime).trim() : null;
        if (quietHoursEnabled !== undefined) data.quietHoursEnabled = !!quietHoursEnabled;
        if (quietHoursStart !== undefined) data.quietHoursStart = quietHoursStart ? String(quietHoursStart).trim() : null;
        if (quietHoursEnd !== undefined) data.quietHoursEnd = quietHoursEnd ? String(quietHoursEnd).trim() : null;
        if (scheduleNotifications !== undefined) data.scheduleNotifications = !!scheduleNotifications;
        if (assignmentNotifications !== undefined) data.assignmentNotifications = !!assignmentNotifications;
        if (messageNotifications !== undefined) data.messageNotifications = !!messageNotifications;
        if (groupNotifications !== undefined) data.groupNotifications = !!groupNotifications;
        if (systemNotifications !== undefined) data.systemNotifications = !!systemNotifications;
        if (reportNotifications !== undefined) data.reportNotifications = !!reportNotifications;

        const settings = await prisma.userNotificationSettings.upsert({
            where: { userId: req.user.id },
            update: data,
            create: {
                userId: req.user.id,
                ...data,
            },
        });

        res.json(settings);
    } catch (e) {
        console.error("PATCH /user/notifications/settings", e);
        res.status(500).json({ error: "Failed to update notification settings" });
    }
});

/* ===============================
   USER PREFERENCES
================================ */

router.get("/preferences", async (req, res) => {
    try {
        const preferences = await prisma.userPreference.upsert({
            where: { userId: req.user.id },
            update: {},
            create: { userId: req.user.id },
        });

        res.json(preferences);
    } catch (e) {
        console.error("GET /user/preferences", e);
        res.status(500).json({ error: "Failed to fetch preferences" });
    }
});

router.patch("/preferences", async (req, res) => {
    try {
        const {
            language,
            region,
            timezone,
            preferredDateFormat,
            weekStartsOn,
        } = req.body || {};

        const data = {};

        if (language !== undefined) data.language = language ? String(language).trim() : null;
        if (region !== undefined) data.region = region ? String(region).trim() : null;
        if (timezone !== undefined) data.timezone = timezone ? String(timezone).trim() : null;
        if (preferredDateFormat !== undefined) data.preferredDateFormat = preferredDateFormat ? String(preferredDateFormat).trim() : null;
        if (weekStartsOn !== undefined) data.weekStartsOn = weekStartsOn ? String(weekStartsOn).trim() : null;

        const preferences = await prisma.userPreference.upsert({
            where: { userId: req.user.id },
            update: data,
            create: {
                userId: req.user.id,
                ...data,
            },
        });

        res.json(preferences);
    } catch (e) {
        console.error("PATCH /user/preferences", e);
        res.status(500).json({ error: "Failed to update preferences" });
    }
});

/* ===============================
   USER INTEGRATIONS
================================ */

router.get("/integrations", async (req, res) => {
    try {
        const integrations = await prisma.userIntegration.findMany({
            where: { userId: req.user.id },
            orderBy: { createdAt: "asc" },
        });

        res.json({ integrations });
    } catch (e) {
        console.error("GET /user/integrations", e);
        res.status(500).json({ error: "Failed to fetch integrations" });
    }
});

router.post("/integrations/:provider/connect", async (req, res) => {
    try {
        const provider = String(req.params.provider || "").trim().toLowerCase();
        const { externalAccountId, metadata } = req.body || {};

        if (!provider) {
            return res.status(400).json({ error: "Provider is required" });
        }

        const integration = await prisma.userIntegration.upsert({
            where: {
                userId_provider: {
                    userId: req.user.id,
                    provider,
                },
            },
            update: {
                connected: true,
                connectedAt: new Date(),
                externalAccountId: externalAccountId ? String(externalAccountId).trim() : null,
                metadata: metadata ?? null,
            },
            create: {
                userId: req.user.id,
                provider,
                connected: true,
                connectedAt: new Date(),
                externalAccountId: externalAccountId ? String(externalAccountId).trim() : null,
                metadata: metadata ?? null,
            },
        });

        res.json(integration);
    } catch (e) {
        console.error("POST /user/integrations/:provider/connect", e);
        res.status(500).json({ error: "Failed to connect integration" });
    }
});

router.delete("/integrations/:provider", async (req, res) => {
    try {
        const provider = String(req.params.provider || "").trim().toLowerCase();

        if (!provider) {
            return res.status(400).json({ error: "Provider is required" });
        }

        const integration = await prisma.userIntegration.findUnique({
            where: {
                userId_provider: {
                    userId: req.user.id,
                    provider,
                },
            },
        });

        if (!integration) {
            return res.status(404).json({ error: "Integration not found" });
        }

        await prisma.userIntegration.update({
            where: {
                userId_provider: {
                    userId: req.user.id,
                    provider,
                },
            },
            data: {
                connected: false,
                connectedAt: null,
                externalAccountId: null,
                metadata: null,
            },
        });

        res.json({ ok: true });
    } catch (e) {
        console.error("DELETE /user/integrations/:provider", e);
        res.status(500).json({ error: "Failed to disconnect integration" });
    }
});

export default router;