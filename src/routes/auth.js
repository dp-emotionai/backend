import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import fetch from "node-fetch";
import multer from "multer";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

/** @typedef {{ cookies?: { refreshToken?: string } }} RequestWithCookies */
/** @typedef {{ country_name?: string; city?: string }} IpApiResponse */

const router = express.Router();

const storage = multer.memoryStorage();

const upload = multer({
    storage,
    limits: {
        fileSize: 2 * 1024 * 1024,
    },
});

const generateAccessToken = (userId) => {
    return jwt.sign(
        { id: userId },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
    );
};

const generateRefreshToken = (userId) => {
    return jwt.sign(
        { id: userId },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: "7d" }
    );
};

const ipLocationCache = new Map();

const formatDate = (date) => {
    const d = new Date(date);
    const day = String(d.getDate()).padStart(2, "0");
    const month = String(d.getMonth() + 1).padStart(2, "0");
    const year = d.getFullYear();
    return `${day}.${month}.${year}`;
};

const cleanupExpiredTokens = async () => {
    await prisma.refreshToken.deleteMany({
        where: {
            expiresAt: { lt: new Date() },
        },
    });
};

const enforceMaxDevices = async (userId, limit = 3) => {
    const tokensToRemove = await prisma.refreshToken.findMany({
        where: { userId },
        orderBy: { lastUsedAt: "desc" },
        skip: limit,
        select: { id: true },
    });

    if (tokensToRemove.length > 0) {
        await prisma.refreshToken.deleteMany({
            where: { id: { in: tokensToRemove.map((t) => t.id) } },
        });
    }
};

const getLocationFromIP = async (req) => {
    const ip =
        req.headers["x-forwarded-for"]?.split(",")[0] ||
        req.ip;

    if (!ip) {
        return "Unknown";
    }

    const cached = ipLocationCache.get(ip);
    if (cached && cached.expiresAt > Date.now()) {
        return cached.location;
    }

    try {
        const geo = await fetch(`https://ipapi.co/${ip}/json/`);
        /** @type {IpApiResponse} */
        const geoData = await geo.json();

        const location = `${geoData?.country_name ?? "Unknown"}, ${geoData?.city ?? ""}`;

        ipLocationCache.set(ip, {
            location,
            expiresAt: Date.now() + 24 * 60 * 60 * 1000,
        });

        return location;
    } catch {
        return "Unknown";
    }
};

router.post("/register", async (req, res) => {
    try {
        const { email, password, name, role } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({
                message: "Email, password and name are required",
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                message: "Password must be at least 6 characters",
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const existingUser = await prisma.user.findUnique({
            where: { email: normalizedEmail },
        });

        if (existingUser) {
            return res.status(400).json({
                message: "User already exists",
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const allowedRoles = ["STUDENT", "TEACHER"];
        const userRole = allowedRoles.includes(role)
            ? role
            : "STUDENT";

        const user = await prisma.user.create({
            data: {
                email: normalizedEmail,
                password: hashedPassword,
                name: name.trim(),
                role: userRole,
            },
        });

        return res.status(201).json({
            message: "User created",
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                createdAt: user.createdAt,
            },
        });
    } catch (error) {
        console.error("REGISTER ERROR:", error);
        return res.status(500).json({
            message: "Something went wrong",
        });
    }
});

router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password)
            return res.status(400).json({
                message: "Email and password required",
            });

        const user = await prisma.user.findUnique({
            where: { email: email.trim().toLowerCase() },
        });

        if (!user)
            return res.status(400).json({
                message: "User not found",
            });

        const validPassword = await bcrypt.compare(
            password,
            user.password
        );

        if (!validPassword)
            return res.status(400).json({
                message: "Wrong password",
            });

        const accessToken = generateAccessToken(user.id);
        const refreshToken = generateRefreshToken(user.id);

        const device = req.headers["user-agent"] ?? "unknown";
        const location = await getLocationFromIP(req);

        const existingSession = await prisma.refreshToken.findFirst({
            where: {
                userId: user.id,
                device,
                location,
            },
        });

        const isNewDevice = !existingSession;

        await prisma.refreshToken.create({
            data: {
                token: refreshToken,
                userId: user.id,
                device,
                location,
                userAgent: device,
                lastUsedAt: new Date(),
                expiresAt: new Date(
                    Date.now() + 7 * 24 * 60 * 60 * 1000
                ),
            },
        });

        await enforceMaxDevices(user.id);
        await cleanupExpiredTokens();

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.json({
            accessToken,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                createdAt: user.createdAt,
            },
            device,
            location,
            isNewDevice,
        });
    } catch {
        res.status(500).json({ message: "Server error" });
    }
});
/** @param {import("express").Request & RequestWithCookies} req */
router.post("/refresh", async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken;

        if (!refreshToken)
            return res.status(401).json({
                message: "No refresh token",
            });

        const storedToken = await prisma.refreshToken.findUnique({
            where: { token: refreshToken },
        });

        if (!storedToken)
            return res.status(401).json({
                message: "Invalid refresh token",
            });

        if (storedToken.expiresAt < new Date()) {
            await prisma.refreshToken.delete({
                where: { token: refreshToken },
            });
            return res.status(401).json({
                message: "Refresh token expired",
            });
        }

        const decoded = jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET
        );

        await prisma.refreshToken.delete({
            where: { token: refreshToken },
        });

        const newRefreshToken = generateRefreshToken(decoded.id);
        const newAccessToken = generateAccessToken(decoded.id);
        const device = req.headers["user-agent"] ?? "unknown";
        const location = await getLocationFromIP(req);

        await prisma.refreshToken.create({
            data: {
                token: newRefreshToken,
                userId: decoded.id,
                device,
                location,
                userAgent: device,
                lastUsedAt: new Date(),
                expiresAt: new Date(
                    Date.now() + 7 * 24 * 60 * 60 * 1000
                ),
            },
        });

        await enforceMaxDevices(decoded.id);
        await cleanupExpiredTokens();

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.json({ accessToken: newAccessToken });
    } catch {
        res.status(401).json({ message: "Invalid refresh token" });
    }
});


/** @param {import("express").Request & RequestWithCookies} req */
router.post("/logout", async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken;

        if (refreshToken) {
            await prisma.refreshToken.deleteMany({
                where: { token: refreshToken },
            });
        }

        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
        });

        res.json({ message: "Logged out successfully" });
    } catch {
        res.status(500).json({ message: "Logout failed" });
    }
});

router.get("/me", authMiddleware, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user.id },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                createdAt: true,
            },
        });

        if (!user) {
            return res.status(404).json({
                message: "User not found",
            });
        }

        res.json(user);
    } catch (error) {
        console.error("ME ERROR:", error);
        res.status(500).json({
            message: "Server error",
        });
    }
});

router.put("/me", authMiddleware, async (req, res) => {
    try {
        const { name } = req.body;

        if (!name || name.trim().length < 2) {
            return res.status(400).json({
                message: "Valid name is required",
            });
        }

        const updatedUser = await prisma.user.update({
            where: { id: req.user.id },
            data: { name: name.trim() },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                createdAt: true,
            },
        });

        res.json(updatedUser);
    } catch (error) {
        console.error("UPDATE PROFILE ERROR:", error);
        res.status(500).json({
            message: "Update failed",
        });
    }
});

router.post(
    "/avatar",
    authMiddleware,
    upload.single("avatar"),
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({
                    message: "No file uploaded",
                });
            }

            await prisma.user.update({
                where: { id: req.user.id },
                data: {
                    avatar: req.file.buffer,
                },
            });

            res.json({
                message: "Avatar updated successfully",
            });
        } catch (error) {
            console.error("AVATAR ERROR:", error);
            res.status(500).json({
                message: "Upload failed",
            });
        }
    }
);

router.get("/avatar", authMiddleware, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user.id },
            select: { avatar: true },
        });

        if (!user || !user.avatar) {
            return res.status(404).json({
                message: "No avatar found",
            });
        }

        res.set("Content-Type", "image/jpeg");
        res.send(user.avatar);
    } catch (error) {
        console.error("GET AVATAR ERROR:", error);
        res.status(500).json({
            message: "Error fetching avatar",
        });
    }
});

router.put("/change-password", authMiddleware, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                message: "Current and new password are required",
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                message: "Password must be at least 6 characters",
            });
        }

        const user = await prisma.user.findUnique({
            where: { id: req.user.id },
        });

        if (!user) {
            return res.status(404).json({
                message: "User not found",
            });
        }

        const validPassword = await bcrypt.compare(
            currentPassword,
            user.password
        );

        if (!validPassword) {
            return res.status(400).json({
                message: "Current password is incorrect",
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await prisma.user.update({
            where: { id: req.user.id },
            data: { password: hashedPassword },
        });

        res.json({ message: "Password updated successfully" });
    } catch (error) {
        console.error("CHANGE PASSWORD ERROR:", error);
        res.status(500).json({
            message: "Failed to change password",
        });
    }
});

router.delete("/delete-account", authMiddleware, async (req, res) => {
    try {
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({
                message: "Password is required",
            });
        }

        const user = await prisma.user.findUnique({
            where: { id: req.user.id },
        });

        if (!user) {
            return res.status(404).json({
                message: "User not found",
            });
        }

        const validPassword = await bcrypt.compare(
            password,
            user.password
        );

        if (!validPassword) {
            return res.status(400).json({
                message: "Incorrect password",
            });
        }

        await prisma.user.delete({
            where: { id: req.user.id },
        });

        res.json({ message: "Account deleted successfully" });
    } catch (error) {
        console.error("DELETE ACCOUNT ERROR:", error);
        res.status(500).json({
            message: "Failed to delete account",
        });
    }
});

router.put("/change-email", authMiddleware, async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                message: "Email is required",
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        const existingUser = await prisma.user.findUnique({
            where: { email: normalizedEmail },
        });

        if (existingUser) {
            return res.status(400).json({
                message: "Email already in use",
            });
        }

        const updatedUser = await prisma.user.update({
            where: { id: req.user.id },
            data: { email: normalizedEmail },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
            },
        });

        res.json(updatedUser);
    } catch (error) {
        console.error("CHANGE EMAIL ERROR:", error);
        res.status(500).json({
            message: "Failed to change email",
        });
    }
});
router.post("/logout-all", authMiddleware, async (req, res) => {
    try {
        await prisma.refreshToken.deleteMany({
            where: { userId: req.user.id },
        });

        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
        });

        res.json({ message: "Logged out from all devices" });

    } catch (error) {
        res.status(500).json({
            message: "Failed to logout from all devices",
        });
    }
});
router.get("/sessions", authMiddleware, async (req, res) => {
    try {
        await cleanupExpiredTokens();

        const sessions = await prisma.refreshToken.findMany({
            where: { userId: req.user.id },
            select: {
                id: true,
                device: true,
                location: true,
                createdAt: true,
                lastUsedAt: true,
                expiresAt: true,
            },
            orderBy: {
                createdAt: "desc",
            },
        });

        const now = Date.now();

        const formatted = sessions.map((session) => {
            const lastUsedTime = new Date(session.lastUsedAt).getTime();
            const isOnline =
                lastUsedTime > now - 5 * 60 * 1000;

            return {
                ...session,
                createdAtFormatted: formatDate(session.createdAt),
                lastUsedAtFormatted: formatDate(session.lastUsedAt),
                expiresAtFormatted: formatDate(session.expiresAt),
                isOnline,
            };
        });

        res.json({ sessions: formatted });

    } catch (error) {
        res.status(500).json({
            message: "Failed to fetch sessions",
        });
    }
});
router.delete("/sessions/:id", authMiddleware, async (req, res) => {
    try {
        const sessionId = parseInt(req.params.id);

        const result = await prisma.refreshToken.deleteMany({
            where: {
                id: sessionId,
                userId: req.user.id,
            },
        });

        if (result.count === 0) {
            return res.status(404).json({
                message: "Session not found",
            });
        }

        res.json({ message: "Session terminated" });

    } catch (error) {
        res.status(500).json({
            message: "Failed to terminate session",
        });
    }
});
export default router;