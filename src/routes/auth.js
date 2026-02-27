import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

/* ================================
   MULTER CONFIG (avatar in memory)
================================ */

const storage = multer.memoryStorage();

const upload = multer({
    storage,
    limits: {
        fileSize: 2 * 1024 * 1024,
    },
});

/* ================================
   TOKEN HELPERS (ADDED)
================================ */

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

/* ================================
   REGISTER (НЕ ТРОГАЛ)
================================ */

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

/* ================================
   LOGIN (UPDATED WITH REFRESH)
================================ */

router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password required",
            });
        }

        const user = await prisma.user.findUnique({
            where: { email: email.trim().toLowerCase() },
        });

        if (!user) {
            return res.status(400).json({
                message: "User not found",
            });
        }

        const validPassword = await bcrypt.compare(
            password,
            user.password
        );

        if (!validPassword) {
            return res.status(400).json({
                message: "Wrong password",
            });
        }

        const accessToken = generateAccessToken(user.id);
        const refreshToken = generateRefreshToken(user.id);

        // 🔥 Сохраняем refresh в httpOnly cookie
        res
            .cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: true,        // true в production
                sameSite: "strict",
                maxAge: 7 * 24 * 60 * 60 * 1000,
            })
            .json({
                accessToken,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    createdAt: user.createdAt,
                },
            });

    } catch (error) {
        console.error("LOGIN ERROR:", error);
        res.status(500).json({
            message: "Server error",
        });
    }
});
/* ================================
   REFRESH TOKEN (ADDED)
================================ */

router.post("/refresh", async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(401).json({
                message: "No refresh token",
            });
        }

        const decoded = jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET
        );

        const newAccessToken = generateAccessToken(decoded.id);

        res.json({
            accessToken: newAccessToken,
        });

    } catch (error) {
        return res.status(401).json({
            message: "Invalid refresh token",
        });
    }
});

/* ================================
   LOGOUT (ADDED)
================================ */

router.post("/logout", (req, res) => {
    res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
    });

    res.json({ message: "Logged out successfully" });
});

/* ================================
   GET CURRENT USER (НЕ ТРОГАЛ)
================================ */

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

/* ================================
   UPDATE PROFILE (НЕ ТРОГАЛ)
================================ */

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

/* ================================
   UPLOAD AVATAR (НЕ ТРОГАЛ)
================================ */

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

/* ================================
   GET AVATAR (НЕ ТРОГАЛ)
================================ */

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

/* ================================
   CHANGE PASSWORD (НЕ ТРОГАЛ)
================================ */

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

/* ================================
   DELETE ACCOUNT (НЕ ТРОГАЛ)
================================ */

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

/* ================================
   CHANGE EMAIL (НЕ ТРОГАЛ)
================================ */

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

export default router;