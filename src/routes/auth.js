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
        fileSize: 2 * 1024 * 1024, // 2MB max
    },
});

/* ================================
   REGISTER
================================ */

router.post("/register", async (req, res) => {
    try {
        const { email, password, name, role } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({
                message: "Email, password and name are required",
            });
        }

        const existingUser = await prisma.user.findUnique({
            where: { email },
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
                email,
                password: hashedPassword,
                name,
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
   LOGIN
================================ */

router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await prisma.user.findUnique({
            where: { email },
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

        const token = jwt.sign(
            { id: user.id },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            token,
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
   GET CURRENT USER
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
   UPDATE PROFILE (NAME)
================================ */

router.put("/me", authMiddleware, async (req, res) => {
    try {
        const { name } = req.body;

        if (!name) {
            return res.status(400).json({
                message: "Name is required",
            });
        }

        const updatedUser = await prisma.user.update({
            where: { id: req.user.id },
            data: { name },
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
   UPLOAD AVATAR
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
            console.error("AVATAR UPLOAD ERROR:", error);
            res.status(500).json({
                message: "Upload failed",
            });
        }
    }
);

/* ================================
   GET AVATAR
================================ */

router.get("/avatar", authMiddleware, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user.id },
            select: { avatar: true },
        });

        if (!user?.avatar) {
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
   CHANGE PASSWORD
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
   DELETE ACCOUNT
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

export default router;