import express from "express";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";

const router = express.Router();

router.use(authMiddleware);

router.get("/", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const userId = req.user.id;
        const role = req.user.role;

        const materials = await prisma.material.findMany({
            where: role === "ADMIN" ? {} : { ownerId: userId },
            orderBy: { createdAt: "desc" },
        });

        return res.json(
            materials.map((m) => ({
                id: m.id,
                title: m.title,
                description: m.description,
                fileName: m.fileName,
                mimeType: m.mimeType,
                storageKey: m.storageKey,
                size: m.size,
                ownerId: m.ownerId,
                createdAt: m.createdAt,
                updatedAt: m.updatedAt,
            }))
        );
    } catch (e) {
        console.error("GET /materials", e);
        return res.status(500).json({ error: "Failed to get materials" });
    }
});

router.post("/", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const userId = req.user.id;
        const { title, description, fileName, mimeType, storageKey, size } = req.body || {};

        if (!title || !String(title).trim()) {
            return res.status(400).json({ error: "title is required" });
        }

        if (!fileName || !String(fileName).trim()) {
            return res.status(400).json({ error: "fileName is required" });
        }

        if (!storageKey || !String(storageKey).trim()) {
            return res.status(400).json({ error: "storageKey is required" });
        }

        const material = await prisma.material.create({
            data: {
                title: String(title).trim(),
                description: description === undefined || description === null ? null : String(description).trim(),
                fileName: String(fileName).trim(),
                mimeType: mimeType === undefined || mimeType === null ? null : String(mimeType).trim(),
                storageKey: String(storageKey).trim(),
                size: typeof size === "number" && Number.isFinite(size) ? size : null,
                ownerId: userId,
            },
        });

        return res.status(201).json({
            id: material.id,
            title: material.title,
            description: material.description,
            fileName: material.fileName,
            mimeType: material.mimeType,
            storageKey: material.storageKey,
            size: material.size,
            ownerId: material.ownerId,
            createdAt: material.createdAt,
            updatedAt: material.updatedAt,
        });
    } catch (e) {
        console.error("POST /materials", e);
        return res.status(500).json({ error: "Failed to create material" });
    }
});

router.patch("/:materialId", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const materialId = req.params.materialId;
        const userId = req.user.id;
        const role = req.user.role;
        const { title, description, fileName, mimeType, storageKey, size } = req.body || {};

        const material = await prisma.material.findUnique({
            where: { id: materialId },
        });

        if (!material) {
            return res.status(404).json({ error: "Material not found" });
        }

        if (role !== "ADMIN" && material.ownerId !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const updates = {};

        if (title !== undefined) updates.title = String(title).trim();
        if (description !== undefined) updates.description = description === null ? null : String(description).trim();
        if (fileName !== undefined) updates.fileName = String(fileName).trim();
        if (mimeType !== undefined) updates.mimeType = mimeType === null ? null : String(mimeType).trim();
        if (storageKey !== undefined) updates.storageKey = String(storageKey).trim();
        if (size !== undefined) {
            updates.size = typeof size === "number" && Number.isFinite(size) ? size : null;
        }

        const updated = await prisma.material.update({
            where: { id: materialId },
            data: updates,
        });

        return res.json({
            id: updated.id,
            title: updated.title,
            description: updated.description,
            fileName: updated.fileName,
            mimeType: updated.mimeType,
            storageKey: updated.storageKey,
            size: updated.size,
            ownerId: updated.ownerId,
            createdAt: updated.createdAt,
            updatedAt: updated.updatedAt,
        });
    } catch (e) {
        console.error("PATCH /materials/:materialId", e);
        return res.status(500).json({ error: "Failed to update material" });
    }
});

router.delete("/:materialId", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const materialId = req.params.materialId;
        const userId = req.user.id;
        const role = req.user.role;

        const material = await prisma.material.findUnique({
            where: { id: materialId },
        });

        if (!material) {
            return res.status(404).json({ error: "Material not found" });
        }

        if (role !== "ADMIN" && material.ownerId !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        await prisma.material.delete({
            where: { id: materialId },
        });

        return res.json({ ok: true, id: materialId });
    } catch (e) {
        console.error("DELETE /materials/:materialId", e);
        return res.status(500).json({ error: "Failed to delete material" });
    }
});

router.post("/:materialId/assign", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const materialId = req.params.materialId;
        const userId = req.user.id;
        const role = req.user.role;
        const { groupId, sessionId, visibleFrom, visibleTo } = req.body || {};

        const material = await prisma.material.findUnique({
            where: { id: materialId },
        });

        if (!material) {
            return res.status(404).json({ error: "Material not found" });
        }

        if (role !== "ADMIN" && material.ownerId !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        if (!groupId && !sessionId) {
            return res.status(400).json({ error: "groupId or sessionId is required" });
        }

        let validatedGroupId = null;
        let validatedSessionId = null;

        if (groupId) {
            const group = await prisma.group.findUnique({
                where: { id: String(groupId) },
            });

            if (!group) {
                return res.status(404).json({ error: "Group not found" });
            }

            if (role !== "ADMIN" && group.teacherId !== userId) {
                return res.status(403).json({ error: "Forbidden" });
            }

            validatedGroupId = group.id;
        }

        if (sessionId) {
            const session = await prisma.session.findUnique({
                where: { id: String(sessionId) },
            });

            if (!session) {
                return res.status(404).json({ error: "Session not found" });
            }

            if (role !== "ADMIN" && session.createdById !== userId) {
                return res.status(403).json({ error: "Forbidden" });
            }

            validatedSessionId = session.id;

            if (!validatedGroupId) {
                validatedGroupId = session.groupId;
            }
        }

        const assignment = await prisma.materialAssignment.create({
            data: {
                materialId,
                groupId: validatedGroupId,
                sessionId: validatedSessionId,
                visibleFrom: visibleFrom ? new Date(visibleFrom) : null,
                visibleTo: visibleTo ? new Date(visibleTo) : null,
            },
        });

        return res.status(201).json({
            id: assignment.id,
            materialId: assignment.materialId,
            groupId: assignment.groupId,
            sessionId: assignment.sessionId,
            visibleFrom: assignment.visibleFrom,
            visibleTo: assignment.visibleTo,
            createdAt: assignment.createdAt,
        });
    } catch (e) {
        console.error("POST /materials/:materialId/assign", e);
        return res.status(500).json({ error: "Failed to assign material" });
    }
});

router.delete("/:materialId/assignments/:assignmentId", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const materialId = req.params.materialId;
        const assignmentId = req.params.assignmentId;
        const userId = req.user.id;
        const role = req.user.role;

        const material = await prisma.material.findUnique({
            where: { id: materialId },
        });

        if (!material) {
            return res.status(404).json({ error: "Material not found" });
        }

        if (role !== "ADMIN" && material.ownerId !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const assignment = await prisma.materialAssignment.findUnique({
            where: { id: assignmentId },
        });

        if (!assignment || assignment.materialId !== materialId) {
            return res.status(404).json({ error: "Assignment not found" });
        }

        await prisma.materialAssignment.delete({
            where: { id: assignmentId },
        });

        return res.json({ ok: true, id: assignmentId });
    } catch (e) {
        console.error("DELETE /materials/:materialId/assignments/:assignmentId", e);
        return res.status(500).json({ error: "Failed to delete material assignment" });
    }
});

router.get("/groups/:groupId/materials", async (req, res) => {
    try {
        const groupId = req.params.groupId;
        const userId = req.user.id;
        const role = req.user.role;

        const group = await prisma.group.findUnique({
            where: { id: groupId },
        });

        if (!group) {
            return res.status(404).json({ error: "Group not found" });
        }

        const isAdmin = role === "ADMIN";
        const isTeacher = role === "TEACHER" && group.teacherId === userId;

        let isMember = false;
        if (role === "STUDENT") {
            const gm = await prisma.groupMember.findUnique({
                where: { groupId_userId: { groupId, userId } },
            });
            isMember = !!gm;
        }

        if (!isAdmin && !isTeacher && !isMember) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const now = new Date();

        const assignments = await prisma.materialAssignment.findMany({
            where: {
                groupId,
                OR: [
                    { visibleFrom: null },
                    { visibleFrom: { lte: now } }
                ],
                AND: [
                    {
                        OR: [
                            { visibleTo: null },
                            { visibleTo: { gte: now } }
                        ]
                    }
                ]
            },
            include: {
                material: true,
            },
            orderBy: { createdAt: "desc" },
        });

        return res.json(assignments.map(a => ({
            assignmentId: a.id,
            materialId: a.material.id,
            title: a.material.title,
            description: a.material.description,
            fileName: a.material.fileName,
            mimeType: a.material.mimeType,
            size: a.material.size,
            createdAt: a.material.createdAt,
            visibleFrom: a.visibleFrom,
            visibleTo: a.visibleTo,
        })));
    } catch (e) {
        console.error("GET /groups/:groupId/materials", e);
        return res.status(500).json({ error: "Failed to get group materials" });
    }
});

router.get("/sessions/:sessionId/materials", async (req, res) => {
    try {
        const sessionId = req.params.sessionId;
        const userId = req.user.id;
        const role = req.user.role;

        const session = await prisma.session.findUnique({
            where: { id: sessionId },
        });

        if (!session) {
            return res.status(404).json({ error: "Session not found" });
        }

        const isAdmin = role === "ADMIN";
        const isOwner = role === "TEACHER" && session.createdById === userId;

        let isMember = false;
        if (role === "STUDENT") {
            const gm = await prisma.groupMember.findUnique({
                where: {
                    groupId_userId: {
                        groupId: session.groupId,
                        userId
                    }
                }
            });
            isMember = !!gm;
        }

        if (!isAdmin && !isOwner && !isMember) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const now = new Date();

        const assignments = await prisma.materialAssignment.findMany({
            where: {
                AND: [
                    {
                        OR: [
                            { sessionId },
                            { groupId: session.groupId }
                        ]
                    },
                    {
                        OR: [
                            { visibleFrom: null },
                            { visibleFrom: { lte: now } }
                        ]
                    },
                    {
                        OR: [
                            { visibleTo: null },
                            { visibleTo: { gte: now } }
                        ]
                    }
                ]
            },
            include: {
                material: true,
            },
            orderBy: { createdAt: "desc" },
        });

        return res.json(assignments.map(a => ({
            assignmentId: a.id,
            materialId: a.material.id,
            title: a.material.title,
            description: a.material.description,
            fileName: a.material.fileName,
            mimeType: a.material.mimeType,
            size: a.material.size,
            createdAt: a.material.createdAt,
            visibleFrom: a.visibleFrom,
            visibleTo: a.visibleTo,
        })));
    } catch (e) {
        console.error("GET /sessions/:sessionId/materials", e);
        return res.status(500).json({ error: "Failed to get session materials" });
    }
});

router.get("/student/materials", roleMiddleware(["STUDENT"]), async (req, res) => {
    try {
        const userId = req.user.id;

        const memberships = await prisma.groupMember.findMany({
            where: { userId },
            select: { groupId: true },
        });

        const groupIds = memberships.map(m => m.groupId);

        const now = new Date();

        const assignments = await prisma.materialAssignment.findMany({
            where: {
                groupId: { in: groupIds },
                OR: [
                    { visibleFrom: null },
                    { visibleFrom: { lte: now } }
                ],
                AND: [
                    {
                        OR: [
                            { visibleTo: null },
                            { visibleTo: { gte: now } }
                        ]
                    }
                ]
            },
            include: {
                material: true,
            },
            orderBy: { createdAt: "desc" },
        });

        return res.json(assignments.map(a => ({
            assignmentId: a.id,
            materialId: a.material.id,
            title: a.material.title,
            description: a.material.description,
            fileName: a.material.fileName,
            mimeType: a.material.mimeType,
            size: a.material.size,
            createdAt: a.material.createdAt,
            visibleFrom: a.visibleFrom,
            visibleTo: a.visibleTo,
        })));
    } catch (e) {
        console.error("GET /student/materials", e);
        return res.status(500).json({ error: "Failed to get student materials" });
    }
});

router.get("/:materialId/download", async (req, res) => {
    try {
        const materialId = req.params.materialId;
        const userId = req.user.id;
        const role = req.user.role;

        const material = await prisma.material.findUnique({
            where: { id: materialId },
        });

        if (!material) {
            return res.status(404).json({ error: "Material not found" });
        }

        const isOwner = material.ownerId === userId;
        const isAdmin = role === "ADMIN";

        let hasAccess = false;

        // teacher/admin/owner — сразу доступ
        if (isOwner || isAdmin) {
            hasAccess = true;
        }

        // если студент — проверяем assignment
        if (!hasAccess && role === "STUDENT") {
            const memberships = await prisma.groupMember.findMany({
                where: { userId },
                select: { groupId: true },
            });

            const groupIds = memberships.map(m => m.groupId);

            const assignment = await prisma.materialAssignment.findFirst({
                where: {
                    materialId,
                    OR: [
                        { groupId: { in: groupIds } },
                        { session: {
                                groupId: { in: groupIds }
                            }}
                    ]
                }
            });

            if (assignment) {
                hasAccess = true;
            }
        }

        if (!hasAccess) {
            return res.status(403).json({ error: "Forbidden" });
        }

        return res.json({
            downloadUrl: `/uploads/${material.storageKey}`,
            fileName: material.fileName,
        });
    } catch (e) {
        console.error("GET /materials/:materialId/download", e);
        return res.status(500).json({ error: "Failed to get download link" });
    }
});

export default router;