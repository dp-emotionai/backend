import express from "express";
import multer from "multer";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";
import { broadcastGroupEvent, broadcastSessionEvent } from "../socket/server.js";
import {
    makeStorageKey,
    uploadBufferToR2,
    getDownloadUrlFromR2,
    deleteFromR2,
} from "../utils/r2.js";

const router = express.Router();

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: Number(process.env.MATERIAL_UPLOAD_MAX_BYTES || 500 * 1024 * 1024),
    },
});

const userSelect = {
    id: true,
    email: true,
    firstName: true,
    lastName: true,
};

const getAuthUserId = (req) => req.user?.id || req.user?.userId;

const detectMaterialKind = (mimeType = "", kind) => {
    const allowed = ["video", "audio", "image", "document", "file"];
    const normalizedKind = kind ? String(kind).trim().toLowerCase() : "";

    if (allowed.includes(normalizedKind)) {
        return normalizedKind;
    }

    const mime = String(mimeType || "").toLowerCase();

    if (mime.startsWith("video/")) return "video";
    if (mime.startsWith("audio/")) return "audio";
    if (mime.startsWith("image/")) return "image";

    if (
        mime.includes("pdf") ||
        mime.includes("word") ||
        mime.includes("document") ||
        mime.includes("presentation") ||
        mime.includes("powerpoint") ||
        mime.includes("spreadsheet") ||
        mime.includes("excel") ||
        mime.startsWith("text/")
    ) {
        return "document";
    }

    return "file";
};

const getMaterialFolder = (kind) => {
    if (kind === "video") return "materials/videos";
    if (kind === "audio") return "materials/audio";
    if (kind === "image") return "materials/images";
    if (kind === "document") return "materials/documents";
    return "materials/files";
};

const normalizeString = (value) => {
    if (value === undefined || value === null) return null;
    const text = String(value).trim();
    return text || null;
};

const normalizeNumber = (value) => {
    if (value === undefined || value === null || value === "") return null;
    const num = Number(value);
    return Number.isFinite(num) ? num : null;
};

const normalizeDate = (value) => {
    if (value === undefined || value === null || value === "") return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
};

const mapUser = (user) => {
    if (!user) return null;

    return {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: [user.firstName, user.lastName].filter(Boolean).join(" "),
    };
};

const mapMaterial = (material) => ({
    id: material.id,
    title: material.title,
    description: material.description,
    kind: material.kind,
    fileName: material.fileName,
    mimeType: material.mimeType,
    storageKey: material.storageKey,
    size: material.size,
    thumbnailStorageKey: material.thumbnailStorageKey,
    durationSec: material.durationSec,
    ownerId: material.ownerId,
    teacher: mapUser(material.owner),
    downloadUrl: `/api/materials/${material.id}/download`,
    createdAt: material.createdAt,
    updatedAt: material.updatedAt,
});

const mapAssignment = (assignment) => ({
    id: assignment.id,
    materialId: assignment.materialId,
    groupId: assignment.groupId,
    sessionId: assignment.sessionId,
    visibleFrom: assignment.visibleFrom,
    visibleTo: assignment.visibleTo,
    assignedById: assignment.assignedById,
    assignedBy: mapUser(assignment.assignedBy),
    createdAt: assignment.createdAt,
});

const mapAssignedMaterial = (assignment) => ({
    assignmentId: assignment.id,
    materialId: assignment.material.id,
    id: assignment.material.id,
    title: assignment.material.title,
    description: assignment.material.description,
    kind: assignment.material.kind,
    fileName: assignment.material.fileName,
    mimeType: assignment.material.mimeType,
    size: assignment.material.size,
    durationSec: assignment.material.durationSec,
    ownerId: assignment.material.ownerId,
    teacher: mapUser(assignment.material.owner),
    assignedById: assignment.assignedById,
    assignedBy: mapUser(assignment.assignedBy),
    assignedAt: assignment.createdAt,
    groupId: assignment.groupId,
    sessionId: assignment.sessionId,
    visibleFrom: assignment.visibleFrom,
    visibleTo: assignment.visibleTo,
    downloadUrl: `/api/materials/${assignment.material.id}/download`,
    createdAt: assignment.material.createdAt,
    updatedAt: assignment.material.updatedAt,
});

router.use(authMiddleware);

router.post("/upload", roleMiddleware(["TEACHER", "ADMIN", "STUDENT"]), upload.single("file"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "file is required" });
        }

        const kind = detectMaterialKind(req.file.mimetype, req.body?.kind);
        const fileName = Buffer.from(req.file.originalname, "latin1").toString("utf8");
        const storageKey = makeStorageKey(getMaterialFolder(kind), fileName);

        await uploadBufferToR2({
            key: storageKey,
            buffer: req.file.buffer,
            contentType: req.file.mimetype || "application/octet-stream",
        });

        return res.status(201).json({
            storageKey,
            kind,
            fileName,
            mimeType: req.file.mimetype,
            size: req.file.size,
        });
    } catch (e) {
        console.error("POST /materials/upload", e);
        return res.status(500).json({ error: "Failed to upload material file" });
    }
});

router.get("/", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const userId = getAuthUserId(req);
        const role = req.user.role;

        const materials = await prisma.material.findMany({
            where: role === "ADMIN" ? {} : { ownerId: userId },
            include: {
                owner: { select: userSelect },
            },
            orderBy: { createdAt: "desc" },
        });

        return res.json(materials.map(mapMaterial));
    } catch (e) {
        console.error("GET /materials", e);
        return res.status(500).json({ error: "Failed to get materials" });
    }
});

router.post("/", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const userId = getAuthUserId(req);

        const {
            title,
            description,
            kind,
            fileName,
            mimeType,
            storageKey,
            size,
            thumbnailStorageKey,
            durationSec,
        } = req.body || {};

        if (!title || !String(title).trim()) {
            return res.status(400).json({ error: "title is required" });
        }

        if (!fileName || !String(fileName).trim()) {
            return res.status(400).json({ error: "fileName is required" });
        }

        if (!storageKey || !String(storageKey).trim()) {
            return res.status(400).json({ error: "storageKey is required" });
        }

        const detectedKind = detectMaterialKind(mimeType, kind);

        const material = await prisma.material.create({
            data: {
                title: String(title).trim(),
                description: normalizeString(description),
                kind: detectedKind,
                fileName: String(fileName).trim(),
                mimeType: normalizeString(mimeType),
                storageKey: String(storageKey).trim(),
                size: normalizeNumber(size),
                thumbnailStorageKey: normalizeString(thumbnailStorageKey),
                durationSec: normalizeNumber(durationSec),
                ownerId: userId,
            },
            include: {
                owner: { select: userSelect },
            },
        });

        return res.status(201).json(mapMaterial(material));
    } catch (e) {
        console.error("POST /materials", e);
        return res.status(500).json({ error: "Failed to create material" });
    }
});

router.get("/groups/:groupId/materials", async (req, res) => {
    try {
        const groupId = req.params.groupId;
        const userId = getAuthUserId(req);
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
                where: {
                    groupId_userId: {
                        groupId,
                        userId,
                    },
                },
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
                AND: [
                    {
                        OR: [
                            { visibleFrom: null },
                            { visibleFrom: { lte: now } },
                        ],
                    },
                    {
                        OR: [
                            { visibleTo: null },
                            { visibleTo: { gte: now } },
                        ],
                    },
                ],
            },
            include: {
                material: {
                    include: {
                        owner: { select: userSelect },
                    },
                },
                assignedBy: { select: userSelect },
            },
            orderBy: { createdAt: "desc" },
        });

        return res.json(assignments.map(mapAssignedMaterial));
    } catch (e) {
        console.error("GET /groups/:groupId/materials", e);
        return res.status(500).json({ error: "Failed to get group materials" });
    }
});

router.get("/sessions/:sessionId/materials", async (req, res) => {
    try {
        const sessionId = req.params.sessionId;
        const userId = getAuthUserId(req);
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
                        userId,
                    },
                },
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
                            { groupId: session.groupId },
                        ],
                    },
                    {
                        OR: [
                            { visibleFrom: null },
                            { visibleFrom: { lte: now } },
                        ],
                    },
                    {
                        OR: [
                            { visibleTo: null },
                            { visibleTo: { gte: now } },
                        ],
                    },
                ],
            },
            include: {
                material: {
                    include: {
                        owner: { select: userSelect },
                    },
                },
                assignedBy: { select: userSelect },
            },
            orderBy: { createdAt: "desc" },
        });

        return res.json(assignments.map(mapAssignedMaterial));
    } catch (e) {
        console.error("GET /sessions/:sessionId/materials", e);
        return res.status(500).json({ error: "Failed to get session materials" });
    }
});

router.get("/student/materials", roleMiddleware(["STUDENT"]), async (req, res) => {
    try {
        const userId = getAuthUserId(req);

        const memberships = await prisma.groupMember.findMany({
            where: { userId },
            select: { groupId: true },
        });

        const groupIds = memberships.map((m) => m.groupId);
        const now = new Date();

        const assignments = await prisma.materialAssignment.findMany({
            where: {
                groupId: { in: groupIds },
                AND: [
                    {
                        OR: [
                            { visibleFrom: null },
                            { visibleFrom: { lte: now } },
                        ],
                    },
                    {
                        OR: [
                            { visibleTo: null },
                            { visibleTo: { gte: now } },
                        ],
                    },
                ],
            },
            include: {
                material: {
                    include: {
                        owner: { select: userSelect },
                    },
                },
                assignedBy: { select: userSelect },
            },
            orderBy: { createdAt: "desc" },
        });

        return res.json(assignments.map(mapAssignedMaterial));
    } catch (e) {
        console.error("GET /student/materials", e);
        return res.status(500).json({ error: "Failed to get student materials" });
    }
});

router.patch("/:materialId", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const materialId = req.params.materialId;
        const userId = getAuthUserId(req);
        const role = req.user.role;

        const {
            title,
            description,
            kind,
            fileName,
            mimeType,
            storageKey,
            size,
            thumbnailStorageKey,
            durationSec,
        } = req.body || {};

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
        if (description !== undefined) updates.description = normalizeString(description);
        if (kind !== undefined) updates.kind = detectMaterialKind(mimeType || material.mimeType, kind);
        if (fileName !== undefined) updates.fileName = String(fileName).trim();
        if (mimeType !== undefined) updates.mimeType = normalizeString(mimeType);
        if (storageKey !== undefined) updates.storageKey = String(storageKey).trim();
        if (size !== undefined) updates.size = normalizeNumber(size);
        if (thumbnailStorageKey !== undefined) updates.thumbnailStorageKey = normalizeString(thumbnailStorageKey);
        if (durationSec !== undefined) updates.durationSec = normalizeNumber(durationSec);

        const updated = await prisma.material.update({
            where: { id: materialId },
            data: updates,
            include: {
                owner: { select: userSelect },
            },
        });

        return res.json(mapMaterial(updated));
    } catch (e) {
        console.error("PATCH /materials/:materialId", e);
        return res.status(500).json({ error: "Failed to update material" });
    }
});

router.delete("/:materialId", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const materialId = req.params.materialId;
        const userId = getAuthUserId(req);
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

        const assignments = await prisma.materialAssignment.findMany({
            where: { materialId },
            select: {
                id: true,
                groupId: true,
                sessionId: true,
            },
        });

        await deleteFromR2(material.storageKey);

        if (material.thumbnailStorageKey) {
            await deleteFromR2(material.thumbnailStorageKey);
        }

        await prisma.material.delete({
            where: { id: materialId },
        });

        try {
            const event = {
                type: "material.deleted",
                materialId,
                id: materialId,
                assignmentIds: assignments.map((assignment) => assignment.id),
            };

            const groupIds = Array.from(new Set(assignments.map((assignment) => assignment.groupId).filter(Boolean)));
            const sessionIds = Array.from(new Set(assignments.map((assignment) => assignment.sessionId).filter(Boolean)));

            for (const groupId of groupIds) broadcastGroupEvent(groupId, event);
            for (const sessionId of sessionIds) broadcastSessionEvent(sessionId, event);
        } catch (wsError) {
            console.error("DELETE /materials/:materialId broadcast error", wsError);
        }

        return res.json({ ok: true, id: materialId });
    } catch (e) {
        console.error("DELETE /materials/:materialId", e);
        return res.status(500).json({ error: "Failed to delete material" });
    }
});

router.get("/:materialId/assignments", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const materialId = req.params.materialId;
        const userId = getAuthUserId(req);
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

        const assignments = await prisma.materialAssignment.findMany({
            where: { materialId },
            include: {
                assignedBy: { select: userSelect },
            },
            orderBy: { createdAt: "desc" },
        });

        return res.json(assignments.map(mapAssignment));
    } catch (e) {
        console.error("GET /materials/:materialId/assignments", e);
        return res.status(500).json({ error: "Failed to get material assignments" });
    }
});

router.post("/:materialId/assign", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const materialId = req.params.materialId;
        const userId = getAuthUserId(req);
        const role = req.user.role;

        const {
            groupId,
            sessionId,
            visibleFrom,
            visibleTo,
        } = req.body || {};

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
                visibleFrom: normalizeDate(visibleFrom),
                visibleTo: normalizeDate(visibleTo),
                assignedById: userId,
            },
            include: {
                assignedBy: { select: userSelect },
                material: {
                    include: {
                        owner: { select: userSelect },
                    },
                },
            },
        });

        const response = mapAssignment(assignment);
        const assignedMaterial = mapAssignedMaterial(assignment);

        try {
            const event = {
                type: "material.assigned",
                materialId,
                assignment: response,
                material: assignedMaterial,
            };

            if (assignment.groupId) broadcastGroupEvent(assignment.groupId, event);
            if (assignment.sessionId) broadcastSessionEvent(assignment.sessionId, event);
        } catch (wsError) {
            console.error("POST /materials/:materialId/assign broadcast error", wsError);
        }

        return res.status(201).json(response);
    } catch (e) {
        console.error("POST /materials/:materialId/assign", e);
        return res.status(500).json({ error: "Failed to assign material" });
    }
});

router.delete("/:materialId/assignments/:assignmentId", roleMiddleware(["TEACHER", "ADMIN"]), async (req, res) => {
    try {
        const materialId = req.params.materialId;
        const assignmentId = req.params.assignmentId;
        const userId = getAuthUserId(req);
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

        try {
            const event = {
                type: "material.unassigned",
                materialId,
                assignmentId,
                groupId: assignment.groupId,
                sessionId: assignment.sessionId,
            };

            if (assignment.groupId) broadcastGroupEvent(assignment.groupId, event);
            if (assignment.sessionId) broadcastSessionEvent(assignment.sessionId, event);
        } catch (wsError) {
            console.error("DELETE /materials/:materialId/assignments/:assignmentId broadcast error", wsError);
        }

        return res.json({ ok: true, id: assignmentId });
    } catch (e) {
        console.error("DELETE /materials/:materialId/assignments/:assignmentId", e);
        return res.status(500).json({ error: "Failed to delete material assignment" });
    }
});


router.get("/download-by-key", async (req, res) => {
    try {
        const storageKey = String(req.query.key || "").trim();
        const fileName = String(req.query.fileName || "").trim() || undefined;

        if (!storageKey) {
            return res.status(400).json({ error: "key is required" });
        }

        // Chat attachments are stored in R2 by storageKey, not as Material rows.
        // Auth is already required by router.use(authMiddleware), so we return
        // a short-lived signed Cloudflare R2 URL instead of /uploads/... local path.
        const mode = req.query.mode === "inline" ? "inline" : "download";
        const downloadUrl = await getDownloadUrlFromR2(storageKey, fileName, mode);

        return res.json({
            downloadUrl,
            url: downloadUrl,
            fileName: fileName || storageKey.split("/").pop() || "file",
        });
    } catch (e) {
        console.error("GET /materials/download-by-key", e);
        return res.status(500).json({ error: "Failed to get download link" });
    }
});

router.get("/:materialId/download", async (req, res) => {
    try {
        const materialId = req.params.materialId;
        const userId = getAuthUserId(req);
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

        if (isOwner || isAdmin) {
            hasAccess = true;
        }

        if (!hasAccess && role === "STUDENT") {
            const memberships = await prisma.groupMember.findMany({
                where: { userId },
                select: { groupId: true },
            });

            const groupIds = memberships.map((m) => m.groupId);
            const now = new Date();

            const assignment = await prisma.materialAssignment.findFirst({
                where: {
                    materialId,
                    AND: [
                        {
                            OR: [
                                { groupId: { in: groupIds } },
                                {
                                    session: {
                                        is: {
                                            groupId: { in: groupIds },
                                        },
                                    },
                                },
                            ],
                        },
                        {
                            OR: [
                                { visibleFrom: null },
                                { visibleFrom: { lte: now } },
                            ],
                        },
                        {
                            OR: [
                                { visibleTo: null },
                                { visibleTo: { gte: now } },
                            ],
                        },
                    ],
                },
            });

            if (assignment) {
                hasAccess = true;
            }
        }

        if (!hasAccess) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const mode = req.query.mode === "inline" ? "inline" : "download";
        const downloadUrl = await getDownloadUrlFromR2(material.storageKey, material.fileName, mode);

        return res.json({
            downloadUrl,
            url: downloadUrl,
            fileName: material.fileName,
            kind: material.kind,
            mimeType: material.mimeType,
        });
    } catch (e) {
        console.error("GET /materials/:materialId/download", e);
        return res.status(500).json({ error: "Failed to get download link" });
    }
});

export default router;