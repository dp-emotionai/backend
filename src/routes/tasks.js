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
import {
    notifyTaskPublished,
} from "../services/taskNotifications.js"

const router = express.Router();

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: Number(process.env.TASK_UPLOAD_MAX_BYTES || 100 * 1024 * 1024),
    },
});

const userSelect = {
    id: true,
    email: true,
    firstName: true,
    lastName: true,
};

const taskTypes = new Set(["test", "homework", "file_upload", "text_answer"]);
const taskStatuses = new Set(["draft", "published", "closed", "archived"]);
const visibleStudentStatuses = ["published", "closed"];

const getAuthUserId = (req) => req.user?.id || req.user?.userId;

const normalizeString = (value) => {
    if (value === undefined || value === null) return null;
    const text = String(value).trim();
    return text || null;
};

const normalizeNumber = (value, fallback = null) => {
    if (value === undefined || value === null || value === "") return fallback;
    const num = Number(value);
    return Number.isFinite(num) ? num : fallback;
};

const normalizeDate = (value) => {
    if (value === undefined || value === null || value === "") return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
};

const normalizeBoolean = (value, fallback = false) => {
    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {
        return fallback;
    }

    if (typeof value === "boolean") {
        return value;
    }

    return ["true", "1", "yes", "on"].includes(
        String(value).trim().toLowerCase()
    );
};

const normalizeFileName = (fileName) => {
    const raw = normalizeString(fileName) || "attachment";

    try {
        const decoded = Buffer.from(raw, "latin1").toString("utf8");
        return decoded.includes("�") ? raw : decoded;
    } catch {
        return raw;
    }
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

const mapGroup = (group) => {
    if (!group) return null;

    return {
        id: group.id,
        name: group.name,
        teacherId: group.teacherId,
    };
};

const mapSession = (session) => {
    if (!session) return null;

    return {
        id: session.id,
        title: session.title,
        type: session.type,
        status: session.status,
        groupId: session.groupId,
        startedAt: session.startedAt,
        endedAt: session.endedAt,
        scheduledStartAt: session.scheduledStartAt,
        scheduledEndAt: session.scheduledEndAt,
    };
};

const mapTest = (test) => {
    if (!test) return null;

    return {
        id: test.id,
        title: test.title,
        description: test.description,
        groupId: test.groupId,
        sessionId: test.sessionId,
        status: test.status,
        timeLimitMinutes: test.timeLimitMinutes,
        attemptsAllowed: test.attemptsAllowed,
        startsAt: test.startsAt,
        endsAt: test.endsAt,
        questionCount: test._count?.questions,
        submissionCount: test._count?.submissions,
    };
};

const mapTaskMaterial = (material) => {
    if (!material) return null;

    return {
        id: material.id,
        taskId: material.taskId,
        fileName: material.fileName,
        mimeType: material.mimeType,
        size: material.size,
        downloadUrl: `/api/tasks/${material.taskId}/materials/${material.id}/download-url`,
        createdAt: material.createdAt,
    };
};

const mapTaskSubmission = (submission) => {
    if (!submission) return null;

    return {
        id: submission.id,
        taskId: submission.taskId,
        studentId: submission.studentId,
        student: mapUser(submission.student),
        status: submission.status,
        isLate: submission.isLate,
        textAnswer: submission.textAnswer,
        attachmentFileName: submission.attachmentFileName,
        attachmentMimeType: submission.attachmentMimeType,
        attachmentSize: submission.attachmentSize,
        attachmentUrl: submission.attachmentStorageKey
            ? `/api/tasks/submissions/${submission.id}/attachment`
            : null,
        score: submission.score,
        feedback: submission.feedback,
        submittedAt: submission.submittedAt,
        gradedAt: submission.gradedAt,
        gradedById: submission.gradedById,
        gradedBy: mapUser(submission.gradedBy),
        createdAt: submission.createdAt,
        updatedAt: submission.updatedAt,
    };
};

const mapTestSubmission = (submission) => {
    if (!submission) return null;

    return {
        id: submission.id,
        testId: submission.testId,
        studentId: submission.studentId,
        student: mapUser(submission.student),
        status: submission.status,
        score: submission.score,
        maxScore: submission.maxScore,
        startedAt: submission.startedAt,
        submittedAt: submission.submittedAt,
        answers: submission.answers,
    };
};

const mapTask = (task) => ({
    id: task.id,
    title: task.title,
    description: task.description,
    type: task.type,
    status: task.status,
    deadline: task.deadline,
    points: task.points,
    allowLateSubmission: task.allowLateSubmission,
    materials: Array.isArray(task.materials)
        ? task.materials.map(mapTaskMaterial)
        : [],
    groupId: task.groupId,
    sessionId: task.sessionId,
    testId: task.testId,
    createdById: task.createdById,
    createdBy: mapUser(task.createdBy),
    group: mapGroup(task.group),
    session: mapSession(task.session),
    test: mapTest(task.test),
    submissionCount:
        task.type === "test"
            ? task.test?._count?.submissions || 0
            : task._count?.submissions || 0,
    mySubmission: mapTaskSubmission(task.mySubmission),
    myTestSubmission: mapTestSubmission(task.myTestSubmission),
    createdAt: task.createdAt,
    updatedAt: task.updatedAt,
});

const getTaskInclude = () => ({
    createdBy: { select: userSelect },
    group: true,
    session: {
        include: {
            group: true,
        },
    },
    test: {
        include: {
            _count: {
                select: {
                    questions: true,
                    submissions: true,
                },
            },
        },
    },
    materials: {
        orderBy: {
            createdAt: "asc",
        },
    },
    _count: {
        select: {
            submissions: true,
        },
    },
});

const getTaskGroupId = (task) => task.session?.groupId || task.groupId || null;

const isStudentInGroup = async (userId, groupId) => {
    if (!userId || !groupId) return false;

    const membership = await prisma.groupMember.findUnique({
        where: {
            groupId_userId: {
                groupId,
                userId,
            },
        },
    });

    return !!membership;
};

const canManageTask = (req, task) => {
    const userId = getAuthUserId(req);
    const role = req.user?.role;

    if (role === "ADMIN") return true;
    if (role !== "TEACHER") return false;
    if (task.createdById === userId) return true;
    if (task.group?.teacherId === userId) return true;
    if (task.session?.group?.teacherId === userId) return true;

    return false;
};

const canStudentAccessTask = async (req, task) => {
    const userId = getAuthUserId(req);
    const role = req.user?.role;

    if (role === "ADMIN" || task.createdById === userId) return true;
    if (role !== "STUDENT") return false;
    if (!visibleStudentStatuses.includes(task.status)) return false;

    const groupId = getTaskGroupId(task);
    return isStudentInGroup(userId, groupId);
};

const ensureTaskAccess = async (req, task) => {
    if (!task) {
        const error = new Error("Task not found");
        error.statusCode = 404;
        throw error;
    }

    if (canManageTask(req, task)) return true;

    const studentAllowed = await canStudentAccessTask(req, task);

    if (!studentAllowed) {
        const error = new Error("Forbidden");
        error.statusCode = 403;
        throw error;
    }

    return true;
};

const validateTaskScope = async ({ groupId, sessionId, userId, role }) => {
    let validatedGroupId = normalizeString(groupId);
    let validatedSessionId = normalizeString(sessionId);

    if (!validatedGroupId && !validatedSessionId) {
        const error = new Error("groupId or sessionId is required");
        error.statusCode = 400;
        throw error;
    }

    if (validatedGroupId) {
        const group = await prisma.group.findUnique({
            where: { id: validatedGroupId },
        });

        if (!group) {
            const error = new Error("Group not found");
            error.statusCode = 404;
            throw error;
        }

        if (role !== "ADMIN" && group.teacherId !== userId) {
            const error = new Error("Forbidden");
            error.statusCode = 403;
            throw error;
        }
    }

    if (validatedSessionId) {
        const session = await prisma.session.findUnique({
            where: { id: validatedSessionId },
            include: { group: true },
        });

        if (!session) {
            const error = new Error("Session not found");
            error.statusCode = 404;
            throw error;
        }

        if (
            role !== "ADMIN" &&
            session.group.teacherId !== userId &&
            session.createdById !== userId
        ) {
            const error = new Error("Forbidden");
            error.statusCode = 403;
            throw error;
        }

        if (!validatedGroupId) {
            validatedGroupId = session.groupId;
        }

        if (validatedGroupId !== session.groupId) {
            const error = new Error(
                "sessionId does not belong to selected groupId"
            );
            error.statusCode = 400;
            throw error;
        }
    }

    return {
        groupId: validatedGroupId,
        sessionId: validatedSessionId,
    };
};

const validateLinkedTest = async ({
                                      testId,
                                      groupId,
                                      sessionId,
                                      userId,
                                      role,
                                      status,
                                  }) => {
    const cleanTestId = normalizeString(testId);

    if (!cleanTestId) {
        const error = new Error("testId is required for task type test");
        error.statusCode = 400;
        throw error;
    }

    const test = await prisma.test.findUnique({
        where: { id: cleanTestId },
        include: {
            group: true,
            session: {
                include: { group: true },
            },
        },
    });

    if (!test) {
        const error = new Error("Test not found");
        error.statusCode = 404;
        throw error;
    }

    const testGroupId = test.session?.groupId || test.groupId;
    const testTeacherId =
        test.session?.group?.teacherId || test.group?.teacherId;

    const canUseTest =
        role === "ADMIN" ||
        test.createdById === userId ||
        testTeacherId === userId;

    if (!canUseTest) {
        const error = new Error("Forbidden");
        error.statusCode = 403;
        throw error;
    }

    if (testGroupId && groupId && testGroupId !== groupId) {
        const error = new Error("Linked test belongs to another group");
        error.statusCode = 400;
        throw error;
    }

    if (test.sessionId && sessionId && test.sessionId !== sessionId) {
        const error = new Error("Linked test belongs to another session");
        error.statusCode = 400;
        throw error;
    }

    if (status === "published" && test.status !== "published") {
        const error = new Error(
            "Linked test must be published before publishing task"
        );
        error.statusCode = 400;
        throw error;
    }

    return test;
};

const attachMySubmissions = async (tasks, userId) => {
    if (!userId || tasks.length === 0) return tasks;

    const taskIds = tasks.map((task) => task.id);
    const testIds = tasks
        .filter((task) => task.type === "test" && task.testId)
        .map((task) => task.testId);

    const [taskSubmissions, testSubmissions] = await Promise.all([
        prisma.taskSubmission.findMany({
            where: {
                taskId: { in: taskIds },
                studentId: userId,
            },
            include: {
                student: { select: userSelect },
                gradedBy: { select: userSelect },
            },
        }),
        testIds.length > 0
            ? prisma.testSubmission.findMany({
                where: {
                    testId: { in: testIds },
                    studentId: userId,
                },
                include: {
                    student: { select: userSelect },
                    answers: true,
                },
            })
            : [],
    ]);

    const taskSubmissionByTaskId = new Map(
        taskSubmissions.map((submission) => [submission.taskId, submission])
    );

    const testSubmissionByTestId = new Map(
        testSubmissions.map((submission) => [submission.testId, submission])
    );

    return tasks.map((task) => ({
        ...task,
        mySubmission: taskSubmissionByTaskId.get(task.id) || null,
        myTestSubmission: task.testId
            ? testSubmissionByTestId.get(task.testId) || null
            : null,
    }));
};

const notifyTaskChanged = (task, action) => {
    const payload = {
        type: `task:${action}`,
        taskId: task.id,
        groupId: task.groupId,
        sessionId: task.sessionId,
    };

    if (task.groupId) {
        broadcastGroupEvent(task.groupId, payload);
    }

    if (task.sessionId) {
        broadcastSessionEvent(task.sessionId, payload);
    }
};

router.use(authMiddleware);

router.get("/", async (req, res) => {
    try {
        const userId = getAuthUserId(req);
        const role = req.user.role;

        const groupId = normalizeString(req.query.groupId);
        const sessionId = normalizeString(req.query.sessionId);
        const type = normalizeString(req.query.type);
        const status = normalizeString(req.query.status);

        const where = {};

        if (type) {
            if (!taskTypes.has(type)) {
                return res.status(400).json({
                    error: "Invalid task type",
                });
            }

            where.type = type;
        }

        if (status) {
            if (!taskStatuses.has(status)) {
                return res.status(400).json({
                    error: "Invalid task status",
                });
            }

            where.status = status;
        }

        if (role === "STUDENT") {
            const memberships = await prisma.groupMember.findMany({
                where: { userId },
                select: { groupId: true },
            });

            const groupIds = memberships.map(
                (membership) => membership.groupId
            );

            if (groupId && !groupIds.includes(groupId)) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            let session = null;

            if (sessionId) {
                session = await prisma.session.findUnique({
                    where: { id: sessionId },
                    select: {
                        id: true,
                        groupId: true,
                    },
                });

                if (!session) {
                    return res.status(404).json({
                        error: "Session not found",
                    });
                }

                if (!groupIds.includes(session.groupId)) {
                    return res.status(403).json({
                        error: "Forbidden",
                    });
                }
            }

            if (status && !visibleStudentStatuses.includes(status)) {
                return res.status(403).json({
                    error: "Students can see only published or closed tasks",
                });
            }

            where.status = status || {
                in: visibleStudentStatuses,
            };

            if (sessionId) {
                where.OR = [
                    { sessionId },
                    {
                        groupId: session.groupId,
                        sessionId: null,
                    },
                ];
            } else if (groupId) {
                where.groupId = groupId;
            } else {
                where.groupId = {
                    in: groupIds,
                };
            }
        } else if (role === "TEACHER") {
            where.AND = [
                {
                    OR: [
                        {
                            createdById: userId,
                        },
                        {
                            group: {
                                is: {
                                    teacherId: userId,
                                },
                            },
                        },
                        {
                            session: {
                                is: {
                                    group: {
                                        is: {
                                            teacherId: userId,
                                        },
                                    },
                                },
                            },
                        },
                    ],
                },
            ];

            if (groupId) {
                where.groupId = groupId;
            }

            if (sessionId) {
                where.sessionId = sessionId;
            }
        } else if (role === "ADMIN") {
            if (groupId) {
                where.groupId = groupId;
            }

            if (sessionId) {
                where.sessionId = sessionId;
            }
        } else {
            return res.status(403).json({
                error: "Forbidden",
            });
        }

        const tasks = await prisma.task.findMany({
            where,
            include: getTaskInclude(),
            orderBy: [
                {
                    deadline: "asc",
                },
                {
                    createdAt: "desc",
                },
            ],
        });

        const tasksWithSubmissions =
            role === "STUDENT"
                ? await attachMySubmissions(tasks, userId)
                : tasks;

        return res.json(
            tasksWithSubmissions.map(mapTask)
        );
    } catch (e) {
        console.error("GET /tasks", e);

        return res.status(500).json({
            error: "Failed to get tasks",
        });
    }
});

router.post(
    "/",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const userId = getAuthUserId(req);
            const role = req.user.role;

            const {
                title,
                description,
                type,
                groupId,
                sessionId,
                testId,
                deadline,
                points,
                status,
                allowLateSubmission,
            } = req.body || {};

            const cleanTitle = normalizeString(title);

            if (!cleanTitle) {
                return res.status(400).json({
                    error: "title is required",
                });
            }

            const cleanType =
                normalizeString(type) || "homework";

            if (!taskTypes.has(cleanType)) {
                return res.status(400).json({
                    error: "Invalid task type",
                });
            }

            const cleanStatus =
                normalizeString(status) || "draft";

            if (!taskStatuses.has(cleanStatus)) {
                return res.status(400).json({
                    error: "Invalid task status",
                });
            }

            const scope = await validateTaskScope({
                groupId,
                sessionId,
                userId,
                role,
            });

            let linkedTestId = null;

            if (cleanType === "test") {
                const test = await validateLinkedTest({
                    testId,
                    groupId: scope.groupId,
                    sessionId: scope.sessionId,
                    userId,
                    role,
                    status: cleanStatus,
                });

                linkedTestId = test.id;
            }

            const task = await prisma.task.create({
                data: {
                    title: cleanTitle,
                    description:
                        normalizeString(description),
                    type: cleanType,
                    status: cleanStatus,
                    deadline: normalizeDate(deadline),
                    points: Math.max(
                        0,
                        normalizeNumber(points, 0)
                    ),
                    allowLateSubmission:
                        normalizeBoolean(
                            allowLateSubmission,
                            false
                        ),
                    groupId: scope.groupId,
                    sessionId: scope.sessionId,
                    testId: linkedTestId,
                    createdById: userId,
                },
                include: getTaskInclude(),
            });

            notifyTaskChanged(task, "created")

            const becamePublished =
                task.status === "published";

            console.log("TASK PUBLISH FLOW", {
                taskId: task.id,
                oldStatus: null,
                requestedStatus: cleanStatus,
                updatedStatus: task.status,
                becamePublished,
            });

            if (becamePublished) {
                console.log(
                    "NOTIFICATION SERVICE CALLED",
                    {
                        entityType: "task",
                        entityId: task.id,
                        groupId: task.groupId,
                        sessionId: task.sessionId,
                    }
                );

                try {
                    await notifyTaskPublished(task)
                } catch (notificationError) {
                    console.error(
                        "Failed to notify students about task",
                        notificationError
                    )
                }
            }

            return res.status(201).json(
                mapTask(task)
            );
        } catch (e) {
            console.error("POST /tasks", e);

            return res
                .status(e.statusCode || 500)
                .json({
                    error:
                        e.message ||
                        "Failed to create task",
                });
        }
    }
);

router.get(
    "/submissions/:submissionId/attachment",
    async (req, res) => {
        try {
            const submission =
                await prisma.taskSubmission.findUnique({
                    where: {
                        id: req.params.submissionId,
                    },
                    include: {
                        student: {
                            select: userSelect,
                        },
                        gradedBy: {
                            select: userSelect,
                        },
                        task: {
                            include: getTaskInclude(),
                        },
                    },
                });

            if (
                !submission ||
                !submission.attachmentStorageKey
            ) {
                return res.status(404).json({
                    error: "Attachment not found",
                });
            }

            const userId = getAuthUserId(req);
            const role = req.user.role;
            const isOwner =
                submission.studentId === userId;

            const isManager = canManageTask(
                req,
                submission.task
            );

            if (
                role !== "ADMIN" &&
                !isOwner &&
                !isManager
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const url = await getDownloadUrlFromR2(
                submission.attachmentStorageKey,
                submission.attachmentFileName
            );

            return res.redirect(url);
        } catch (e) {
            console.error(
                "GET /tasks/submissions/:submissionId/attachment",
                e
            );

            return res.status(500).json({
                error: "Failed to get attachment",
            });
        }
    }
);

router.get(
    "/submissions/:submissionId/attachment-url",
    async (req, res) => {
        try {
            const submission =
                await prisma.taskSubmission.findUnique({
                    where: {
                        id: req.params.submissionId,
                    },
                    include: {
                        task: {
                            include: getTaskInclude(),
                        },
                    },
                });

            if (
                !submission ||
                !submission.attachmentStorageKey
            ) {
                return res.status(404).json({
                    error: "Attachment not found",
                });
            }

            const userId = getAuthUserId(req);
            const role = req.user.role;

            const isOwner =
                submission.studentId === userId;

            const isManager = canManageTask(
                req,
                submission.task
            );

            if (
                role !== "ADMIN" &&
                !isOwner &&
                !isManager
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const url = await getDownloadUrlFromR2(
                submission.attachmentStorageKey,
                submission.attachmentFileName
            );

            return res.json({
                url,
                fileName:
                submission.attachmentFileName,
                mimeType:
                submission.attachmentMimeType,
                size: submission.attachmentSize,
            });
        } catch (e) {
            console.error(
                "GET /tasks/submissions/:submissionId/attachment-url",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to get attachment url",
            });
        }
    }
);

router.post(
    "/:taskId/materials",
    roleMiddleware(["TEACHER", "ADMIN"]),
    upload.array("materials", 10),
    async (req, res) => {
        const uploadedKeys = [];

        try {
            const taskId = req.params.taskId;

            const task = await prisma.task.findUnique({
                where: {
                    id: taskId,
                },
                include: getTaskInclude(),
            });

            if (!task) {
                return res.status(404).json({
                    error: "Task not found",
                });
            }

            if (!canManageTask(req, task)) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const files = Array.isArray(req.files)
                ? req.files
                : [];

            if (files.length === 0) {
                return res.status(400).json({
                    error:
                        "At least one material file is required",
                });
            }

            const materialData = [];

            for (const file of files) {
                const cleanFileName =
                    normalizeFileName(
                        file.originalname
                    );

                const storageKey = makeStorageKey(
                    `tasks/${taskId}/materials`,
                    cleanFileName
                );

                await uploadBufferToR2({
                    key: storageKey,
                    buffer: file.buffer,
                    contentType:
                        file.mimetype ||
                        "application/octet-stream",
                });

                uploadedKeys.push(storageKey);

                materialData.push({
                    taskId,
                    storageKey,
                    fileName: cleanFileName,
                    mimeType:
                        file.mimetype ||
                        "application/octet-stream",
                    size: file.size,
                });
            }

            await prisma.taskMaterial.createMany({
                data: materialData,
            });

            const materials =
                await prisma.taskMaterial.findMany({
                    where: {
                        storageKey: {
                            in: uploadedKeys,
                        },
                    },
                    orderBy: {
                        createdAt: "asc",
                    },
                });

            notifyTaskChanged(
                task,
                "materials-updated"
            );

            return res.status(201).json(
                materials.map(mapTaskMaterial)
            );
        } catch (e) {
            console.error(
                "POST /tasks/:taskId/materials",
                e
            );

            await Promise.allSettled(
                uploadedKeys.map((key) =>
                    deleteFromR2(key)
                )
            );

            return res
                .status(e.statusCode || 500)
                .json({
                    error:
                        e.message ||
                        "Failed to upload task materials",
                });
        }
    }
);

router.get(
    "/:taskId/materials/:materialId/download-url",
    async (req, res) => {
        try {
            const taskId = req.params.taskId;
            const materialId =
                req.params.materialId;

            const task = await prisma.task.findUnique({
                where: {
                    id: taskId,
                },
                include: getTaskInclude(),
            });

            await ensureTaskAccess(req, task);

            const material =
                await prisma.taskMaterial.findUnique({
                    where: {
                        id: materialId,
                    },
                });

            if (
                !material ||
                material.taskId !== taskId
            ) {
                return res.status(404).json({
                    error: "Material not found",
                });
            }

            const url =
                await getDownloadUrlFromR2(
                    material.storageKey,
                    material.fileName
                );

            return res.json({
                url,
                fileName: material.fileName,
                mimeType: material.mimeType,
                size: material.size,
            });
        } catch (e) {
            console.error(
                "GET /tasks/:taskId/materials/:materialId/download-url",
                e
            );

            return res
                .status(e.statusCode || 500)
                .json({
                    error:
                        e.message ||
                        "Failed to get material url",
                });
        }
    }
);

router.get(
    "/:taskId/materials/:materialId/download",
    async (req, res) => {
        try {
            const taskId = req.params.taskId;
            const materialId =
                req.params.materialId;

            const task = await prisma.task.findUnique({
                where: {
                    id: taskId,
                },
                include: getTaskInclude(),
            });

            await ensureTaskAccess(req, task);

            const material =
                await prisma.taskMaterial.findUnique({
                    where: {
                        id: materialId,
                    },
                });

            if (
                !material ||
                material.taskId !== taskId
            ) {
                return res.status(404).json({
                    error: "Material not found",
                });
            }

            const url =
                await getDownloadUrlFromR2(
                    material.storageKey,
                    material.fileName
                );

            return res.redirect(url);
        } catch (e) {
            console.error(
                "GET /tasks/:taskId/materials/:materialId/download",
                e
            );

            return res
                .status(e.statusCode || 500)
                .json({
                    error:
                        e.message ||
                        "Failed to download material",
                });
        }
    }
);

router.delete(
    "/:taskId/materials/:materialId",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const taskId = req.params.taskId;
            const materialId =
                req.params.materialId;

            const task = await prisma.task.findUnique({
                where: {
                    id: taskId,
                },
                include: getTaskInclude(),
            });

            if (!task) {
                return res.status(404).json({
                    error: "Task not found",
                });
            }

            if (!canManageTask(req, task)) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const material =
                await prisma.taskMaterial.findUnique({
                    where: {
                        id: materialId,
                    },
                });

            if (
                !material ||
                material.taskId !== taskId
            ) {
                return res.status(404).json({
                    error: "Material not found",
                });
            }

            await prisma.taskMaterial.delete({
                where: {
                    id: materialId,
                },
            });

            await deleteFromR2(
                material.storageKey
            ).catch(() => null);

            notifyTaskChanged(
                task,
                "materials-updated"
            );

            return res.json({
                ok: true,
            });
        } catch (e) {
            console.error(
                "DELETE /tasks/:taskId/materials/:materialId",
                e
            );

            return res
                .status(e.statusCode || 500)
                .json({
                    error:
                        e.message ||
                        "Failed to delete material",
                });
        }
    }
);

router.get("/:taskId", async (req, res) => {
    try {
        const task = await prisma.task.findUnique({
            where: {
                id: req.params.taskId,
            },
            include: getTaskInclude(),
        });

        await ensureTaskAccess(req, task);

        let result = task;

        if (req.user.role === "STUDENT") {
            [result] = await attachMySubmissions(
                [task],
                getAuthUserId(req)
            );
        }

        return res.json(mapTask(result));
    } catch (e) {
        console.error("GET /tasks/:taskId", e);

        return res
            .status(e.statusCode || 500)
            .json({
                error:
                    e.message ||
                    "Failed to get task",
            });
    }
});

router.patch(
    "/:taskId",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const userId = getAuthUserId(req);
            const role = req.user.role;
            const taskId = req.params.taskId;

            const task = await prisma.task.findUnique({
                where: {
                    id: taskId,
                },
                include: getTaskInclude(),
            });

            if (!task) {
                return res.status(404).json({
                    error: "Task not found",
                });
            }

            if (!canManageTask(req, task)) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const {
                title,
                description,
                type,
                groupId,
                sessionId,
                testId,
                deadline,
                points,
                status,
                allowLateSubmission,
            } = req.body || {};

            const updates = {};

            if (title !== undefined) {
                const cleanTitle =
                    normalizeString(title);

                if (!cleanTitle) {
                    return res.status(400).json({
                        error:
                            "title cannot be empty",
                    });
                }

                updates.title = cleanTitle;
            }

            if (description !== undefined) {
                updates.description =
                    normalizeString(description);
            }

            if (deadline !== undefined) {
                updates.deadline =
                    normalizeDate(deadline);
            }

            if (points !== undefined) {
                updates.points = Math.max(
                    0,
                    normalizeNumber(points, 0)
                );
            }

            if (
                allowLateSubmission !== undefined
            ) {
                updates.allowLateSubmission =
                    normalizeBoolean(
                        allowLateSubmission,
                        false
                    );
            }

            const nextStatus =
                status !== undefined
                    ? normalizeString(status)
                    : task.status;

            if (status !== undefined) {
                if (
                    !taskStatuses.has(nextStatus)
                ) {
                    return res.status(400).json({
                        error:
                            "Invalid task status",
                    });
                }

                updates.status = nextStatus;
            }

            const nextType =
                type !== undefined
                    ? normalizeString(type)
                    : task.type;

            if (type !== undefined) {
                if (!taskTypes.has(nextType)) {
                    return res.status(400).json({
                        error:
                            "Invalid task type",
                    });
                }

                updates.type = nextType;
            }

            const changesScopeOrType =
                groupId !== undefined ||
                sessionId !== undefined ||
                type !== undefined ||
                testId !== undefined;

            if (changesScopeOrType) {
                const submissionCount =
                    await prisma.taskSubmission.count({
                        where: {
                            taskId,
                        },
                    });

                if (submissionCount > 0) {
                    return res.status(400).json({
                        error:
                            "Cannot change group/session/type/test after students submitted this task",
                    });
                }
            }

            let nextGroupId = task.groupId;
            let nextSessionId = task.sessionId;

            if (
                groupId !== undefined ||
                sessionId !== undefined
            ) {
                const scope =
                    await validateTaskScope({
                        groupId:
                            groupId !== undefined
                                ? groupId
                                : task.groupId,
                        sessionId:
                            sessionId !== undefined
                                ? sessionId
                                : task.sessionId,
                        userId,
                        role,
                    });

                nextGroupId = scope.groupId;
                nextSessionId =
                    scope.sessionId;

                updates.groupId = nextGroupId;
                updates.sessionId =
                    nextSessionId;
            }

            if (nextType === "test") {
                const nextTestId =
                    testId !== undefined
                        ? testId
                        : task.testId;

                const test =
                    await validateLinkedTest({
                        testId: nextTestId,
                        groupId: nextGroupId,
                        sessionId:
                        nextSessionId,
                        userId,
                        role,
                        status: nextStatus,
                    });

                updates.testId = test.id;
            } else if (
                type !== undefined ||
                testId !== undefined
            ) {
                updates.testId = null;
            }

            const becamePublished =
                task.status !== "published" &&
                nextStatus === "published";

            const updated =
                await prisma.task.update({
                    where: {
                        id: taskId,
                    },
                    data: updates,
                    include: getTaskInclude(),
                });

            console.log("TASK PUBLISH FLOW", {
                taskId,
                oldStatus: task.status,
                requestedStatus:
                    status !== undefined
                        ? status
                        : null,
                updatedStatus: updated.status,
                becamePublished,
            });

            notifyTaskChanged(
                updated,
                "updated"
            );

            if (becamePublished) {
                console.log(
                    "NOTIFICATION SERVICE CALLED",
                    {
                        entityType: "task",
                        entityId: updated.id,
                        groupId: updated.groupId,
                        sessionId: updated.sessionId,
                    }
                );

                try {
                    await notifyTaskPublished(updated);
                } catch (notificationError) {
                    console.error(
                        "Failed to notify students about published task",
                        notificationError
                    );
                }
            }

            return res.json(mapTask(updated));
        } catch (e) {
            console.error(
                "PATCH /tasks/:taskId",
                e
            );

            return res
                .status(e.statusCode || 500)
                .json({
                    error:
                        e.message ||
                        "Failed to update task",
                });
        }
    }
);

router.delete(
    "/:taskId",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const taskId = req.params.taskId;

            const task = await prisma.task.findUnique({
                where: {
                    id: taskId,
                },
                include: getTaskInclude(),
            });

            if (!task) {
                return res.status(404).json({
                    error: "Task not found",
                });
            }

            if (!canManageTask(req, task)) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const submissions =
                await prisma.taskSubmission.findMany({
                    where: {
                        taskId,
                    },
                    select: {
                        attachmentStorageKey: true,
                    },
                });

            await prisma.task.delete({
                where: {
                    id: taskId,
                },
            });

            const submissionKeys = submissions
                .map(
                    (submission) =>
                        submission.attachmentStorageKey
                )
                .filter(Boolean);

            const materialKeys =
                Array.isArray(task.materials)
                    ? task.materials
                        .map(
                            (material) =>
                                material.storageKey
                        )
                        .filter(Boolean)
                    : [];

            await Promise.allSettled(
                [
                    ...submissionKeys,
                    ...materialKeys,
                ].map((key) =>
                    deleteFromR2(key)
                )
            );

            notifyTaskChanged(task, "deleted");

            return res.json({
                ok: true,
            });
        } catch (e) {
            console.error(
                "DELETE /tasks/:taskId",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to delete task",
            });
        }
    }
);

router.post(
    "/:taskId/submit",
    roleMiddleware(["STUDENT"]),
    upload.single("attachment"),
    async (req, res) => {
        let uploadedStorageKey = null;

        try {
            const userId = getAuthUserId(req);
            const taskId = req.params.taskId;

            const task = await prisma.task.findUnique({
                where: {
                    id: taskId,
                },
                include: getTaskInclude(),
            });

            if (!task) {
                return res.status(404).json({
                    error: "Task not found",
                });
            }

            const allowed =
                await canStudentAccessTask(
                    req,
                    task
                );

            if (!allowed) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            if (task.status !== "published") {
                return res.status(403).json({
                    error:
                        "Task is not accepting submissions",
                });
            }

            const isLate =
                Boolean(task.deadline) &&
                task.deadline < new Date();

            if (
                isLate &&
                !task.allowLateSubmission
            ) {
                return res.status(403).json({
                    error: "Deadline has passed",
                });
            }

            if (task.type === "test") {
                return res.status(400).json({
                    error:
                        "This task is linked to a test. Submit it through /api/tests/:testId/submit",
                    testId: task.testId,
                });
            }

            const textAnswer =
                normalizeString(
                    req.body?.textAnswer
                );

            if (
                task.type === "text_answer" &&
                !textAnswer
            ) {
                return res.status(400).json({
                    error:
                        "textAnswer is required",
                });
            }

            if (
                task.type === "file_upload" &&
                !req.file
            ) {
                return res.status(400).json({
                    error:
                        "attachment file is required",
                });
            }

            if (!textAnswer && !req.file) {
                return res.status(400).json({
                    error:
                        "textAnswer or attachment is required",
                });
            }

            const existing =
                await prisma.taskSubmission.findUnique({
                    where: {
                        taskId_studentId: {
                            taskId,
                            studentId: userId,
                        },
                    },
                });

            let cleanFileName = null;

            if (req.file) {
                cleanFileName =
                    normalizeFileName(
                        req.file.originalname
                    );

                uploadedStorageKey =
                    makeStorageKey(
                        `tasks/${taskId}/submissions/${userId}`,
                        cleanFileName
                    );

                await uploadBufferToR2({
                    key: uploadedStorageKey,
                    buffer: req.file.buffer,
                    contentType:
                        req.file.mimetype ||
                        "application/octet-stream",
                });
            }

            const data = {
                status: "submitted",
                isLate,
                textAnswer,
                submittedAt: new Date(),
                score: null,
                feedback: null,
                gradedAt: null,
                gradedById: null,
            };

            if (req.file) {
                data.attachmentStorageKey =
                    uploadedStorageKey;

                data.attachmentFileName =
                    cleanFileName;

                data.attachmentMimeType =
                    req.file.mimetype ||
                    "application/octet-stream";

                data.attachmentSize =
                    req.file.size;
            }

            const submission =
                await prisma.taskSubmission.upsert({
                    where: {
                        taskId_studentId: {
                            taskId,
                            studentId: userId,
                        },
                    },
                    create: {
                        ...data,
                        taskId,
                        studentId: userId,
                    },
                    update: data,
                    include: {
                        student: {
                            select: userSelect,
                        },
                        gradedBy: {
                            select: userSelect,
                        },
                    },
                });

            if (
                req.file &&
                existing?.attachmentStorageKey &&
                existing.attachmentStorageKey !==
                uploadedStorageKey
            ) {
                await deleteFromR2(
                    existing.attachmentStorageKey
                );
            }

            notifyTaskChanged(
                task,
                "submitted"
            );

            return res
                .status(existing ? 200 : 201)
                .json(
                    mapTaskSubmission(submission)
                );
        } catch (e) {
            console.error(
                "POST /tasks/:taskId/submit",
                e
            );

            if (uploadedStorageKey) {
                await deleteFromR2(
                    uploadedStorageKey
                ).catch(() => null);
            }

            return res
                .status(e.statusCode || 500)
                .json({
                    error:
                        e.message ||
                        "Failed to submit task",
                });
        }
    }
);

router.get(
    "/:taskId/my-submission",
    roleMiddleware(["STUDENT"]),
    async (req, res) => {
        try {
            const userId = getAuthUserId(req);
            const taskId = req.params.taskId;

            const task = await prisma.task.findUnique({
                where: {
                    id: taskId,
                },
                include: getTaskInclude(),
            });

            if (!task) {
                return res.status(404).json({
                    error: "Task not found",
                });
            }

            const allowed =
                await canStudentAccessTask(
                    req,
                    task
                );

            if (!allowed) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            if (task.type === "test") {
                if (!task.testId) {
                    return res.status(404).json({
                        error:
                            "Linked test not found",
                    });
                }

                const testSubmission =
                    await prisma.testSubmission.findFirst({
                        where: {
                            testId: task.testId,
                            studentId: userId,
                        },
                        include: {
                            student: {
                                select: userSelect,
                            },
                            answers: true,
                        },
                    });

                if (!testSubmission) {
                    return res.status(404).json({
                        error:
                            "Submission not found",
                    });
                }

                return res.json({
                    type: "test",
                    submission:
                        mapTestSubmission(
                            testSubmission
                        ),
                });
            }

            const submission =
                await prisma.taskSubmission.findUnique({
                    where: {
                        taskId_studentId: {
                            taskId,
                            studentId: userId,
                        },
                    },
                    include: {
                        student: {
                            select: userSelect,
                        },
                        gradedBy: {
                            select: userSelect,
                        },
                    },
                });

            if (!submission) {
                return res.status(404).json({
                    error:
                        "Submission not found",
                });
            }

            return res.json({
                type: "task",
                submission:
                    mapTaskSubmission(submission),
            });
        } catch (e) {
            console.error(
                "GET /tasks/:taskId/my-submission",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to get submission",
            });
        }
    }
);

router.get(
    "/:taskId/submissions",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const taskId = req.params.taskId;

            const task = await prisma.task.findUnique({
                where: {
                    id: taskId,
                },
                include: getTaskInclude(),
            });

            if (!task) {
                return res.status(404).json({
                    error: "Task not found",
                });
            }

            if (!canManageTask(req, task)) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            if (task.type === "test") {
                if (!task.testId) {
                    return res.json({
                        type: "test",
                        submissions: [],
                    });
                }

                const submissions =
                    await prisma.testSubmission.findMany({
                        where: {
                            testId: task.testId,
                        },
                        include: {
                            student: {
                                select: userSelect,
                            },
                            answers: true,
                        },
                        orderBy: {
                            submittedAt: "desc",
                        },
                    });

                return res.json({
                    type: "test",
                    submissions:
                        submissions.map(
                            mapTestSubmission
                        ),
                });
            }

            const submissions =
                await prisma.taskSubmission.findMany({
                    where: {
                        taskId,
                    },
                    include: {
                        student: {
                            select: userSelect,
                        },
                        gradedBy: {
                            select: userSelect,
                        },
                    },
                    orderBy: {
                        submittedAt: "desc",
                    },
                });

            return res.json({
                type: "task",
                submissions:
                    submissions.map(
                        mapTaskSubmission
                    ),
            });
        } catch (e) {
            console.error(
                "GET /tasks/:taskId/submissions",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to get submissions",
            });
        }
    }
);

router.patch(
    "/:taskId/submissions/:submissionId/grade",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const userId = getAuthUserId(req);
            const taskId = req.params.taskId;
            const submissionId =
                req.params.submissionId;

            const {
                score,
                feedback,
            } = req.body || {};

            const task = await prisma.task.findUnique({
                where: {
                    id: taskId,
                },
                include: getTaskInclude(),
            });

            if (!task) {
                return res.status(404).json({
                    error: "Task not found",
                });
            }

            if (!canManageTask(req, task)) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            if (task.type === "test") {
                return res.status(400).json({
                    error:
                        "Test submissions are graded through the tests module",
                    testId: task.testId,
                });
            }

            const cleanScore =
                normalizeNumber(score, null);

            if (
                cleanScore === null ||
                cleanScore < 0
            ) {
                return res.status(400).json({
                    error:
                        "score must be a non-negative number",
                });
            }

            const submission =
                await prisma.taskSubmission.findUnique({
                    where: {
                        id: submissionId,
                    },
                });

            if (
                !submission ||
                submission.taskId !== taskId
            ) {
                return res.status(404).json({
                    error:
                        "Submission not found",
                });
            }

            const maxPoints = Number(
                task.points || 0
            );

            if (
                maxPoints > 0 &&
                cleanScore > maxPoints
            ) {
                return res.status(400).json({
                    error:
                        "score cannot be greater than task points",
                });
            }

            const updated =
                await prisma.taskSubmission.update({
                    where: {
                        id: submissionId,
                    },
                    data: {
                        status: "graded",
                        score: cleanScore,
                        feedback:
                            normalizeString(
                                feedback
                            ),
                        gradedAt: new Date(),
                        gradedById: userId,
                    },
                    include: {
                        student: {
                            select: userSelect,
                        },
                        gradedBy: {
                            select: userSelect,
                        },
                    },
                });

            notifyTaskChanged(
                task,
                "graded"
            );

            return res.json(
                mapTaskSubmission(updated)
            );
        } catch (e) {
            console.error(
                "PATCH /tasks/:taskId/submissions/:submissionId/grade",
                e
            );

            return res
                .status(e.statusCode || 500)
                .json({
                    error:
                        e.message ||
                        "Failed to grade submission",
                });
        }
    }
);

export default router;