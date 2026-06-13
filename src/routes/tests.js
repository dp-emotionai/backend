import express from "express";
import multer from "multer";
import prisma from "../utils/prisma.js";
import authMiddleware from "../middleware/authMiddleware.js";
import roleMiddleware from "../middleware/roleMiddleware.js";
import { broadcastGroupEvent, broadcastSessionEvent } from "../socket/server.js";
import { notifyTestPublished } from "../services/testNotifications.js";
import {
    makeStorageKey,
    uploadBufferToR2,
    getObjectFromR2,
    deleteFromR2,
} from "../utils/r2.js";

const router = express.Router();

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: Number(process.env.TEST_IMAGE_MAX_BYTES || 10 * 1024 * 1024),
    },
    fileFilter: (_req, file, cb) => {
        if (!String(file.mimetype || "").startsWith("image/")) {
            cb(new Error("Only image uploads are allowed"));
            return;
        }

        cb(null, true);
    },
});

const userSelect = {
    id: true,
    email: true,
    firstName: true,
    lastName: true,
};

const questionTypes = new Set(["single_choice", "multiple_choice", "text"]);
const testStatuses = new Set(["draft", "published", "closed"]);

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

const normalizeBoolean = (value, fallback = false) => {
    if (value === undefined || value === null) return fallback;
    if (typeof value === "boolean") return value;
    return String(value).toLowerCase() === "true";
};

const normalizeDate = (value) => {
    if (value === undefined || value === null || value === "") return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
};

const normalizeQuestionType = (value) => {
    const type = normalizeString(value) || "single_choice";
    return questionTypes.has(type) ? type : "single_choice";
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

const mapOption = (option, includeCorrect = false) => ({
    id: option.id,
    questionId: option.questionId,
    text: option.text,
    imageStorageKey: option.imageStorageKey,
    imageUrl: option.imageStorageKey ? `/api/tests/options/${option.id}/image` : null,
    order: option.order,
    ...(includeCorrect ? { isCorrect: option.isCorrect } : {}),
    createdAt: option.createdAt,
    updatedAt: option.updatedAt,
});

const mapQuestion = (question, includeCorrect = false) => ({
    id: question.id,
    testId: question.testId,
    type: question.type,
    text: question.text,
    imageStorageKey: question.imageStorageKey,
    imageUrl: question.imageStorageKey ? `/api/tests/questions/${question.id}/image` : null,
    points: question.points,
    order: question.order,
    explanation: includeCorrect ? question.explanation : undefined,
    options: Array.isArray(question.options)
        ? question.options.map((option) => mapOption(option, includeCorrect))
        : [],
    createdAt: question.createdAt,
    updatedAt: question.updatedAt,
});

const mapTest = (test, includeCorrect = false) => ({
    id: test.id,
    title: test.title,
    description: test.description,
    groupId: test.groupId,
    sessionId: test.sessionId,
    status: test.status,
    timeLimitMinutes: test.timeLimitMinutes,
    attemptsAllowed: test.attemptsAllowed,
    shuffleQuestions: test.shuffleQuestions,
    shuffleOptions: test.shuffleOptions,
    startsAt: test.startsAt,
    endsAt: test.endsAt,
    createdById: test.createdById,
    createdBy: mapUser(test.createdBy),
    createdAt: test.createdAt,
    updatedAt: test.updatedAt,
    questions: Array.isArray(test.questions)
        ? test.questions.map((question) => mapQuestion(question, includeCorrect))
        : undefined,
});

const mapSubmission = (submission, includeAnswers = true) => ({
    id: submission.id,
    testId: submission.testId,
    studentId: submission.studentId,
    student: mapUser(submission.student),
    status: submission.status,
    score: submission.score,
    maxScore: submission.maxScore,
    startedAt: submission.startedAt,
    submittedAt: submission.submittedAt,
    answers: includeAnswers ? submission.answers : undefined,
});

const canManageTest = (req, test) => {
    const userId = getAuthUserId(req);
    const role = req.user?.role;

    return role === "ADMIN" || test.createdById === userId;
};

const countSubmissions = async (testId) => {
    return prisma.testSubmission.count({
        where: { testId },
    });
};

const assertNoSubmissions = async (testId) => {
    const submissionCount = await countSubmissions(testId);

    if (submissionCount > 0) {
        const error = new Error(
            "Cannot edit questions/options after students submitted this test"
        );
        error.statusCode = 400;
        throw error;
    }
};

const validateTestScope = async ({ groupId, sessionId, userId, role }) => {
    let validatedGroupId = normalizeString(groupId);
    let validatedSessionId = normalizeString(sessionId);

    if (!validatedGroupId && !validatedSessionId) {
        const error = new Error("groupId or sessionId is required");
        error.statusCode = 400;
        throw error;
    }

    let group = null;
    let session = null;

    if (validatedGroupId) {
        group = await prisma.group.findUnique({
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
        session = await prisma.session.findUnique({
            where: { id: validatedSessionId },
        });

        if (!session) {
            const error = new Error("Session not found");
            error.statusCode = 404;
            throw error;
        }

        if (role !== "ADMIN" && session.createdById !== userId) {
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

const canStudentAccessTest = async (req, test) => {
    const userId = getAuthUserId(req);
    const role = req.user?.role;

    if (role === "ADMIN" || test.createdById === userId) {
        return true;
    }

    if (role !== "STUDENT") {
        return false;
    }

    if (test.status !== "published") {
        return false;
    }

    const groupId = test.session?.groupId || test.groupId;

    if (!groupId) {
        return false;
    }

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

const checkTestDateAvailable = (test) => {
    const now = new Date();

    if (test.startsAt && test.startsAt > now) {
        const error = new Error("Test is not started yet");
        error.statusCode = 403;
        throw error;
    }

    if (test.endsAt && test.endsAt < now) {
        const error = new Error("Test is already ended");
        error.statusCode = 403;
        throw error;
    }
};

const validateTestBeforePublish = async (testId) => {
    const questions = await prisma.testQuestion.findMany({
        where: { testId },
        include: {
            options: {
                orderBy: { order: "asc" },
            },
        },
        orderBy: { order: "asc" },
    });

    if (questions.length === 0) {
        const error = new Error(
            "Test must have at least one question"
        );
        error.statusCode = 400;
        throw error;
    }

    for (const question of questions) {
        if (!normalizeString(question.text)) {
            const error = new Error(
                "Every question must have text"
            );
            error.statusCode = 400;
            throw error;
        }

        if (
            question.type === "single_choice" ||
            question.type === "multiple_choice"
        ) {
            if (question.options.length < 2) {
                const error = new Error(
                    "Choice question must have at least 2 options"
                );
                error.statusCode = 400;
                throw error;
            }

            const correctCount =
                question.options.filter(
                    (option) => option.isCorrect
                ).length;

            if (
                question.type === "single_choice" &&
                correctCount !== 1
            ) {
                const error = new Error(
                    "Single choice question must have exactly one correct option"
                );
                error.statusCode = 400;
                throw error;
            }

            if (
                question.type === "multiple_choice" &&
                correctCount < 1
            ) {
                const error = new Error(
                    "Multiple choice question must have at least one correct option"
                );
                error.statusCode = 400;
                throw error;
            }
        }
    }
};

const deleteQuestionImages = async (question) => {
    if (question.imageStorageKey) {
        await deleteFromR2(
            question.imageStorageKey
        );
    }

    if (Array.isArray(question.options)) {
        for (const option of question.options) {
            if (option.imageStorageKey) {
                await deleteFromR2(
                    option.imageStorageKey
                );
            }
        }
    }
};

router.use(authMiddleware);

router.post(
    "/upload-image",
    roleMiddleware(["TEACHER", "ADMIN"]),
    upload.single("image"),
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({
                    error: "image is required",
                });
            }

            const userId =
                getAuthUserId(req);

            const storageKey =
                makeStorageKey(
                    `tests/images/${userId}`,
                    req.file.originalname
                );

            await uploadBufferToR2({
                key: storageKey,
                buffer: req.file.buffer,
                contentType:
                    req.file.mimetype ||
                    "application/octet-stream",
            });

            return res.status(201).json({
                storageKey,
                fileName:
                req.file.originalname,
                mimeType:
                req.file.mimetype,
                size: req.file.size,
            });
        } catch (e) {
            console.error(
                "POST /tests/upload-image",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to upload image",
            });
        }
    }
);

router.get(
    "/questions/:questionId/image",
    async (req, res) => {
        try {
            const question =
                await prisma.testQuestion.findUnique({
                    where: {
                        id: req.params.questionId,
                    },
                    include: {
                        test: {
                            include: {
                                session: true,
                            },
                        },
                    },
                });

            if (
                !question ||
                !question.imageStorageKey
            ) {
                return res.status(404).json({
                    error: "Image not found",
                });
            }

            const allowed =
                canManageTest(
                    req,
                    question.test
                ) ||
                (await canStudentAccessTest(
                    req,
                    question.test
                ));

            if (!allowed) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const object =
                await getObjectFromR2(
                    question.imageStorageKey
                );

            if (!object.Body) {
                return res.status(404).json({
                    error:
                        "Image body not found",
                });
            }

            const bytes =
                await object.Body.transformToByteArray();

            res.setHeader(
                "Content-Type",
                object.ContentType ||
                "image/jpeg"
            );

            res.setHeader(
                "Cache-Control",
                "private, max-age=300"
            );

            if (object.ETag) {
                res.setHeader(
                    "ETag",
                    object.ETag
                );
            }

            return res
                .status(200)
                .send(Buffer.from(bytes));
        } catch (e) {
            console.error(
                "GET /tests/questions/:questionId/image",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to get question image",
            });
        }
    }
);

router.get(
    "/options/:optionId/image",
    async (req, res) => {
        try {
            const option =
                await prisma.testOption.findUnique({
                    where: {
                        id: req.params.optionId,
                    },
                    include: {
                        question: {
                            include: {
                                test: {
                                    include: {
                                        session: true,
                                    },
                                },
                            },
                        },
                    },
                });

            if (
                !option ||
                !option.imageStorageKey
            ) {
                return res.status(404).json({
                    error: "Image not found",
                });
            }

            const test =
                option.question.test;

            const allowed =
                canManageTest(req, test) ||
                (await canStudentAccessTest(
                    req,
                    test
                ));

            if (!allowed) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const object =
                await getObjectFromR2(
                    option.imageStorageKey
                );

            if (!object.Body) {
                return res.status(404).json({
                    error:
                        "Image body not found",
                });
            }

            const bytes =
                await object.Body.transformToByteArray();

            res.setHeader(
                "Content-Type",
                object.ContentType ||
                "image/jpeg"
            );

            res.setHeader(
                "Cache-Control",
                "private, max-age=300"
            );

            if (object.ETag) {
                res.setHeader(
                    "ETag",
                    object.ETag
                );
            }

            return res
                .status(200)
                .send(Buffer.from(bytes));
        } catch (e) {
            console.error(
                "GET /tests/options/:optionId/image",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to get option image",
            });
        }
    }
);

router.get(
    "/",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const userId =
                getAuthUserId(req);

            const role =
                req.user.role;

            const status =
                normalizeString(
                    req.query.status
                );

            const groupId =
                normalizeString(
                    req.query.groupId
                );

            const sessionId =
                normalizeString(
                    req.query.sessionId
                );

            const tests =
                await prisma.test.findMany({
                    where: {
                        ...(role === "ADMIN"
                            ? {}
                            : {
                                createdById:
                                userId,
                            }),
                        ...(status &&
                        testStatuses.has(
                            status
                        )
                            ? { status }
                            : {}),
                        ...(groupId
                            ? { groupId }
                            : {}),
                        ...(sessionId
                            ? { sessionId }
                            : {}),
                    },
                    include: {
                        createdBy: {
                            select:
                            userSelect,
                        },
                        _count: {
                            select: {
                                questions:
                                    true,
                                submissions:
                                    true,
                            },
                        },
                    },
                    orderBy: {
                        createdAt: "desc",
                    },
                });

            return res.json(
                tests.map((test) => ({
                    ...mapTest(
                        test,
                        true
                    ),
                    questionCount:
                    test._count
                        .questions,
                    submissionCount:
                    test._count
                        .submissions,
                }))
            );
        } catch (e) {
            console.error(
                "GET /tests",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to get tests",
            });
        }
    }
);

router.post(
    "/",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const userId =
                getAuthUserId(req);

            const role =
                req.user.role;

            const {
                title,
                description,
                groupId,
                sessionId,
                timeLimitMinutes,
                attemptsAllowed,
                shuffleQuestions,
                shuffleOptions,
                startsAt,
                endsAt,
            } = req.body || {};

            if (
                !title ||
                !String(title).trim()
            ) {
                return res.status(400).json({
                    error:
                        "title is required",
                });
            }

            const scope =
                await validateTestScope({
                    groupId,
                    sessionId,
                    userId,
                    role,
                });

            const test =
                await prisma.test.create({
                    data: {
                        title: String(
                            title
                        ).trim(),
                        description:
                            normalizeString(
                                description
                            ),
                        groupId:
                        scope.groupId,
                        sessionId:
                        scope.sessionId,
                        createdById:
                        userId,
                        status: "draft",
                        timeLimitMinutes:
                            normalizeNumber(
                                timeLimitMinutes
                            ),
                        attemptsAllowed:
                            Math.max(
                                1,
                                normalizeNumber(
                                    attemptsAllowed,
                                    1
                                )
                            ),
                        shuffleQuestions:
                            normalizeBoolean(
                                shuffleQuestions,
                                false
                            ),
                        shuffleOptions:
                            normalizeBoolean(
                                shuffleOptions,
                                false
                            ),
                        startsAt:
                            normalizeDate(
                                startsAt
                            ),
                        endsAt:
                            normalizeDate(
                                endsAt
                            ),
                    },
                    include: {
                        createdBy: {
                            select:
                            userSelect,
                        },
                        questions: {
                            include: {
                                options:
                                    true,
                            },
                            orderBy: {
                                order: "asc",
                            },
                        },
                    },
                });

            return res
                .status(201)
                .json(
                    mapTest(test, true)
                );
        } catch (e) {
            console.error(
                "POST /tests",
                e
            );

            return res
                .status(
                    e.statusCode || 500
                )
                .json({
                    error:
                        e.message ||
                        "Failed to create test",
                });
        }
    }
);

router.get(
    "/student/available",
    roleMiddleware(["STUDENT"]),
    async (req, res) => {
        try {
            const userId =
                getAuthUserId(req);

            const groupId =
                normalizeString(
                    req.query.groupId
                );

            const sessionId =
                normalizeString(
                    req.query.sessionId
                );

            const now = new Date();

            const memberships =
                await prisma.groupMember.findMany({
                    where: {
                        userId,
                    },
                    select: {
                        groupId: true,
                    },
                });

            const groupIds =
                memberships.map(
                    (membership) =>
                        membership.groupId
                );

            if (
                groupId &&
                !groupIds.includes(groupId)
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            let session = null;

            if (sessionId) {
                session =
                    await prisma.session.findUnique({
                        where: {
                            id: sessionId,
                        },
                        select: {
                            id: true,
                            groupId: true,
                        },
                    });

                if (!session) {
                    return res.status(404).json({
                        error:
                            "Session not found",
                    });
                }

                if (
                    !groupIds.includes(
                        session.groupId
                    )
                ) {
                    return res.status(403).json({
                        error:
                            "Forbidden",
                    });
                }
            }

            const tests =
                await prisma.test.findMany({
                    where: {
                        status:
                            "published",
                        AND: [
                            {
                                OR: [
                                    {
                                        startsAt:
                                            null,
                                    },
                                    {
                                        startsAt: {
                                            lte: now,
                                        },
                                    },
                                ],
                            },
                            {
                                OR: [
                                    {
                                        endsAt:
                                            null,
                                    },
                                    {
                                        endsAt: {
                                            gte: now,
                                        },
                                    },
                                ],
                            },
                            sessionId
                                ? {
                                    OR: [
                                        {
                                            sessionId,
                                        },
                                        {
                                            groupId:
                                            session.groupId,
                                            sessionId:
                                                null,
                                        },
                                    ],
                                }
                                : groupId
                                    ? {
                                        groupId,
                                    }
                                    : {
                                        OR: [
                                            {
                                                groupId: {
                                                    in: groupIds,
                                                },
                                            },
                                            {
                                                session: {
                                                    is: {
                                                        groupId: {
                                                            in: groupIds,
                                                        },
                                                    },
                                                },
                                            },
                                        ],
                                    },
                        ],
                    },
                    include: {
                        createdBy: {
                            select:
                            userSelect,
                        },
                        _count: {
                            select: {
                                questions:
                                    true,
                                submissions:
                                    true,
                            },
                        },
                    },
                    orderBy: {
                        createdAt: "desc",
                    },
                });

            return res.json(
                tests.map((test) => ({
                    id: test.id,
                    title: test.title,
                    description:
                    test.description,
                    groupId:
                    test.groupId,
                    sessionId:
                    test.sessionId,
                    status: test.status,
                    timeLimitMinutes:
                    test.timeLimitMinutes,
                    attemptsAllowed:
                    test.attemptsAllowed,
                    startsAt:
                    test.startsAt,
                    endsAt: test.endsAt,
                    createdBy:
                        mapUser(
                            test.createdBy
                        ),
                    questionCount:
                    test._count
                        .questions,
                    createdAt:
                    test.createdAt,
                    updatedAt:
                    test.updatedAt,
                }))
            );
        } catch (e) {
            console.error(
                "GET /tests/student/available",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to get available tests",
            });
        }
    }
);

router.get(
    "/student/:testId",
    roleMiddleware(["STUDENT"]),
    async (req, res) => {
        try {
            const test =
                await prisma.test.findUnique({
                    where: {
                        id: req.params.testId,
                    },
                    include: {
                        createdBy: {
                            select:
                            userSelect,
                        },
                        session: true,
                        questions: {
                            include: {
                                options: {
                                    orderBy: {
                                        order:
                                            "asc",
                                    },
                                },
                            },
                            orderBy: {
                                order: "asc",
                            },
                        },
                    },
                });

            if (!test) {
                return res.status(404).json({
                    error:
                        "Test not found",
                });
            }

            const allowed =
                await canStudentAccessTest(
                    req,
                    test
                );

            if (!allowed) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            checkTestDateAvailable(test);

            return res.json(
                mapTest(test, false)
            );
        } catch (e) {
            console.error(
                "GET /tests/student/:testId",
                e
            );

            return res
                .status(
                    e.statusCode || 500
                )
                .json({
                    error:
                        e.message ||
                        "Failed to get test",
                });
        }
    }
);

router.get(
    "/:testId/my-result",
    roleMiddleware(["STUDENT"]),
    async (req, res) => {
        try {
            const userId =
                getAuthUserId(req);

            const submission =
                await prisma.testSubmission.findFirst({
                    where: {
                        testId:
                        req.params.testId,
                        studentId:
                        userId,
                    },
                    include: {
                        student: {
                            select:
                            userSelect,
                        },
                        answers: true,
                    },
                    orderBy: {
                        submittedAt:
                            "desc",
                    },
                });

            if (!submission) {
                return res.status(404).json({
                    error:
                        "Submission not found",
                });
            }

            return res.json(
                mapSubmission(
                    submission,
                    true
                )
            );
        } catch (e) {
            console.error(
                "GET /tests/:testId/my-result",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to get result",
            });
        }
    }
);

router.post(
    "/:testId/submit",
    roleMiddleware(["STUDENT"]),
    async (req, res) => {
        try {
            const userId =
                getAuthUserId(req);

            const testId =
                req.params.testId;

            const { answers } =
            req.body || {};

            if (!Array.isArray(answers)) {
                return res.status(400).json({
                    error:
                        "answers array is required",
                });
            }

            const test =
                await prisma.test.findUnique({
                    where: {
                        id: testId,
                    },
                    include: {
                        session: true,
                        questions: {
                            include: {
                                options:
                                    true,
                            },
                            orderBy: {
                                order: "asc",
                            },
                        },
                    },
                });

            if (!test) {
                return res.status(404).json({
                    error:
                        "Test not found",
                });
            }

            const allowed =
                await canStudentAccessTest(
                    req,
                    test
                );

            if (!allowed) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            checkTestDateAvailable(test);

            const existing =
                await prisma.testSubmission.findFirst({
                    where: {
                        testId,
                        studentId:
                        userId,
                    },
                });

            if (existing) {
                return res.status(400).json({
                    error:
                        "You have already submitted this test",
                });
            }

            const answersMap =
                new Map(
                    answers.map(
                        (answer) => [
                            String(
                                answer.questionId
                            ),
                            answer,
                        ]
                    )
                );

            let score = 0;
            let maxScore = 0;
            const answerRows = [];

            for (
                const question of
                test.questions
                ) {
                const userAnswer =
                    answersMap.get(
                        question.id
                    );

                const questionPoints =
                    Number(
                        question.points ||
                        0
                    );

                maxScore +=
                    questionPoints;

                if (
                    question.type ===
                    "text"
                ) {
                    answerRows.push({
                        questionId:
                        question.id,
                        selectedOptionIds:
                            null,
                        textAnswer:
                            normalizeString(
                                userAnswer?.textAnswer
                            ),
                        isCorrect: null,
                        pointsEarned: 0,
                    });

                    continue;
                }

                const selectedOptionIds =
                    Array.isArray(
                        userAnswer?.selectedOptionIds
                    )
                        ? userAnswer.selectedOptionIds.map(
                            (id) =>
                                String(id)
                        )
                        : [];

                if (
                    question.type ===
                    "single_choice" &&
                    selectedOptionIds.length >
                    1
                ) {
                    return res.status(400).json({
                        error:
                            `Question ${question.id} accepts only one selected option`,
                    });
                }

                const optionIds =
                    new Set(
                        question.options.map(
                            (option) =>
                                option.id
                        )
                    );

                for (
                    const selectedOptionId of
                    selectedOptionIds
                    ) {
                    if (
                        !optionIds.has(
                            selectedOptionId
                        )
                    ) {
                        return res.status(400).json({
                            error:
                                `Selected option ${selectedOptionId} does not belong to question ${question.id}`,
                        });
                    }
                }

                const correctIds =
                    question.options
                        .filter(
                            (option) =>
                                option.isCorrect
                        )
                        .map(
                            (option) =>
                                option.id
                        )
                        .sort();

                const selectedSorted = [
                    ...selectedOptionIds,
                ].sort();

                const isCorrect =
                    correctIds.length ===
                    selectedSorted.length &&
                    correctIds.every(
                        (id, index) =>
                            id ===
                            selectedSorted[
                                index
                                ]
                    );

                const pointsEarned =
                    isCorrect
                        ? questionPoints
                        : 0;

                score += pointsEarned;

                answerRows.push({
                    questionId:
                    question.id,
                    selectedOptionIds,
                    textAnswer: null,
                    isCorrect,
                    pointsEarned,
                });
            }

            const submission =
                await prisma.$transaction(
                    async (tx) => {
                        const created =
                            await tx.testSubmission.create({
                                data: {
                                    testId,
                                    studentId:
                                    userId,
                                    status:
                                        "submitted",
                                    score,
                                    maxScore,
                                    submittedAt:
                                        new Date(),
                                },
                            });

                        for (
                            const answerRow of
                            answerRows
                            ) {
                            await tx.testAnswer.create({
                                data: {
                                    submissionId:
                                    created.id,
                                    questionId:
                                    answerRow.questionId,
                                    selectedOptionIds:
                                    answerRow.selectedOptionIds,
                                    textAnswer:
                                    answerRow.textAnswer,
                                    isCorrect:
                                    answerRow.isCorrect,
                                    pointsEarned:
                                    answerRow.pointsEarned,
                                },
                            });
                        }

                        return tx.testSubmission.findUnique({
                            where: {
                                id: created.id,
                            },
                            include: {
                                student: {
                                    select:
                                    userSelect,
                                },
                                answers:
                                    true,
                            },
                        });
                    }
                );

            return res
                .status(201)
                .json(
                    mapSubmission(
                        submission,
                        true
                    )
                );
        } catch (e) {
            console.error(
                "POST /tests/:testId/submit",
                e
            );

            if (e.code === "P2002") {
                return res.status(400).json({
                    error:
                        "You have already submitted this test",
                });
            }

            return res
                .status(
                    e.statusCode || 500
                )
                .json({
                    error:
                        e.message ||
                        "Failed to submit test",
                });
        }
    }
);

router.get(
    "/:testId",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const test =
                await prisma.test.findUnique({
                    where: {
                        id: req.params.testId,
                    },
                    include: {
                        createdBy: {
                            select:
                            userSelect,
                        },
                        questions: {
                            include: {
                                options: {
                                    orderBy: {
                                        order:
                                            "asc",
                                    },
                                },
                            },
                            orderBy: {
                                order: "asc",
                            },
                        },
                    },
                });

            if (!test) {
                return res.status(404).json({
                    error:
                        "Test not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            return res.json(
                mapTest(test, true)
            );
        } catch (e) {
            console.error(
                "GET /tests/:testId",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to get test",
            });
        }
    }
);

router.patch(
    "/:testId",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const testId =
                req.params.testId;

            const userId =
                getAuthUserId(req);

            const role =
                req.user.role;

            const test =
                await prisma.test.findUnique({
                    where: {
                        id: testId,
                    },
                });

            if (!test) {
                return res.status(404).json({
                    error:
                        "Test not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const {
                title,
                description,
                groupId,
                sessionId,
                status,
                timeLimitMinutes,
                attemptsAllowed,
                shuffleQuestions,
                shuffleOptions,
                startsAt,
                endsAt,
            } = req.body || {};

            const updates = {};

            if (title !== undefined) {
                updates.title =
                    String(title).trim();
            }

            if (
                description !== undefined
            ) {
                updates.description =
                    normalizeString(
                        description
                    );
            }

            if (
                timeLimitMinutes !==
                undefined
            ) {
                updates.timeLimitMinutes =
                    normalizeNumber(
                        timeLimitMinutes
                    );
            }

            if (
                attemptsAllowed !==
                undefined
            ) {
                updates.attemptsAllowed =
                    Math.max(
                        1,
                        normalizeNumber(
                            attemptsAllowed,
                            1
                        )
                    );
            }

            if (
                shuffleQuestions !==
                undefined
            ) {
                updates.shuffleQuestions =
                    normalizeBoolean(
                        shuffleQuestions,
                        test.shuffleQuestions
                    );
            }

            if (
                shuffleOptions !==
                undefined
            ) {
                updates.shuffleOptions =
                    normalizeBoolean(
                        shuffleOptions,
                        test.shuffleOptions
                    );
            }

            if (startsAt !== undefined) {
                updates.startsAt =
                    normalizeDate(startsAt);
            }

            if (endsAt !== undefined) {
                updates.endsAt =
                    normalizeDate(endsAt);
            }

            let becamePublished = false;

            if (status !== undefined) {
                const cleanStatus =
                    normalizeString(status);

                if (
                    !testStatuses.has(
                        cleanStatus
                    )
                ) {
                    return res.status(400).json({
                        error:
                            "Invalid status",
                    });
                }

                becamePublished =
                    test.status !==
                    "published" &&
                    cleanStatus ===
                    "published";

                if (becamePublished) {
                    await validateTestBeforePublish(
                        testId
                    );
                }

                updates.status =
                    cleanStatus;
            }

            if (
                groupId !== undefined ||
                sessionId !== undefined
            ) {
                const submissionCount =
                    await countSubmissions(
                        testId
                    );

                if (
                    submissionCount > 0
                ) {
                    return res.status(400).json({
                        error:
                            "Cannot change group/session after students submitted this test",
                    });
                }

                const scope =
                    await validateTestScope({
                        groupId:
                            groupId !==
                            undefined
                                ? groupId
                                : test.groupId,
                        sessionId:
                            sessionId !==
                            undefined
                                ? sessionId
                                : test.sessionId,
                        userId,
                        role,
                    });

                updates.groupId =
                    scope.groupId;

                updates.sessionId =
                    scope.sessionId;
            }

            const updated =
                await prisma.test.update({
                    where: {
                        id: testId,
                    },
                    data: updates,
                    include: {
                        createdBy: {
                            select:
                            userSelect,
                        },
                        questions: {
                            include: {
                                options: {
                                    orderBy: {
                                        order:
                                            "asc",
                                    },
                                },
                            },
                            orderBy: {
                                order: "asc",
                            },
                        },
                    },
                });

            console.log("TEST PUBLISH FLOW", {
                testId,
                oldStatus: test.status,
                requestedStatus:
                    status !== undefined
                        ? status
                        : null,
                updatedStatus: updated.status,
                becamePublished,
            });

            if (becamePublished) {
                console.log(
                    "NOTIFICATION SERVICE CALLED",
                    {
                        entityType: "test",
                        entityId: updated.id,
                        groupId: updated.groupId,
                        sessionId: updated.sessionId,
                    }
                );

                try {
                    await notifyTestPublished(
                        updated
                    );
                } catch (
                    notificationError
                    ) {
                    console.error(
                        "PATCH /tests/:testId notification error",
                        notificationError
                    );
                }
            }

            return res.json(
                mapTest(updated, true)
            );
        } catch (e) {
            console.error(
                "PATCH /tests/:testId",
                e
            );

            return res
                .status(
                    e.statusCode || 500
                )
                .json({
                    error:
                        e.message ||
                        "Failed to update test",
                });
        }
    }
);

router.post(
    "/:testId/publish",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const testId =
                req.params.testId;

            const test =
                await prisma.test.findUnique({
                    where: {
                        id: testId,
                    },
                });

            if (!test) {
                return res.status(404).json({
                    error:
                        "Test not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const becamePublished =
                test.status !==
                "published";

            await validateTestBeforePublish(
                testId
            );

            const updated =
                await prisma.test.update({
                    where: {
                        id: testId,
                    },
                    data: {
                        status:
                            "published",
                    },
                    include: {
                        createdBy: {
                            select:
                            userSelect,
                        },
                        questions: {
                            include: {
                                options: {
                                    orderBy: {
                                        order:
                                            "asc",
                                    },
                                },
                            },
                            orderBy: {
                                order: "asc",
                            },
                        },
                    },
                });

            try {
                const event = {
                    type: "test.published",
                    testId:
                    updated.id,
                    groupId:
                    updated.groupId,
                    sessionId:
                    updated.sessionId,
                    title:
                    updated.title,
                };

                if (updated.groupId) {
                    broadcastGroupEvent(
                        updated.groupId,
                        event
                    );
                }

                if (
                    updated.sessionId
                ) {
                    broadcastSessionEvent(
                        updated.sessionId,
                        event
                    );
                }
            } catch (wsError) {
                console.error(
                    "POST /tests/:testId/publish broadcast error",
                    wsError
                );
            }

            console.log("TEST PUBLISH FLOW", {
                testId,
                oldStatus: test.status,
                requestedStatus: "published",
                updatedStatus: updated.status,
                becamePublished,
            });

            if (becamePublished) {
                console.log(
                    "NOTIFICATION SERVICE CALLED",
                    {
                        entityType: "test",
                        entityId: updated.id,
                        groupId: updated.groupId,
                        sessionId: updated.sessionId,
                    }
                );

                try {
                    await notifyTestPublished(
                        updated
                    );
                } catch (
                    notificationError
                    ) {
                    console.error(
                        "POST /tests/:testId/publish notification error",
                        notificationError
                    );
                }
            }

            return res.json(
                mapTest(updated, true)
            );
        } catch (e) {
            console.error(
                "POST /tests/:testId/publish",
                e
            );

            return res
                .status(
                    e.statusCode || 500
                )
                .json({
                    error:
                        e.message ||
                        "Failed to publish test",
                });
        }
    }
);

router.post(
    "/:testId/close",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const test =
                await prisma.test.findUnique({
                    where: {
                        id: req.params.testId,
                    },
                });

            if (!test) {
                return res.status(404).json({
                    error:
                        "Test not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const updated =
                await prisma.test.update({
                    where: {
                        id: test.id,
                    },
                    data: {
                        status: "closed",
                    },
                    include: {
                        createdBy: {
                            select:
                            userSelect,
                        },
                        questions: {
                            include: {
                                options: {
                                    orderBy: {
                                        order:
                                            "asc",
                                    },
                                },
                            },
                            orderBy: {
                                order: "asc",
                            },
                        },
                    },
                });

            return res.json(
                mapTest(updated, true)
            );
        } catch (e) {
            console.error(
                "POST /tests/:testId/close",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to close test",
            });
        }
    }
);

router.delete(
    "/:testId",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const test =
                await prisma.test.findUnique({
                    where: {
                        id: req.params.testId,
                    },
                    include: {
                        questions: {
                            include: {
                                options:
                                    true,
                            },
                        },
                    },
                });

            if (!test) {
                return res.status(404).json({
                    error:
                        "Test not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            for (
                const question of
                test.questions
                ) {
                await deleteQuestionImages(
                    question
                );
            }

            await prisma.test.delete({
                where: {
                    id: test.id,
                },
            });

            return res.json({
                ok: true,
                id: test.id,
            });
        } catch (e) {
            console.error(
                "DELETE /tests/:testId",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to delete test",
            });
        }
    }
);

router.post(
    "/:testId/questions",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const testId =
                req.params.testId;

            const {
                type,
                text,
                imageStorageKey,
                points,
                order,
                explanation,
                options,
            } = req.body || {};

            const test =
                await prisma.test.findUnique({
                    where: {
                        id: testId,
                    },
                });

            if (!test) {
                return res.status(404).json({
                    error:
                        "Test not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            await assertNoSubmissions(
                testId
            );

            if (
                !text ||
                !String(text).trim()
            ) {
                return res.status(400).json({
                    error:
                        "question text is required",
                });
            }

            const cleanType =
                normalizeQuestionType(type);

            const question =
                await prisma.$transaction(
                    async (tx) => {
                        const createdQuestion =
                            await tx.testQuestion.create({
                                data: {
                                    testId,
                                    type:
                                    cleanType,
                                    text: String(
                                        text
                                    ).trim(),
                                    imageStorageKey:
                                        normalizeString(
                                            imageStorageKey
                                        ),
                                    points:
                                        Math.max(
                                            0,
                                            normalizeNumber(
                                                points,
                                                1
                                            )
                                        ),
                                    order:
                                        normalizeNumber(
                                            order,
                                            0
                                        ),
                                    explanation:
                                        normalizeString(
                                            explanation
                                        ),
                                },
                            });

                        if (
                            Array.isArray(
                                options
                            ) &&
                            cleanType !==
                            "text"
                        ) {
                            for (
                                let index = 0;
                                index <
                                options.length;
                                index += 1
                            ) {
                                const option =
                                    options[
                                        index
                                        ];

                                await tx.testOption.create({
                                    data: {
                                        questionId:
                                        createdQuestion.id,
                                        text:
                                            normalizeString(
                                                option.text
                                            ),
                                        imageStorageKey:
                                            normalizeString(
                                                option.imageStorageKey
                                            ),
                                        isCorrect:
                                            normalizeBoolean(
                                                option.isCorrect,
                                                false
                                            ),
                                        order:
                                            normalizeNumber(
                                                option.order,
                                                index
                                            ),
                                    },
                                });
                            }
                        }

                        return tx.testQuestion.findUnique({
                            where: {
                                id: createdQuestion.id,
                            },
                            include: {
                                options: {
                                    orderBy: {
                                        order:
                                            "asc",
                                    },
                                },
                            },
                        });
                    }
                );

            return res
                .status(201)
                .json(
                    mapQuestion(
                        question,
                        true
                    )
                );
        } catch (e) {
            console.error(
                "POST /tests/:testId/questions",
                e
            );

            return res
                .status(
                    e.statusCode || 500
                )
                .json({
                    error:
                        e.message ||
                        "Failed to create question",
                });
        }
    }
);

router.patch(
    "/:testId/questions/:questionId",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const {
                testId,
                questionId,
            } = req.params;

            const question =
                await prisma.testQuestion.findUnique({
                    where: {
                        id: questionId,
                    },
                    include: {
                        test: true,
                    },
                });

            if (
                !question ||
                question.testId !== testId
            ) {
                return res.status(404).json({
                    error:
                        "Question not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    question.test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            await assertNoSubmissions(
                testId
            );

            const {
                type,
                text,
                imageStorageKey,
                points,
                order,
                explanation,
            } = req.body || {};

            const updates = {};

            if (type !== undefined) {
                updates.type =
                    normalizeQuestionType(
                        type
                    );
            }

            if (text !== undefined) {
                updates.text =
                    String(text).trim();
            }

            if (
                imageStorageKey !==
                undefined
            ) {
                updates.imageStorageKey =
                    normalizeString(
                        imageStorageKey
                    );
            }

            if (points !== undefined) {
                updates.points =
                    Math.max(
                        0,
                        normalizeNumber(
                            points,
                            question.points
                        )
                    );
            }

            if (order !== undefined) {
                updates.order =
                    normalizeNumber(
                        order,
                        question.order
                    );
            }

            if (
                explanation !== undefined
            ) {
                updates.explanation =
                    normalizeString(
                        explanation
                    );
            }

            const updated =
                await prisma.testQuestion.update({
                    where: {
                        id: questionId,
                    },
                    data: updates,
                    include: {
                        options: {
                            orderBy: {
                                order: "asc",
                            },
                        },
                    },
                });

            if (
                imageStorageKey !==
                undefined &&
                question.imageStorageKey &&
                question.imageStorageKey !==
                updated.imageStorageKey
            ) {
                await deleteFromR2(
                    question.imageStorageKey
                );
            }

            return res.json(
                mapQuestion(
                    updated,
                    true
                )
            );
        } catch (e) {
            console.error(
                "PATCH /tests/:testId/questions/:questionId",
                e
            );

            return res
                .status(
                    e.statusCode || 500
                )
                .json({
                    error:
                        e.message ||
                        "Failed to update question",
                });
        }
    }
);

router.delete(
    "/:testId/questions/:questionId",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const {
                testId,
                questionId,
            } = req.params;

            const question =
                await prisma.testQuestion.findUnique({
                    where: {
                        id: questionId,
                    },
                    include: {
                        test: true,
                        options: true,
                    },
                });

            if (
                !question ||
                question.testId !== testId
            ) {
                return res.status(404).json({
                    error:
                        "Question not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    question.test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            await assertNoSubmissions(
                testId
            );

            await deleteQuestionImages(
                question
            );

            await prisma.testQuestion.delete({
                where: {
                    id: questionId,
                },
            });

            return res.json({
                ok: true,
                id: questionId,
            });
        } catch (e) {
            console.error(
                "DELETE /tests/:testId/questions/:questionId",
                e
            );

            return res
                .status(
                    e.statusCode || 500
                )
                .json({
                    error:
                        e.message ||
                        "Failed to delete question",
                });
        }
    }
);

router.post(
    "/:testId/questions/:questionId/options",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const {
                testId,
                questionId,
            } = req.params;

            const {
                text,
                imageStorageKey,
                isCorrect,
                order,
            } = req.body || {};

            const question =
                await prisma.testQuestion.findUnique({
                    where: {
                        id: questionId,
                    },
                    include: {
                        test: true,
                    },
                });

            if (
                !question ||
                question.testId !== testId
            ) {
                return res.status(404).json({
                    error:
                        "Question not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    question.test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            if (
                question.type ===
                "text"
            ) {
                return res.status(400).json({
                    error:
                        "Text question cannot have options",
                });
            }

            await assertNoSubmissions(
                testId
            );

            const correct =
                normalizeBoolean(
                    isCorrect,
                    false
                );

            const option =
                await prisma.$transaction(
                    async (tx) => {
                        if (
                            question.type ===
                            "single_choice" &&
                            correct
                        ) {
                            await tx.testOption.updateMany({
                                where: {
                                    questionId,
                                },
                                data: {
                                    isCorrect:
                                        false,
                                },
                            });
                        }

                        return tx.testOption.create({
                            data: {
                                questionId,
                                text:
                                    normalizeString(
                                        text
                                    ),
                                imageStorageKey:
                                    normalizeString(
                                        imageStorageKey
                                    ),
                                isCorrect:
                                correct,
                                order:
                                    normalizeNumber(
                                        order,
                                        0
                                    ),
                            },
                        });
                    }
                );

            return res
                .status(201)
                .json(
                    mapOption(
                        option,
                        true
                    )
                );
        } catch (e) {
            console.error(
                "POST /tests/:testId/questions/:questionId/options",
                e
            );

            return res
                .status(
                    e.statusCode || 500
                )
                .json({
                    error:
                        e.message ||
                        "Failed to create option",
                });
        }
    }
);

router.patch(
    "/:testId/questions/:questionId/options/:optionId",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const {
                testId,
                questionId,
                optionId,
            } = req.params;

            const {
                text,
                imageStorageKey,
                isCorrect,
                order,
            } = req.body || {};

            const option =
                await prisma.testOption.findUnique({
                    where: {
                        id: optionId,
                    },
                    include: {
                        question: {
                            include: {
                                test: true,
                            },
                        },
                    },
                });

            if (
                !option ||
                option.questionId !==
                questionId ||
                option.question.testId !==
                testId
            ) {
                return res.status(404).json({
                    error:
                        "Option not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    option.question.test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            await assertNoSubmissions(
                testId
            );

            const updates = {};

            if (text !== undefined) {
                updates.text =
                    normalizeString(text);
            }

            if (
                imageStorageKey !==
                undefined
            ) {
                updates.imageStorageKey =
                    normalizeString(
                        imageStorageKey
                    );
            }

            if (
                isCorrect !== undefined
            ) {
                updates.isCorrect =
                    normalizeBoolean(
                        isCorrect,
                        option.isCorrect
                    );
            }

            if (order !== undefined) {
                updates.order =
                    normalizeNumber(
                        order,
                        option.order
                    );
            }

            const updated =
                await prisma.$transaction(
                    async (tx) => {
                        if (
                            option.question
                                .type ===
                            "single_choice" &&
                            updates.isCorrect ===
                            true
                        ) {
                            await tx.testOption.updateMany({
                                where: {
                                    questionId,
                                    id: {
                                        not:
                                        optionId,
                                    },
                                },
                                data: {
                                    isCorrect:
                                        false,
                                },
                            });
                        }

                        return tx.testOption.update({
                            where: {
                                id: optionId,
                            },
                            data: updates,
                        });
                    }
                );

            if (
                imageStorageKey !==
                undefined &&
                option.imageStorageKey &&
                option.imageStorageKey !==
                updated.imageStorageKey
            ) {
                await deleteFromR2(
                    option.imageStorageKey
                );
            }

            return res.json(
                mapOption(
                    updated,
                    true
                )
            );
        } catch (e) {
            console.error(
                "PATCH /tests/:testId/questions/:questionId/options/:optionId",
                e
            );

            return res
                .status(
                    e.statusCode || 500
                )
                .json({
                    error:
                        e.message ||
                        "Failed to update option",
                });
        }
    }
);

router.delete(
    "/:testId/questions/:questionId/options/:optionId",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const {
                testId,
                questionId,
                optionId,
            } = req.params;

            const option =
                await prisma.testOption.findUnique({
                    where: {
                        id: optionId,
                    },
                    include: {
                        question: {
                            include: {
                                test: true,
                            },
                        },
                    },
                });

            if (
                !option ||
                option.questionId !==
                questionId ||
                option.question.testId !==
                testId
            ) {
                return res.status(404).json({
                    error:
                        "Option not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    option.question.test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            await assertNoSubmissions(
                testId
            );

            if (
                option.imageStorageKey
            ) {
                await deleteFromR2(
                    option.imageStorageKey
                );
            }

            await prisma.testOption.delete({
                where: {
                    id: optionId,
                },
            });

            return res.json({
                ok: true,
                id: optionId,
            });
        } catch (e) {
            console.error(
                "DELETE /tests/:testId/questions/:questionId/options/:optionId",
                e
            );

            return res
                .status(
                    e.statusCode || 500
                )
                .json({
                    error:
                        e.message ||
                        "Failed to delete option",
                });
        }
    }
);

router.get(
    "/:testId/results",
    roleMiddleware(["TEACHER", "ADMIN"]),
    async (req, res) => {
        try {
            const testId =
                req.params.testId;

            const test =
                await prisma.test.findUnique({
                    where: {
                        id: testId,
                    },
                });

            if (!test) {
                return res.status(404).json({
                    error:
                        "Test not found",
                });
            }

            if (
                !canManageTest(
                    req,
                    test
                )
            ) {
                return res.status(403).json({
                    error: "Forbidden",
                });
            }

            const submissions =
                await prisma.testSubmission.findMany({
                    where: {
                        testId,
                    },
                    include: {
                        student: {
                            select:
                            userSelect,
                        },
                        answers: true,
                    },
                    orderBy: {
                        submittedAt:
                            "desc",
                    },
                });

            return res.json(
                submissions.map(
                    (submission) =>
                        mapSubmission(
                            submission,
                            true
                        )
                )
            );
        } catch (e) {
            console.error(
                "GET /tests/:testId/results",
                e
            );

            return res.status(500).json({
                error:
                    "Failed to get results",
            });
        }
    }
);

export default router;