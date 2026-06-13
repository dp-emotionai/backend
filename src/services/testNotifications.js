import prisma from "../utils/prisma.js";
import { sendMail } from "../utils/email.js";
import { broadcastUserEvent } from "../socket/server.js";
import {
    isEligibleAssignmentRecipient,
    logGroupMembers,
    logNotificationRecipients,
    matchesAssignmentNotification,
} from "./assignmentNotificationRecipients.js";

const FRONTEND_URL = (
    process.env.FRONTEND_URL ||
    "https://www.konilai.space"
).replace(/\/+$/, "");

const escapeHtml = (value) =>
    String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

const formatDate = (value) => {
    if (!value) return null;

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return null;
    }

    return new Intl.DateTimeFormat("ru-RU", {
        timeZone:
            process.env.APP_TIMEZONE ||
            "Asia/Almaty",
        day: "2-digit",
        month: "long",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    }).format(date);
};

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

export async function notifyTestPublished(test) {
    if (
        !test?.id ||
        test.status !== "published"
    ) {
        return {
            createdCount: 0,
            emailCount: 0,
        };
    }

    const fullTest =
        await prisma.test.findUnique({
            where: {
                id: test.id,
            },
            include: {
                session: {
                    select: {
                        groupId: true,
                    },
                },
                group: {
                    select: {
                        id: true,
                        name: true,
                    },
                },
            },
        });

    if (!fullTest) {
        return {
            createdCount: 0,
            emailCount: 0,
        };
    }

    const groupId =
        fullTest.groupId ||
        fullTest.session?.groupId ||
        null;

    if (!groupId) {
        console.warn(
            "notifyTestPublished: groupId not found",
            {
                testId: fullTest.id,
            }
        );

        return {
            createdCount: 0,
            emailCount: 0,
        };
    }

    const members =
        await prisma.groupMember.findMany({
            where: {
                groupId,
                removedAt: null,
            },
            include: {
                user: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                        role: true,
                        status: true,
                        notificationSettings: {
                            select: {
                                emailNotifications: true,
                                pushNotifications: true,
                                assignmentNotifications:
                                    true,
                            },
                        },
                    },
                },
            },
        });

    logGroupMembers(groupId, members);

    const recipients = members.filter(
        isEligibleAssignmentRecipient
    );

    logNotificationRecipients(
        groupId,
        recipients
    );

    if (recipients.length === 0) {
        return {
            createdCount: 0,
            emailCount: 0,
        };
    }

    const userIds = recipients.map(
        (member) => member.user.id
    );

    const existingNotifications =
        await prisma.notification.findMany({
            where: {
                userId: {
                    in: userIds,
                },
                type: "task_assigned",
            },
            select: {
                userId: true,
                data: true,
            },
        });

    const alreadyNotifiedUserIds =
        new Set(
            existingNotifications
                .filter((notification) =>
                    matchesAssignmentNotification(
                        notification.data,
                        {
                            taskId:
                            fullTest.id,
                            testId:
                            fullTest.id,
                        }
                    )
                )
                .map(
                    (notification) =>
                        notification.userId
                )
        );

    const newRecipients =
        recipients.filter(
            (member) =>
                !alreadyNotifiedUserIds.has(
                    member.user.id
                )
        );

    if (newRecipients.length === 0) {
        return {
            createdCount: 0,
            emailCount: 0,
        };
    }

    const testHref =
        `/student/tests/${fullTest.id}`;

    const startsAtText =
        formatDate(fullTest.startsAt);

    const endsAtText =
        formatDate(fullTest.endsAt);

    const notificationTitle =
        "Новый тест";

    const notificationBody =
        startsAtText
            ? `Опубликован тест «${fullTest.title}». Начало: ${startsAtText}.`
            : `Опубликован тест «${fullTest.title}».`;

    newRecipients.forEach((member) => {
        console.log("CREATING NOTIFICATION", {
            userId: member.user.id,
            entityId: fullTest.id,
            type: "task_assigned",
        });
    });

    let createdNotifications;

    try {
        createdNotifications =
            await prisma.$transaction(
                newRecipients.map((member) =>
                    prisma.notification.create({
                        data: {
                            userId:
                            member.user.id,
                            type: "task_assigned",
                            title:
                            notificationTitle,
                            body:
                            notificationBody,
                            data: {
                                taskId:
                                fullTest.id,
                                taskType: "test",
                                testId:
                                fullTest.id,
                                groupId,
                                sessionId:
                                fullTest.sessionId,
                                href: testHref,
                                category: "task",
                            },
                        },
                    })
                )
            );
    } catch (error) {
        console.error(
            "NOTIFICATION CREATE FAILED",
            error
        );
        throw error;
    }

    createdNotifications.forEach(
        (notification) => {
            console.log(
                "NOTIFICATION CREATED",
                {
                    id: notification.id,
                    userId:
                    notification.userId,
                    data: notification.data,
                }
            );
        }
    );

    for (
        let index = 0;
        index <
        createdNotifications.length;
        index += 1
    ) {
        const notification =
            createdNotifications[index];

        const recipient =
            newRecipients[index];

        if (
            recipient.user
                .notificationSettings
                ?.pushNotifications ===
            false
        ) {
            continue;
        }

        try {
            const mappedNotification =
                mapNotification(
                    notification
                );

            console.log(
                "BROADCAST USER NOTIFICATION",
                {
                    userId:
                    recipient.user.id,
                    notificationId:
                    notification.id,
                }
            );

            broadcastUserEvent(
                recipient.user.id,
                {
                    type:
                        "notification.new",
                    notification:
                    mappedNotification,
                    countsDelta: {
                        totalUnread: 1,
                        taskUnread: 1,
                    },
                }
            );
        } catch (socketError) {
            console.error(
                "notifyTestPublished socket error",
                {
                    userId:
                    recipient.user.id,
                    testId:
                    fullTest.id,
                    error:
                        socketError?.message ||
                        socketError,
                }
            );
        }
    }

    const emailResults =
        await Promise.allSettled(
            newRecipients.map(
                async (member) => {
                    if (
                        member.user
                            .notificationSettings
                            ?.emailNotifications ===
                        false
                    ) {
                        return {
                            skipped: true,
                        };
                    }

                    const email =
                        String(
                            member.user
                                .email || ""
                        ).trim();

                    if (!email) {
                        return {
                            skipped: true,
                        };
                    }

                    const studentName = [
                        member.user
                            .firstName,
                        member.user
                            .lastName,
                    ]
                        .filter(Boolean)
                        .join(" ");

                    const testUrl =
                        `${FRONTEND_URL}${testHref}`;

                    const scheduleLines = [
                        startsAtText
                            ? `Начало: ${startsAtText}`
                            : null,
                        endsAtText
                            ? `Завершение: ${endsAtText}`
                            : null,
                    ].filter(Boolean);

                    const text = [
                        studentName
                            ? `Здравствуйте, ${studentName}!`
                            : "Здравствуйте!",
                        "",
                        `Преподаватель опубликовал новый тест: «${fullTest.title}».`,
                        ...scheduleLines,
                        "",
                        `Открыть тест: ${testUrl}`,
                    ].join("\n");

                    const html = [
                        `<p>${
                            studentName
                                ? `Здравствуйте, ${escapeHtml(
                                    studentName
                                )}!`
                                : "Здравствуйте!"
                        }</p>`,
                        `<p>Преподаватель опубликовал новый тест: <b>«${escapeHtml(
                            fullTest.title
                        )}»</b>.</p>`,
                        startsAtText
                            ? `<p><b>Начало:</b> ${escapeHtml(
                                startsAtText
                            )}</p>`
                            : "",
                        endsAtText
                            ? `<p><b>Завершение:</b> ${escapeHtml(
                                endsAtText
                            )}</p>`
                            : "",
                        `<p><a href="${escapeHtml(
                            testUrl
                        )}" target="_blank" rel="noopener noreferrer">Открыть тест</a></p>`,
                    ].join("");

                    return sendMail({
                        to: email,
                        subject:
                            `Новый тест: ${fullTest.title}`,
                        text,
                        html,
                    });
                }
            )
        );

    const emailCount =
        emailResults.filter(
            (result) =>
                result.status ===
                "fulfilled" &&
                !result.value?.skipped
        ).length;

    for (const result of emailResults) {
        if (
            result.status === "rejected"
        ) {
            console.error(
                "notifyTestPublished email error",
                result.reason
            );
        }
    }

    return {
        createdCount:
        createdNotifications.length,
        emailCount,
    };
}
