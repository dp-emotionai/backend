import prisma from "../utils/prisma.js"
import { sendMail } from "../utils/email.js"
import { broadcastUserEvent } from "../socket/server.js"

const DEFAULT_FRONTEND_URL = "https://www.konilai.space"
const EMAIL_BATCH_SIZE = 5

function getFrontendUrl() {
    return (
        process.env.FRONTEND_URL ||
        DEFAULT_FRONTEND_URL
    ).replace(/\/+$/, "")
}

function escapeHtml(value) {
    const entities = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;",
    }

    return String(value ?? "").replace(
        /[&<>"']/g,
        (symbol) => entities[symbol]
    )
}

function formatDeadline(value) {
    if (!value) {
        return "Без дедлайна"
    }

    const date =
        value instanceof Date
            ? value
            : new Date(value)

    if (Number.isNaN(date.getTime())) {
        return "Без дедлайна"
    }

    const options = {
        day: "2-digit",
        month: "long",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    }

    try {
        return date.toLocaleString("ru-RU", {
            ...options,
            timeZone:
                process.env.APP_TIMEZONE ||
                "Asia/Almaty",
        })
    } catch {
        return date.toLocaleString(
            "ru-RU",
            options
        )
    }
}

function getStudentName(student) {
    const fullName = [
        student.firstName,
        student.lastName,
    ]
        .filter(Boolean)
        .join(" ")
        .trim()

    return fullName || student.email || "студент"
}

function getTaskHref(task) {
    if (
        task.type === "test" &&
        task.testId
    ) {
        return `/student/tests/${task.testId}`
    }

    return `/student/tasks/${task.id}`
}

function getNotificationTexts(task) {
    if (task.type === "test") {
        return {
            title: "Новый тест",
            body: `Добавлен новый тест «${task.title}»`,
        }
    }

    return {
        title: "Новое задание",
        body: `Добавлено новое задание «${task.title}»`,
    }
}

async function resolveTaskGroupId(task) {
    if (task.groupId) {
        return task.groupId
    }

    if (!task.sessionId) {
        return null
    }

    const session =
        await prisma.session.findUnique({
            where: {
                id: task.sessionId,
            },
            select: {
                groupId: true,
            },
        })

    return session?.groupId || null
}

function buildTaskEmail({
    student,
    task,
    groupName,
    href,
}) {
    const frontendUrl = getFrontendUrl()
    const taskUrl = `${frontendUrl}${href}`

    const isTest = task.type === "test"

    const entityLabel = isTest
        ? "тест"
        : "задание"

    const subject = isTest
        ? `Новый тест: ${task.title}`
        : `Новое задание: ${task.title}`

    const deadline =
        formatDeadline(task.deadline)

    const points = Number(task.points || 0)

    const studentName =
        getStudentName(student)

    const sessionTitle =
        task.session?.title || null

    const textLines = [
        `Здравствуйте, ${studentName}!`,
        "",
        `Преподаватель добавил новое ${entityLabel}:`,
        task.title,
        "",
        `Группа: ${groupName}`,
        sessionTitle
            ? `Урок: ${sessionTitle}`
            : null,
        `Дедлайн: ${deadline}`,
        `Баллы: ${points}`,
        "",
        `Открыть: ${taskUrl}`,
        "",
        "С уважением,",
        "Команда KonilAI",
    ].filter(Boolean)

    const safeStudentName =
        escapeHtml(studentName)

    const safeTitle =
        escapeHtml(task.title)

    const safeGroupName =
        escapeHtml(groupName)

    const safeSessionTitle =
        escapeHtml(sessionTitle)

    const safeDeadline =
        escapeHtml(deadline)

    const safeTaskUrl =
        escapeHtml(taskUrl)

    const html = `
<div style="background:#f7f7fb;padding:32px 16px;font-family:Arial,sans-serif;color:#1e293b;">
    <div style="max-width:620px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:20px;overflow:hidden;">
    <div style="background:#6d28d9;padding:24px 28px;color:#ffffff;">
    <div style="font-size:13px;font-weight:700;opacity:.85;">
    KonilAI
    </div>

<h1 style="margin:8px 0 0;font-size:24px;line-height:1.3;">
    ${isTest ? "Новый тест" : "Новое задание"}
</h1>
</div>

<div style="padding:28px;">
    <p style="margin:0 0 18px;font-size:16px;line-height:1.6;">
        Здравствуйте, <b>${safeStudentName}</b>!
    </p>

    <p style="margin:0 0 18px;font-size:15px;line-height:1.7;color:#475569;">
        Преподаватель добавил новое ${entityLabel}.
    </p>

    <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:14px;padding:18px;margin-bottom:22px;">
        <div style="font-size:18px;font-weight:700;color:#0f172a;margin-bottom:14px;">
            ${safeTitle}
        </div>

        <div style="font-size:14px;line-height:1.8;color:#475569;">
            <div>
                <b>Группа:</b> ${safeGroupName}
            </div>

            ${
            sessionTitle
                ? `<div><b>Урок:</b> ${safeSessionTitle}</div>`
                : ""
        }

            <div>
                <b>Дедлайн:</b> ${safeDeadline}
            </div>

            <div>
                <b>Баллы:</b> ${points}
            </div>
        </div>
    </div>

    <a
        href="${safeTaskUrl}"
        target="_blank"
        rel="noopener noreferrer"
        style="display:inline-block;background:#6d28d9;color:#ffffff;text-decoration:none;padding:13px 22px;border-radius:11px;font-size:14px;font-weight:700;"
    >
        ${isTest ? "Открыть тест" : "Открыть задание"}
    </a>

    <p style="margin:26px 0 0;font-size:13px;line-height:1.6;color:#94a3b8;">
        Это автоматическое письмо от KonilAI.
    </p>
</div>
</div>
</div>
`

    return {
        subject,
        text: textLines.join("\n"),
        html,
    }
}

async function sendEmailsInBatches(jobs) {
    let sent = 0
    let skipped = 0
    let failed = 0

    for (
        let index = 0;
        index < jobs.length;
        index += EMAIL_BATCH_SIZE
    ) {
        const batch = jobs.slice(
            index,
            index + EMAIL_BATCH_SIZE
        )

        const results =
            await Promise.allSettled(
                batch.map((job) => job())
            )

        results.forEach((result) => {
            if (result.status === "rejected") {
                failed += 1

                console.error(
                    "[taskNotifications] email failed",
                    result.reason?.message ||
                        result.reason
                )

                return
            }

            if (result.value?.skipped) {
                skipped += 1
                return
            }

            sent += 1
        })
    }

    return {
        sent,
        skipped,
        failed,
    }
}

/**
 * Создаёт уведомления студентам после публикации задания.
 *
 * Вызывать только:
 * - при создании задания со status = published;
 * - при переходе draft/closed -> published.
 */
export async function notifyTaskPublished(task) {
    if (!task?.id) {
        throw new Error(
            "notifyTaskPublished: task is required"
        )
    }

    if (task.status !== "published") {
        return {
            skipped: true,
            reason: "task-is-not-published",
        }
    }

    const groupId =
        await resolveTaskGroupId(task)

    if (!groupId) {
        console.warn(
            "[taskNotifications] task has no group",
            {
                taskId: task.id,
            }
        )

        return {
            skipped: true,
            reason: "group-not-found",
        }
    }

    const group =
        await prisma.group.findUnique({
            where: {
                id: groupId,
            },
            select: {
                id: true,
                name: true,
                members: {
                    where: {
                        status: "active",
                        removedAt: null,
                    },
                    select: {
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
                                        assignmentNotifications: true,
                                    },
                                },
                            },
                        },
                    },
                },
            },
        })

    if (!group) {
        console.warn(
            "[taskNotifications] group not found",
            {
                taskId: task.id,
                groupId,
            }
        )

        return {
            skipped: true,
            reason: "group-not-found",
        }
    }

    const recipients = group.members
        .map((member) => member.user)
        .filter(Boolean)
        .filter(
            (user) =>
                user.role === "STUDENT" &&
                user.status === "APPROVED"
        )
        .filter(
            (user) =>
                user.notificationSettings
                    ?.assignmentNotifications !==
                false
        )

    if (recipients.length === 0) {
        return {
            skipped: true,
            reason: "no-recipients",
            groupId,
        }
    }

    const href = getTaskHref(task)

    const texts =
        getNotificationTexts(task)

    const notificationData = {
        taskId: task.id,
        taskType: task.type,
        groupId,
        sessionId:
            task.sessionId || null,
        testId: task.testId || null,
        href,
        category: "task",
    }

    /*
     * Сначала создаём все уведомления в базе.
     * Если одно создание упадёт, транзакция
     * не сохранит неполный список.
     */
    const notificationOperations =
        recipients.map((student) =>
            prisma.notification.create({
                data: {
                    userId: student.id,
                    type: "task_assigned",
                    title: texts.title,
                    body: texts.body,
                    data: notificationData,
                },
            })
        )

    const notifications =
        await prisma.$transaction(
            notificationOperations
        )

    let socketSent = 0
    let socketFailed = 0

    notifications.forEach(
        (notification, index) => {
            const student =
                recipients[index]

            if (
                student.notificationSettings
                    ?.pushNotifications === false
            ) {
                return
            }

            try {
                broadcastUserEvent(
                    student.id,
                    {
                        type: "notification.new",
                        notification: {
                            id: notification.id,
                            type: notification.type,
                            title: notification.title,
                            body: notification.body,
                            data: notification.data,
                            readAt:
                                notification.readAt,
                            createdAt:
                                notification.createdAt,
                            isRead: false,
                        },
                        countsDelta: {
                            totalUnread: 1,
                            taskUnread: 1,
                        },
                    }
                )

                socketSent += 1
            } catch (error) {
                socketFailed += 1

                console.error(
                    "[taskNotifications] socket failed",
                    {
                        userId: student.id,
                        taskId: task.id,
                        error:
                            error?.message ||
                            error,
                    }
                )
            }
        }
    )

    const emailJobs = recipients
        .filter(
            (student) =>
                student.email &&
                student.notificationSettings
                    ?.emailNotifications !==
                    false
        )
        .map((student) => {
            return async () => {
                const email =
                    buildTaskEmail({
                        student,
                        task,
                        groupName:
                            group.name,
                        href,
                    })

                return sendMail({
                    to: student.email,
                    subject:
                        email.subject,
                    text: email.text,
                    html: email.html,
                })
            }
        })

    const emailResult =
        await sendEmailsInBatches(
            emailJobs
        )

    const result = {
        ok: true,
        taskId: task.id,
        groupId,
        studentsFound:
            group.members.length,
        recipients:
            recipients.length,
        notificationsCreated:
            notifications.length,
        socketSent,
        socketFailed,
        emailsSent:
            emailResult.sent,
        emailsSkipped:
            emailResult.skipped,
        emailsFailed:
            emailResult.failed,
    }

    console.log(
        "[taskNotifications] completed",
        result
    )

    return result
}
