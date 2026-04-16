import { Resend } from "resend"

const resend = process.env.RESEND_API_KEY
    ? new Resend(process.env.RESEND_API_KEY)
    : null

const EMAIL_TIMEOUT_MS = 12000

function assertSingleEmailRecipient(to) {
    if (Array.isArray(to)) {
        throw new Error(`sendMail expected single recipient, got array: ${JSON.stringify(to)}`)
    }

    const value = String(to || "").trim()

    if (!value) {
        throw new Error("sendMail recipient is empty")
    }

    if (value.includes(",")) {
        throw new Error(`sendMail expected single recipient, got comma-separated list: ${value}`)
    }

    if (value.includes(";")) {
        throw new Error(`sendMail expected single recipient, got semicolon-separated list: ${value}`)
    }

    return value.toLowerCase()
}

function withTimeout(promise, ms, label = "async operation") {
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            setTimeout(() => {
                reject(new Error(`${label} timed out after ${ms}ms`))
            }, ms)
        }),
    ])
}

export async function sendMail({ to, subject, text, html }) {
    if (!resend) {
        console.warn("RESEND_API_KEY not set, skipping email send")
        return { skipped: true }
    }

    const safeTo = assertSingleEmailRecipient(to)
    const fromEmail =
        process.env.RESEND_FROM_EMAIL || "KonilAI <no-reply@konilai.space>"

    try {
        console.log("[sendMail] sending email", {
            to: safeTo,
            subject,
        })

        const result = await withTimeout(
            resend.emails.send({
                from: fromEmail,
                to: safeTo,
                subject,
                text,
                html,
            }),
            EMAIL_TIMEOUT_MS,
            "resend.emails.send"
        )

        const { data, error } = result || {}

        console.log("[sendMail] result", {
            id: data?.id || null,
            error: error || null,
        })

        if (error) {
            throw new Error(typeof error === "string" ? error : JSON.stringify(error))
        }

        return {
            ok: true,
            id: data?.id || null,
        }
    } catch (err) {
        console.error("[sendMail] error", {
            to: safeTo,
            subject,
            error: err?.message || err,
        })
        throw err
    }
}

export async function sendUserApprovedEmail(user) {
    const subject = "Ваш аккаунт в KonilAI одобрен администратором"

    const text =
        `Здравствуйте${user.name ? ", " + user.name : ""}!\n\n` +
        "Ваш аккаунт в системе KonilAI был одобрен администратором. " +
        "Теперь вы можете войти, используя свой email и пароль.\n\n" +
        "С уважением,\nКоманда KonilAI"

    const html =
        `<p>Здравствуйте${user.name ? ", " + user.name : ""}!</p>` +
        `<p>Ваш аккаунт в системе <b>KonilAI</b> был одобрен администратором.</p>` +
        `<p>Теперь вы можете войти, используя свой email и пароль.</p>` +
        `<p>С уважением,<br/>Команда KonilAI</p>`

    await sendMail({
        to: user.email,
        subject,
        text,
        html,
    })
}

export async function sendNewRegistrationAdminEmail(user) {
    const adminEmail = process.env.ADMIN_EMAIL

    if (!adminEmail) {
        console.warn("ADMIN_EMAIL is not set, skipping admin registration email")
        return
    }

    const frontendBase = process.env.FRONTEND_URL || ""

    const adminLink = frontendBase
        ? `${frontendBase.replace(/\/+$/, "")}/admin/users?userId=${user.id}`
        : "/admin/users"

    const status = user.status || "PENDING"

    const subject = `Новая заявка преподавателя в KonilAI: ${user.email}`

    const text =
        `Email: ${user.email}\n` +
        `Имя: ${user.name ?? "—"}\n` +
        `Роль: teacher\n` +
        `Статус: ${status}\n` +
        `Организация: ${user.organization ?? "—"}\n` +
        `Профиль: ${user.profileUrl ?? "—"}\n` +
        `Дата регистрации: ${user.createdAt?.toISOString?.() ?? String(user.createdAt ?? "")}\n\n` +
        `Ссылка для админа: ${adminLink}`

    const html =
        `<p>Новая заявка преподавателя в <b>KonilAI</b>:</p>` +
        `<ul>` +
        `<li><b>Email:</b> ${user.email}</li>` +
        `<li><b>Имя:</b> ${user.name ?? "—"}</li>` +
        `<li><b>Роль:</b> teacher</li>` +
        `<li><b>Статус:</b> ${status}</li>` +
        `<li><b>Организация:</b> ${user.organization ?? "—"}</li>` +
        `<li><b>Профиль:</b> ${user.profileUrl ?? "—"}</li>` +
        `<li><b>Дата регистрации:</b> ${user.createdAt?.toISOString?.() ?? String(user.createdAt ?? "")}</li>` +
        `</ul>` +
        `<p>Ссылка для админа: <a href="${adminLink}">${adminLink}</a></p>`

    await sendMail({
        to: adminEmail,
        subject,
        text,
        html,
    })
}

export async function sendEmailVerificationCode(email, code) {
    const subject = "Ваш код подтверждения KonilAI"

    const text =
        `Ваш код подтверждения для KonilAI: ${code}\n\n` +
        "Введите этот код в приложении, чтобы подтвердить email и завершить вход или регистрацию."

    const html =
        `<p>Ваш код подтверждения для <b>KonilAI</b>:</p>` +
        `<p style="font-size: 24px; font-weight: bold; letter-spacing: 4px;">${code}</p>` +
        `<p>Введите этот код в приложении, чтобы подтвердить email и завершить вход или регистрацию.</p>`

    await sendMail({
        to: email,
        subject,
        text,
        html,
    })
}

export async function sendPasswordResetEmail(email, token) {
    const frontendBase = process.env.FRONTEND_URL || "https://www.konilai.space"
    const base = frontendBase.replace(/\/+$/, "")
    const resetLink = `${base}/auth/reset-password?token=${encodeURIComponent(token)}`

    const subject = "Сброс пароля KonilAI"

    const text =
        `Вы запросили сброс пароля для KonilAI.\n\n` +
        `Если вы не делали этот запрос, просто проигнорируйте это письмо.\n\n` +
        `Ссылка для сброса пароля (действительна 30 минут):\n${resetLink}\n`

    const html =
        `<p>Вы запросили сброс пароля для <b>KonilAI</b>.</p>` +
        `<p>Если вы не делали этот запрос, просто проигнорируйте это письмо.</p>` +
        `<p><a href="${resetLink}" target="_blank" rel="noopener noreferrer">Сбросить пароль</a></p>` +
        `<p>Ссылка действует <b>30 минут</b>.</p>`

    await sendMail({
        to: email,
        subject,
        text,
        html,
    })
}