import { Resend } from "resend"

const resend = process.env.RESEND_API_KEY
    ? new Resend(process.env.RESEND_API_KEY)
    : null

export async function sendMail({ to, subject, text, html }) {
    if (!resend) {
        console.warn("RESEND_API_KEY not set, skipping email send")
        return
    }

    const fromEmail = process.env.RESEND_FROM_EMAIL || "konilai<onboarding@resend.dev>"

    try {
        const { data, error } = await resend.emails.send({
            from: fromEmail,
            to,
            subject,
            text,
            html,
        })

        console.log("Email sent:", data?.id || null, "error:", error || null)
    } catch (err) {
        console.error("Resend error:", err)
    }
}

export async function sendUserApprovedEmail(user) {
    const subject = "Ваш аккаунт в konilai одобрен администратором"

    const text =
        `Здравствуйте${user.name ? ", " + user.name : ""}!\n\n` +
        "Ваш аккаунт в системе konilai был одобрен администратором. " +
        "Теперь вы можете войти, используя свой email и пароль.\n\n" +
        "С уважением,\nКоманда konilai"

    const html =
        `<p>Здравствуйте${user.name ? ", " + user.name : ""}!</p>` +
        `<p>Ваш аккаунт в системе <b>konilai</b> был одобрен администратором.</p>` +
        `<p>Теперь вы можете войти, используя свой email и пароль.</p>` +
        `<p>С уважением,<br/>Команда ELAS</p>`

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

    const adminLink =
        frontendBase
            ? `${frontendBase.replace(/\/+$/, "")}/admin/users?userId=${user.id}`
            : "/admin/users"

    const status = user.status || "PENDING"

    const subject = `Новая заявка преподавателя в konilai: ${user.email}`

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
        `<p>Новая заявка преподавателя в <b>konilai</b>:</p>` +
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
    const subject = "Ваш код входа в konilai"

    const text =
        `Ваш код подтверждения для konilai: ${code}\n\n` +
        "Введите этот код в приложении, чтобы подтвердить email и войти."

    const html =
        `<p>Ваш код подтверждения для <b>ELAS</b>:</p>` +
        `<p style="font-size: 24px; font-weight: bold; letter-spacing: 4px;">${code}</p>` +
        `<p>Введите этот код в приложении, чтобы подтвердить email и войти.</p>`

    await sendMail({
        to: email,
        subject,
        text,
        html,
    })
}