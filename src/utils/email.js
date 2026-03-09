import nodemailer from "nodemailer"

const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === "true",
    auth: process.env.SMTP_USER && process.env.SMTP_PASS ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    } : undefined,
})

export async function sendMail({ to, subject, text, html }) {
    if (!process.env.SMTP_HOST) {
        console.warn("SMTP_HOST is not set, skipping email send")
        return
    }
    await transport.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to,
        subject,
        text,
        html,
    })
}

export async function sendUserApprovedEmail(user) {
    const subject = "Ваш аккаунт в ELAS одобрен администратором"
    const text =
        `Здравствуйте${user.name ? ", " + user.name : ""}!\n\n` +
        "Ваш аккаунт в системе ELAS был одобрен администратором. " +
        "Теперь вы можете войти, используя свой email и пароль.\n\n" +
        "С уважением,\nКоманда ELAS"
    const html =
        `<p>Здравствуйте${user.name ? ", " + user.name : ""}!</p>` +
        `<p>Ваш аккаунт в системе <b>ELAS</b> был одобрен администратором.</p>` +
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

    const subject = "Новая регистрация в ELAS"
    const text =
        `Новый пользователь зарегистрировался в ELAS.\n\n` +
        `Email: ${user.email}\n` +
        `Имя: ${user.name ?? "-"}\n` +
        `Роль: ${user.role}\n` +
        `Статус: ${user.status}\n\n` +
        `Чтобы одобрить или отклонить, зайдите в админ-панель ELAS.`
    const html =
        `<p>Новый пользователь зарегистрировался в <b>ELAS</b>.</p>` +
        `<ul>` +
        `<li><b>Email:</b> ${user.email}</li>` +
        `<li><b>Имя:</b> ${user.name ?? "-"}</li>` +
        `<li><b>Роль:</b> ${user.role}</li>` +
        `<li><b>Статус:</b> ${user.status}</li>` +
        `</ul>` +
        `<p>Чтобы одобрить или отклонить пользователя, откройте админ-панель ELAS.</p>`

    await sendMail({
        to: adminEmail,
        subject,
        text,
        html,
    })
}


