import express from "express"
import PDFDocument from "pdfkit"

const router = express.Router()

router.get("/privacy-policy/download", (req, res) => {
    const fileName = "KonilAI-Privacy-Policy.pdf"

    res.setHeader("Content-Type", "application/pdf")
    res.setHeader(
        "Content-Disposition",
        `attachment; filename="${fileName}"`
    )

    const doc = new PDFDocument({
        size: "A4",
        margin: 56,
    })

    doc.pipe(res)

    doc
        .fontSize(10)
        .fillColor("#7448FF")
        .text("Публичный документ")

    doc.moveDown(0.5)

    doc
        .fontSize(26)
        .fillColor("#0F172A")
        .text("Политика конфиденциальности KonilAI", {
            lineGap: 4,
        })

    doc.moveDown(0.5)

    doc
        .fontSize(12)
        .fillColor("#64748B")
        .text(
            "Что мы обрабатываем, что сохраняем и кто имеет доступ к данным.",
            { lineGap: 4 }
        )

    doc.moveDown(1.5)

    addSection(
        doc,
        "1. Что мы обрабатываем",
        "Мы обрабатываем кадры с вашей веб-камеры с низкой частотой — 1–2 кадра в секунду. Это не непрерывная видеозапись. Кадры используются только для анализа эмоций и вовлечённости в реальном времени. Видеозапись не сохраняется."
    )

    addSection(
        doc,
        "2. Что мы сохраняем",
        "Мы не сохраняем исходное видео или изображения. Сохраняются только метаданные: агрегированные показатели эмоций, уровень вовлечённости и временные метки для аналитики и отчётов. В групповых отчётах данные обезличиваются."
    )

    addSection(
        doc,
        "3. Кто имеет доступ",
        "Доступ зависит от роли пользователя. Студенты видят только собственную сводку, если они дали согласие. Преподаватели видят агрегированную аналитику по своим группам и сессиям. Администраторы управляют пользователями и настройками системы. Мы не передаём данные третьим лицам для маркетинговых или неучебных целей."
    )

    addSection(
        doc,
        "4. Срок хранения",
        "Срок хранения данных может настраиваться вашей организацией. Вы можете запросить удаление своих данных, и мы обработаем такой запрос в соответствии с применимыми правилами и требованиями."
    )

    addSection(
        doc,
        "5. Ваше согласие",
        "Участие в видеоаналитике требует вашего явного согласия. Вы можете дать или отозвать согласие в любой момент в центре согласия. Без согласия кадры не обрабатываются и не анализируются."
    )

    doc.moveDown(1.4)

    const noteY = doc.y

    doc
        .roundedRect(56, noteY, 483, 78, 16)
        .fill("#F5F3FF")

    doc
        .fillColor("#5B21B6")
        .fontSize(11)
        .text(
            "KonilAI бережно относится к приватности пользователей. Видео не записывается, а данные используются только для образовательной аналитики.",
            76,
            noteY + 20,
            { width: 443, lineGap: 4 }
        )

    doc.end()
})

function addSection(doc, title, body) {
    const startY = doc.y

    doc
        .roundedRect(56, startY, 483, 96, 14)
        .strokeColor("#E2E8F0")
        .lineWidth(1)
        .stroke()

    doc
        .fontSize(14)
        .fillColor("#0F172A")
        .text(title, 76, startY + 16, { width: 443 })

    doc
        .fontSize(10.5)
        .fillColor("#475569")
        .text(body, 76, startY + 40, {
            width: 443,
            lineGap: 3,
        })

    doc.y = startY + 112
}

export default router