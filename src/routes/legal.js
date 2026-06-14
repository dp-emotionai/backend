import express from "express"
import puppeteer from "puppeteer-core"
import chromium from "@sparticuz/chromium"

const router = express.Router()

router.get("/privacy-policy/download", async (req, res, next) => {
    let browser

    try {
        browser = await puppeteer.launch({
            args: chromium.args,
            defaultViewport: chromium.defaultViewport,
            executablePath: await chromium.executablePath(),
            headless: chromium.headless,
        })

        const page = await browser.newPage()

        await page.setContent(getPrivacyPolicyHtml(), {
            waitUntil: "networkidle0",
        })

        const pdfBuffer = await page.pdf({
            format: "A4",
            printBackground: true,
            preferCSSPageSize: true,
            margin: {
                top: "0px",
                right: "0px",
                bottom: "0px",
                left: "0px",
            },
        })

        res.setHeader("Content-Type", "application/pdf")
        res.setHeader(
            "Content-Disposition",
            'attachment; filename="KonilAI-Privacy-Policy.pdf"'
        )

        res.send(pdfBuffer)
    } catch (error) {
        console.error("PDF GENERATION FAILED", error)
        next(error)
    } finally {
        if (browser) {
            await browser.close()
        }
    }
})

function getPrivacyPolicyHtml() {
    const date = new Date().toLocaleDateString("ru-RU")

    return `
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <title>Политика конфиденциальности KonilAI</title>
  <style>
    @page {
      size: A4;
      margin: 20mm 18mm 18mm 18mm;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Arial, "Helvetica Neue", sans-serif;
      color: #111827;
      background: #ffffff;
      font-size: 12px;
      line-height: 1.55;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid #d1d5db;
      padding-bottom: 14px;
      margin-bottom: 22px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 700;
      font-size: 16px;
      color: #111827;
    }

    .logo {
      width: 34px;
      height: 34px;
      border-radius: 10px;
      background: #7448ff;
      color: #ffffff;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
    }

    .meta {
      text-align: right;
      color: #6b7280;
      font-size: 11px;
    }

    .label {
      display: inline-block;
      margin-bottom: 10px;
      padding: 5px 10px;
      border-radius: 999px;
      background: #f3f4f6;
      color: #4b5563;
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    h1 {
      margin: 0 0 8px;
      font-size: 28px;
      line-height: 1.15;
      color: #111827;
      letter-spacing: -0.03em;
    }

    .subtitle {
      max-width: 650px;
      color: #4b5563;
      font-size: 13px;
      margin-bottom: 22px;
    }

    .notice {
      border: 1px solid #ddd6fe;
      background: #f5f3ff;
      border-left: 4px solid #7448ff;
      border-radius: 12px;
      padding: 14px 16px;
      margin-bottom: 22px;
      color: #312e81;
    }

    .notice strong {
      display: block;
      margin-bottom: 4px;
      color: #1e1b4b;
      font-size: 13px;
    }

    .section {
      page-break-inside: avoid;
      border: 1px solid #e5e7eb;
      border-radius: 12px;
      padding: 14px 16px;
      margin-bottom: 12px;
      background: #ffffff;
    }

    .section-title {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 6px;
      font-size: 14px;
      font-weight: 700;
      color: #111827;
    }

    .num {
      width: 24px;
      height: 24px;
      border-radius: 999px;
      background: #ede9fe;
      color: #7448ff;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      font-weight: 800;
      flex: 0 0 auto;
    }

    p {
      margin: 0;
      color: #374151;
    }

    .table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 18px;
      page-break-inside: avoid;
    }

    .table th,
    .table td {
      border: 1px solid #e5e7eb;
      padding: 9px 10px;
      text-align: left;
      vertical-align: top;
    }

    .table th {
      background: #f9fafb;
      color: #111827;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }

    .table td {
      color: #374151;
    }

    .signature {
      margin-top: 24px;
      display: flex;
      justify-content: space-between;
      gap: 24px;
      page-break-inside: avoid;
    }

    .signature-box {
      flex: 1;
      border-top: 1px solid #9ca3af;
      padding-top: 8px;
      color: #6b7280;
      font-size: 11px;
    }

    .footer {
      margin-top: 22px;
      padding-top: 12px;
      border-top: 1px solid #e5e7eb;
      display: flex;
      justify-content: space-between;
      color: #6b7280;
      font-size: 10px;
    }
  </style>
</head>
<body>
  <header class="header">
    <div class="brand">
      <div class="logo">K</div>
      <div>KonilAI</div>
    </div>
    <div class="meta">
      Документ: Privacy Policy<br />
      Версия: 1.0<br />
      Дата формирования: ${escapeHtml(date)}
    </div>
  </header>

  <main>
    <div class="label">Публичный документ</div>

    <h1>Политика конфиденциальности KonilAI</h1>

    <div class="subtitle">
      Настоящий документ описывает, какие данные обрабатываются в образовательной платформе KonilAI,
      с какой целью они используются, кто имеет доступ к данным и каким образом пользователь может
      управлять своим согласием.
    </div>

    <div class="notice">
      <strong>Ключевой принцип</strong>
      KonilAI не сохраняет исходное видео пользователя. Аналитика используется только в образовательных целях
      и только при наличии согласия пользователя.
    </div>

    ${section(
        "1",
        "Что мы обрабатываем",
        "Платформа может обрабатывать отдельные кадры с веб-камеры пользователя с низкой частотой — примерно 1–2 кадра в секунду. Это не является непрерывной видеозаписью. Такие кадры используются только для анализа вовлечённости и эмоционального состояния в рамках образовательного процесса."
    )}

    ${section(
        "2",
        "Что мы сохраняем",
        "KonilAI не сохраняет исходное видео или изображения. В системе могут сохраняться только метаданные: агрегированные показатели эмоций, уровень вовлечённости, временные метки и аналитические показатели, необходимые для формирования образовательных отчётов."
    )}

    ${section(
        "3",
        "Кто имеет доступ к данным",
        "Доступ к данным зависит от роли пользователя. Студент может видеть только собственную информацию при наличии согласия. Преподаватель получает агрегированную аналитику по своим группам и сессиям. Администратор управляет пользователями и настройками системы."
    )}

    ${section(
        "4",
        "Срок хранения данных",
        "Срок хранения данных может определяться правилами образовательной организации. Пользователь может запросить удаление своих данных, после чего запрос обрабатывается в соответствии с применимыми требованиями и внутренними правилами платформы."
    )}

    ${section(
        "5",
        "Согласие пользователя",
        "Участие в видеоаналитике требует явного согласия пользователя. Пользователь может дать или отозвать согласие в любой момент. Без согласия кадры не обрабатываются и не анализируются."
    )}

    ${section(
        "6",
        "Ограничения использования",
        "Данные видеоаналитики не предназначены для выставления оценок, применения санкций или принятия дисциплинарных решений. Они используются только как вспомогательный инструмент для улучшения качества образовательного процесса."
    )}

    <table class="table">
      <thead>
        <tr>
          <th>Категория</th>
          <th>Описание</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Видео</td>
          <td>Исходное видео не сохраняется.</td>
        </tr>
        <tr>
          <td>Метаданные</td>
          <td>Могут сохраняться агрегированные показатели вовлечённости и эмоций.</td>
        </tr>
        <tr>
          <td>Доступ</td>
          <td>Ограничен ролью пользователя и образовательным назначением.</td>
        </tr>
        <tr>
          <td>Согласие</td>
          <td>Пользователь может управлять согласием самостоятельно.</td>
        </tr>
      </tbody>
    </table>

    <div class="signature">
      <div class="signature-box">
        Ответственная сторона: KonilAI
      </div>
      <div class="signature-box">
        Дата актуализации: ${escapeHtml(date)}
      </div>
    </div>
  </main>

  <footer class="footer">
    <div>KonilAI · Политика конфиденциальности</div>
    <div>Сформировано автоматически</div>
  </footer>
</body>
</html>
`
}

function section(number, title, body) {
    return `
      <section class="section">
        <div class="section-title">
          <span class="num">${escapeHtml(number)}</span>
          <span>${escapeHtml(title)}</span>
        </div>
        <p>${escapeHtml(body)}</p>
      </section>
    `
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;")
}

export default router