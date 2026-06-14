import express from "express"
import puppeteer from "puppeteer"

const router = express.Router()

router.get("/privacy-policy/download", async (req, res, next) => {
    let browser

    try {
        browser = await puppeteer.launch({
            headless: "new",
            args: ["--no-sandbox", "--disable-setuid-sandbox"],
        })

        const page = await browser.newPage()

        await page.setContent(getPrivacyPolicyHtml(), {
            waitUntil: "networkidle0",
        })

        const pdfBuffer = await page.pdf({
            format: "A4",
            printBackground: true,
            margin: {
                top: "24px",
                right: "24px",
                bottom: "24px",
                left: "24px",
            },
        })

        res.setHeader("Content-Type", "application/pdf")
        res.setHeader(
            "Content-Disposition",
            'attachment; filename="KonilAI-Privacy-Policy.pdf"'
        )

        res.send(pdfBuffer)
    } catch (error) {
        next(error)
    } finally {
        if (browser) {
            await browser.close()
        }
    }
})

function getPrivacyPolicyHtml() {
    return `
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <title>Политика конфиденциальности KonilAI</title>
  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Arial, sans-serif;
      color: #0f172a;
      background: #f8fafc;
    }

    .page {
      width: 100%;
      min-height: 100vh;
      padding: 38px;
      background:
        radial-gradient(circle at top left, rgba(124, 58, 237, 0.13), transparent 34%),
        radial-gradient(circle at bottom right, rgba(168, 85, 247, 0.16), transparent 34%),
        #f8fafc;
    }

    .hero {
      margin-bottom: 26px;
    }

    .badge {
      display: inline-block;
      padding: 7px 14px;
      border-radius: 999px;
      background: #ede9fe;
      color: #7448ff;
      font-size: 12px;
      font-weight: 700;
      margin-bottom: 12px;
    }

    h1 {
      margin: 0;
      font-size: 34px;
      line-height: 1.1;
      letter-spacing: -0.04em;
      color: #0f172a;
    }

    .subtitle {
      margin-top: 10px;
      max-width: 680px;
      color: #64748b;
      font-size: 15px;
      line-height: 1.6;
    }

    .cover-card {
      border: 1px solid #e2e8f0;
      border-radius: 28px;
      background: rgba(255, 255, 255, 0.92);
      box-shadow: 0 20px 60px rgba(15, 23, 42, 0.08);
      padding: 22px;
    }

    .section {
      display: flex;
      gap: 18px;
      padding: 18px;
      border: 1px solid #e2e8f0;
      border-radius: 22px;
      background: #ffffff;
      margin-bottom: 12px;
    }

    .icon {
      width: 52px;
      height: 52px;
      border-radius: 18px;
      background: #f3e8ff;
      color: #7448ff;
      display: flex;
      align-items: center;
      justify-content: center;
      flex: 0 0 auto;
      font-size: 24px;
      font-weight: 700;
    }

    .section h2 {
      margin: 0 0 5px;
      font-size: 17px;
      color: #0f172a;
    }

    .section p {
      margin: 0;
      color: #475569;
      font-size: 13px;
      line-height: 1.55;
    }

    .note {
      display: flex;
      gap: 16px;
      margin-top: 20px;
      padding: 18px;
      border-radius: 22px;
      background: linear-gradient(135deg, #ede9fe, #faf5ff);
      color: #4c1d95;
    }

    .note strong {
      display: block;
      margin-bottom: 4px;
      color: #4c1d95;
    }

    .footer {
      margin-top: 22px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      color: #64748b;
      font-size: 12px;
    }

    .status {
      padding: 7px 14px;
      border-radius: 999px;
      background: #dcfce7;
      color: #15803d;
      font-weight: 700;
    }

    .illustration {
      margin: 18px 0 22px;
      padding: 22px;
      border-radius: 28px;
      background: linear-gradient(135deg, #7448ff, #a855f7);
      color: white;
      display: flex;
      align-items: center;
      justify-content: space-between;
      overflow: hidden;
    }

    .illustration-text {
      max-width: 420px;
    }

    .illustration-title {
      font-size: 22px;
      font-weight: 800;
      margin-bottom: 8px;
    }

    .illustration-subtitle {
      font-size: 13px;
      line-height: 1.55;
      opacity: 0.9;
    }

    .visual {
      width: 170px;
      height: 120px;
      border-radius: 28px;
      background: rgba(255,255,255,0.18);
      position: relative;
    }

    .visual::before {
      content: "🔒";
      position: absolute;
      left: 34px;
      top: 26px;
      font-size: 54px;
    }

    .visual::after {
      content: "📊";
      position: absolute;
      right: 30px;
      bottom: 22px;
      font-size: 38px;
    }
  </style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <div class="badge">Публичный документ</div>
      <h1>Политика конфиденциальности KonilAI</h1>
      <div class="subtitle">
        Что мы обрабатываем, что сохраняем и кто имеет доступ к данным.
        Видео не записывается, а аналитика используется только для образовательного процесса.
      </div>
    </section>

    <section class="illustration">
      <div class="illustration-text">
        <div class="illustration-title">Приватность ученика — в центре системы</div>
        <div class="illustration-subtitle">
          KonilAI анализирует только ограниченные сигналы вовлечённости после согласия пользователя.
          Исходное видео не сохраняется и не передаётся третьим лицам.
        </div>
      </div>
      <div class="visual"></div>
    </section>

    <section class="cover-card">
      ${section("📷", "Что мы обрабатываем", "Мы обрабатываем кадры с вашей веб-камеры с низкой частотой — 1–2 кадра в секунду. Это не непрерывная видеозапись. Кадры используются только для анализа эмоций и вовлечённости в реальном времени. Видеозапись не сохраняется.")}
      ${section("🗄️", "Что мы сохраняем", "Мы не сохраняем исходное видео или изображения. Сохраняются только метаданные: агрегированные показатели эмоций, уровень вовлечённости и временные метки для аналитики и отчётов. В групповых отчётах данные обезличиваются.")}
      ${section("👥", "Кто имеет доступ", "Доступ зависит от роли пользователя. Студенты видят только собственную сводку, если они дали согласие. Преподаватели видят агрегированную аналитику по своим группам и сессиям. Администраторы управляют пользователями и настройками системы.")}
      ${section("📅", "Срок хранения", "Срок хранения данных может настраиваться вашей организацией. Вы можете запросить удаление своих данных, и мы обработаем такой запрос в соответствии с применимыми правилами и требованиями.")}
      ${section("🛡️", "Ваше согласие", "Участие в видеоаналитике требует вашего явного согласия. Вы можете дать или отозвать согласие в любой момент в центре согласия. Без согласия кадры не обрабатываются и не анализируются.")}

      <div class="note">
        <div class="icon">✓</div>
        <div>
          <strong>KonilAI бережно относится к приватности пользователей.</strong>
          Данные используются только для улучшения образовательного процесса и строго в соответствии
          с принципами этики и конфиденциальности.
        </div>
      </div>

      <div class="footer">
        <div>KonilAI · Privacy Policy</div>
        <div class="status">Согласие управляется пользователем</div>
      </div>
    </section>
  </main>
</body>
</html>
`
}

function section(icon, title, body) {
    return `
      <div class="section">
        <div class="icon">${icon}</div>
        <div>
          <h2>${title}</h2>
          <p>${body}</p>
        </div>
      </div>
    `
}

export default router