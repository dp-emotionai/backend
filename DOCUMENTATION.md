# ELAS Backend — Докладқа арналған қысқаша құжат

## 1. Қолданылған кітапханалар (Dependencies)

| Кітапхана | Нұсқа | Мақсаты |
|-----------|--------|---------|
| **express** | ^5.2.1 | HTTP API фреймворкі, маршрутизация, middleware |
| **@prisma/client** | ^5.22.0 | ORM — PostgreSQL дерекқорымен жұмыс |
| **prisma** | ^5.22.0 | Схема, миграциялар және Prisma CLI |
| **bcrypt** | ^6.0.0 | Парольдерді хэштеу |
| **jsonwebtoken** | ^9.0.3 | JWT access/refresh токендер |
| **cookie-parser** | ^1.4.7 | Cookie парсинг (refresh токендер үшін) |
| **cors** | ^2.8.6 | Cross-Origin запростерді рұқсат ету |
| **dotenv** | ^17.3.1 | `.env` орта айнымалылары |
| **express-rate-limit** | ^8.3.0 | Запростерді шектеу (DDoS қорғаныс) |
| **multer** | ^2.0.2 | Файл жүктеу (multipart/form-data) |
| **cloudinary** | ^1.41.3 | Бұлттық медиа сақтау (суреттер) |
| **multer-storage-cloudinary** | ^4.0.0 | Multer + Cloudinary интеграциясы |
| **node-fetch** | ^3.3.2 | HTTP сұраулар (сыртқы API) |
| **node-mailjet** | ^6.0.11 | Email жіберу (Mailjet) |
| **nodemailer** | ^8.0.2 | Email жіберу (альтернативті) |
| **resend** | ^6.9.3 | Email жіберу (Resend) |
| **pdfkit** | ^0.17.2 | PDF құжаттар генерациясы |
| **socket.io** | ^4.8.3 | Real-time байланыс (чат, уведомления) |
| **ws** | ^8.19.0 | WebSocket (raw) — эмоция/аналитика стриминг |
| **nodemon** | ^3.1.13 | Dev режимінде серверді автоматты қайта іске қосу |

### Әзірлеу құралдары (devDependencies)

| Құрал | Нұсқа | Мақсаты |
|-------|--------|---------|
| **prisma-erd-generator** | ^2.4.2 | ERD диаграммасын генерациялау (ERD.svg) |

---

## 2. Сыртқы қызметтер мен құралдар

- **PostgreSQL** — негізгі дерекқор
- **Cloudinary** — файл/сурет сақтау
- **Resend** — email жіберу
- **Node.js** — runtime (ES modules)
- **Prisma** — миграциялар, seed, ERD генерациясы

---

## 3. Архитектура

### 3.1 Жалпы құрылым

```
elas-backend/
├── prisma/
│   ├── schema.prisma    # Модельдер, enum, қатынастар
│   ├── migrations/      # SQL миграциялар
│   ├── seed.js          # Бастапқы деректер
│   └── ERD.svg          # Entity-Relation диаграммасы
├── src/
│   ├── server.js        # HTTP сервер + Socket.IO + raw WebSocket
│   ├── app.js           # Express app, CORS, маршрутар
│   ├── config/          # Конфигурация
│   ├── middleware/      # auth, rateLimit, error, notFound, role
│   ├── routes/          # API эндпоинттер (auth, users, notes, groups, ...)
│   ├── ws/              # WebSocket: server.js, raw.js, handler.js, rooms.js
│   └── utils/           # prisma, cloudinary, email, logger, audit
└── package.json
```

### 3.2 Қабаттар (Layers)

1. **Кіріс (Entry)**  
   `server.js` — HTTP сервер құрады, `app.js` (Express) пен WebSocket серверлерін қосады.

2. **Express қолданбасы**  
   `app.js` — CORS, cookie-parser, rate limit, JSON/urlencoded, статика (`/uploads`), барлық API маршрутар, 404 және глобалды error middleware.

3. **Маршруттар (Routes)**  
   Рөл бойынша бөлінген:
   - **auth** — логин, логаут, refresh, пароль қалпына келтіру
   - **users** — профиль, жаңарту
   - **notes, documents, noteUpload** — жазбалар мен құжаттар
   - **groups** — топтар, мүшелік
   - **sessions** — сабақ сессиялары
   - **analytics** — аналитика/эмоция деректері
   - **invitations** — топқа шақырулар
   - **search** — іздеу
   - **student, teacher, admin** — рөлге арналған API

4. **Middleware**  
   - Аутентификация (JWT), рөл тексеру  
   - Rate limiting  
   - 404 және орталықтандырылған error handler  

5. **Дерекқор**  
   Prisma ORM + PostgreSQL: User, Group, Session, Note, Document, Message, Invitation, Analytics, AuditLog және т.б. (схема `prisma/schema.prisma`).

6. **Real-time**  
   - **Socket.IO** — чат, бөлмелер  
   - **ws (raw)** — эмоция/аналитика стриминг  

7. **Утилиталар**  
   Prisma клиент, Cloudinary, email (Mailjet/Nodemailer/Resend), logger, audit.

### 3.3 API префикстері

| Префикс | Мақсаты |
|---------|--------|
| `/` | Hello / status |
| `/health` | Денсаулық тексеру |
| `/api/auth` | Аутентификация |
| `/api/users` | Пайдаланушылар |
| `/api/notes` | Жазбалар |
| `/api/documents` | Құжаттар |
| `/api/groups` | Топтар |
| `/api/sessions` | Сессиялар |
| `/api/analytics` | Аналитика |
| `/api/invitations` | Шақырулар |
| `/api/search` | Іздеу |
| `/api/student`, `/api/teacher`, `/api/admin` | Рөлдік API |
| `/notes/upload` | Жазбаға файл жүктеу |

---

## 4. Дерекқор модельдері (қысқаша)

- **User** — email, пароль, role (STUDENT/TEACHER/ADMIN), refresh токендер, ноталар, құжаттар, топтар, сессиялар
- **Group, GroupMember, Invitation** — топтар мен шақырулар
- **Session, SessionEmotionSample, SessionSummary, SessionTimelineBucket** — сабақ сессиялары және эмоциялық аналитика
- **Note, Document** — жазбалар мен файлдар
- **GroupMessage, SessionMessage, MessageRead** — чат және оқылғандық
- **ConsentRecord, AuditLog, PasswordResetToken, EmailCode** — келісім, аудит, қауіпсіздік

---

Бұл құжат докладқа «қолданылған кітапханалар, құралдар және архитектура» деген тақырыптарды қамтиды. Керек болса, кез келген бөлімді слайдтарға бөліп жазуға болады.
