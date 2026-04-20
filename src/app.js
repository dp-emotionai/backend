import express from "express"
import cors from "cors"
import cookieParser from "cookie-parser"

import rateLimit from "./middleware/rateLimit.js"
import errorMiddleware from "./middleware/errorMiddleware.js"
import notFoundMiddleware from "./middleware/notFoundMiddleware.js"

import authRoutes from "./routes/auth.js"
import usersRoutes from "./routes/users.js"
import notesRoutes from "./routes/notes.js"
import noteUploadRoutes from "./routes/noteUpload.js"
import documentsRoutes from "./routes/documents.js"
import groupsRoutes from "./routes/groups.js"
import sessionsRoutes from "./routes/sessions.js"
import analyticsRoutes from "./routes/analytics.js"
import invitationsRoutes from "./routes/invitations.js"
import searchRoutes from "./routes/search.js"
import studentRoutes from "./routes/student.js"
import teacherRoutes from "./routes/teacher.js"
import adminRoutes from "./routes/admin.js"
import userSettingsRoutes from "./routes/userSettings.js";

const app = express()

app.set("trust proxy", 1)

app.use(
    cors({
        origin: [
            "https://www.konilai.space",
            "http://localhost:3000",
        ],
        credentials: true,
    })
)
app.use(express.json({ limit: "100kb" }))
app.use(express.urlencoded({ extended: true, limit: "100kb" }))
app.use(cookieParser())
app.use(rateLimit)
app.use("/uploads", express.static("uploads"))

/* ROUTES */
app.get("/", (req, res) => {
    res.json({ message: "Konil Backend Running", status: "ok" })
})
app.get("/health", (req, res) => {
    res.json({ status: "ok" })
})

app.use("/api/auth", authRoutes)
app.use("/api/users", usersRoutes)
app.use("/api/notes", notesRoutes)
app.use("/api/documents", documentsRoutes)
app.use("/api/groups", groupsRoutes)
app.use("/api/sessions", sessionsRoutes)
app.use("/api/analytics", analyticsRoutes)
app.use("/api/invitations", invitationsRoutes)
app.use("/api/search", searchRoutes)
app.use("/api/student", studentRoutes)
app.use("/api/teacher", teacherRoutes)
app.use("/api/admin", adminRoutes)
app.use("/api/user", userSettingsRoutes);

app.use("/notes/upload", noteUploadRoutes)

app.use(notFoundMiddleware)
app.use(errorMiddleware)

export default app