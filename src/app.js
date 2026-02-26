import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.js";
import notesRoutes from "./routes/notes.js";
import documentsRoutes from "./routes/documents.js";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));

app.use("/auth", authRoutes);
app.use("/notes", notesRoutes);
app.use("/documents", documentsRoutes);

app.get("/", (req, res) => {
    res.json({ message: "ELAS Backend Running" });
});

export default app;