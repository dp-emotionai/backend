import path from "path";
import fs from "fs";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";

const SALT_ROUNDS = 10;

const candidates = [
    path.resolve(process.cwd(), ".env"),
    path.resolve("prisma", "..", ".env"),
];

for (const p of candidates) {
    if (fs.existsSync(p)) {
        dotenv.config({ path: p });
        break;
    }
}

const prisma = new PrismaClient();

async function main() {
    const email = process.env.ADMIN_EMAIL?.trim();
    const password = process.env.ADMIN_PASSWORD;

    if (!email || !password) {
        console.log("Seed: ADMIN_EMAIL и ADMIN_PASSWORD не заданы — админ не создаётся.");
        return;
    }

    const normalizedEmail = email.toLowerCase();

    const existing = await prisma.user.findUnique({
        where: { email: normalizedEmail },
    });

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    if (existing) {
        if (existing.role === "ADMIN") {
            console.log("Админ уже существует:", normalizedEmail);
            return;
        }

        await prisma.user.update({
            where: { email: normalizedEmail },
            data: {
                role: "ADMIN",
                password: passwordHash,
                name: existing.name || "Admin",
            },
        });

        console.log("Пользователь назначен админом:", normalizedEmail);
    } else {
        await prisma.user.create({
            data: {
                email: normalizedEmail,
                password: passwordHash,
                role: "ADMIN",
                name: "Admin",
            },
        });

        console.log("Создан админ:", normalizedEmail);
    }
}

main()
    .catch((e) => {
        console.error("Seed error:", e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });