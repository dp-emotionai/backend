import pkg from "@prisma/client";

const { PrismaClient } = pkg;

/** @type {import("@prisma/client").PrismaClient} */
const prisma = new PrismaClient();

export default prisma;