-- AlterTable
ALTER TABLE "Group" ADD COLUMN     "imageUrl" TEXT;

-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "scheduledEndAt" TIMESTAMP(3),
ADD COLUMN     "scheduledStartAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "SessionEmotionSample" ADD COLUMN     "engagement" DOUBLE PRECISION,
ADD COLUMN     "fatigue" DOUBLE PRECISION,
ADD COLUMN     "stress" DOUBLE PRECISION;

-- AlterTable
ALTER TABLE "SessionMessage" ADD COLUMN     "attachment" JSONB,
ADD COLUMN     "deletedAt" TIMESTAMP(3),
ADD COLUMN     "editedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "SessionContent" (
    "sessionId" TEXT NOT NULL,
    "lessonPlan" TEXT,
    "keyPoints" JSONB,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SessionContent_pkey" PRIMARY KEY ("sessionId")
);

-- CreateTable
CREATE TABLE "SessionWhiteboard" (
    "sessionId" TEXT NOT NULL,
    "elements" JSONB NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SessionWhiteboard_pkey" PRIMARY KEY ("sessionId")
);

-- CreateTable
CREATE TABLE "SessionParticipantState" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "joinedAt" TIMESTAMP(3),
    "leftAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SessionParticipantState_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WhiteboardOperation" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "version" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WhiteboardOperation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Material" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "fileName" TEXT NOT NULL,
    "mimeType" TEXT,
    "storageKey" TEXT NOT NULL,
    "size" INTEGER,
    "ownerId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Material_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MaterialAssignment" (
    "id" TEXT NOT NULL,
    "materialId" TEXT NOT NULL,
    "groupId" TEXT,
    "sessionId" TEXT,
    "visibleFrom" TIMESTAMP(3),
    "visibleTo" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MaterialAssignment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CalendarEvent" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "startsAt" TIMESTAMP(3) NOT NULL,
    "endsAt" TIMESTAMP(3),
    "groupId" TEXT,
    "sessionId" TEXT,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CalendarEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Notification" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "title" TEXT,
    "body" TEXT,
    "data" JSONB,
    "readAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Notification_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "SessionParticipantState_sessionId_userId_key" ON "SessionParticipantState"("sessionId", "userId");

-- CreateIndex
CREATE INDEX "WhiteboardOperation_sessionId_createdAt_idx" ON "WhiteboardOperation"("sessionId", "createdAt");

-- CreateIndex
CREATE INDEX "WhiteboardOperation_sessionId_version_idx" ON "WhiteboardOperation"("sessionId", "version");

-- CreateIndex
CREATE INDEX "MaterialAssignment_materialId_idx" ON "MaterialAssignment"("materialId");

-- CreateIndex
CREATE INDEX "MaterialAssignment_groupId_idx" ON "MaterialAssignment"("groupId");

-- CreateIndex
CREATE INDEX "MaterialAssignment_sessionId_idx" ON "MaterialAssignment"("sessionId");

-- CreateIndex
CREATE INDEX "Notification_userId_createdAt_idx" ON "Notification"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "SessionMessage_sessionId_createdAt_idx" ON "SessionMessage"("sessionId", "createdAt");

-- AddForeignKey
ALTER TABLE "SessionContent" ADD CONSTRAINT "SessionContent_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SessionWhiteboard" ADD CONSTRAINT "SessionWhiteboard_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SessionParticipantState" ADD CONSTRAINT "SessionParticipantState_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SessionParticipantState" ADD CONSTRAINT "SessionParticipantState_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WhiteboardOperation" ADD CONSTRAINT "WhiteboardOperation_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WhiteboardOperation" ADD CONSTRAINT "WhiteboardOperation_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Material" ADD CONSTRAINT "Material_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MaterialAssignment" ADD CONSTRAINT "MaterialAssignment_materialId_fkey" FOREIGN KEY ("materialId") REFERENCES "Material"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MaterialAssignment" ADD CONSTRAINT "MaterialAssignment_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "Group"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MaterialAssignment" ADD CONSTRAINT "MaterialAssignment_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CalendarEvent" ADD CONSTRAINT "CalendarEvent_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CalendarEvent" ADD CONSTRAINT "CalendarEvent_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "Group"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CalendarEvent" ADD CONSTRAINT "CalendarEvent_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
