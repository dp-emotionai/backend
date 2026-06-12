-- AlterTable
ALTER TABLE "Material" ADD COLUMN     "durationSec" INTEGER,
ADD COLUMN     "kind" TEXT NOT NULL DEFAULT 'file',
ADD COLUMN     "thumbnailStorageKey" TEXT;

-- AlterTable
ALTER TABLE "MaterialAssignment" ADD COLUMN     "assignedById" TEXT;

-- CreateTable
CREATE TABLE "Test" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "groupId" TEXT,
    "sessionId" TEXT,
    "createdById" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'draft',
    "timeLimitMinutes" INTEGER,
    "attemptsAllowed" INTEGER NOT NULL DEFAULT 1,
    "shuffleQuestions" BOOLEAN NOT NULL DEFAULT false,
    "shuffleOptions" BOOLEAN NOT NULL DEFAULT false,
    "startsAt" TIMESTAMP(3),
    "endsAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Test_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TestQuestion" (
    "id" TEXT NOT NULL,
    "testId" TEXT NOT NULL,
    "type" TEXT NOT NULL DEFAULT 'single_choice',
    "text" TEXT NOT NULL,
    "imageStorageKey" TEXT,
    "points" INTEGER NOT NULL DEFAULT 1,
    "order" INTEGER NOT NULL DEFAULT 0,
    "explanation" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TestQuestion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TestOption" (
    "id" TEXT NOT NULL,
    "questionId" TEXT NOT NULL,
    "text" TEXT,
    "imageStorageKey" TEXT,
    "isCorrect" BOOLEAN NOT NULL DEFAULT false,
    "order" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TestOption_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TestSubmission" (
    "id" TEXT NOT NULL,
    "testId" TEXT NOT NULL,
    "studentId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'submitted',
    "score" DOUBLE PRECISION,
    "maxScore" DOUBLE PRECISION,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "submittedAt" TIMESTAMP(3),

    CONSTRAINT "TestSubmission_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TestAnswer" (
    "id" TEXT NOT NULL,
    "submissionId" TEXT NOT NULL,
    "questionId" TEXT NOT NULL,
    "selectedOptionIds" JSONB,
    "textAnswer" TEXT,
    "isCorrect" BOOLEAN,
    "pointsEarned" DOUBLE PRECISION,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TestAnswer_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Test_groupId_idx" ON "Test"("groupId");

-- CreateIndex
CREATE INDEX "Test_sessionId_idx" ON "Test"("sessionId");

-- CreateIndex
CREATE INDEX "Test_createdById_idx" ON "Test"("createdById");

-- CreateIndex
CREATE INDEX "Test_status_idx" ON "Test"("status");

-- CreateIndex
CREATE INDEX "TestQuestion_testId_idx" ON "TestQuestion"("testId");

-- CreateIndex
CREATE INDEX "TestOption_questionId_idx" ON "TestOption"("questionId");

-- CreateIndex
CREATE INDEX "TestSubmission_testId_idx" ON "TestSubmission"("testId");

-- CreateIndex
CREATE INDEX "TestSubmission_studentId_idx" ON "TestSubmission"("studentId");

-- CreateIndex
CREATE UNIQUE INDEX "TestSubmission_testId_studentId_key" ON "TestSubmission"("testId", "studentId");

-- CreateIndex
CREATE INDEX "TestAnswer_submissionId_idx" ON "TestAnswer"("submissionId");

-- CreateIndex
CREATE INDEX "TestAnswer_questionId_idx" ON "TestAnswer"("questionId");

-- CreateIndex
CREATE INDEX "Material_ownerId_idx" ON "Material"("ownerId");

-- CreateIndex
CREATE INDEX "Material_kind_idx" ON "Material"("kind");

-- CreateIndex
CREATE INDEX "Material_createdAt_idx" ON "Material"("createdAt");

-- CreateIndex
CREATE INDEX "MaterialAssignment_assignedById_idx" ON "MaterialAssignment"("assignedById");

-- AddForeignKey
ALTER TABLE "MaterialAssignment" ADD CONSTRAINT "MaterialAssignment_assignedById_fkey" FOREIGN KEY ("assignedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Test" ADD CONSTRAINT "Test_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Test" ADD CONSTRAINT "Test_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "Group"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Test" ADD CONSTRAINT "Test_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TestQuestion" ADD CONSTRAINT "TestQuestion_testId_fkey" FOREIGN KEY ("testId") REFERENCES "Test"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TestOption" ADD CONSTRAINT "TestOption_questionId_fkey" FOREIGN KEY ("questionId") REFERENCES "TestQuestion"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TestSubmission" ADD CONSTRAINT "TestSubmission_testId_fkey" FOREIGN KEY ("testId") REFERENCES "Test"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TestSubmission" ADD CONSTRAINT "TestSubmission_studentId_fkey" FOREIGN KEY ("studentId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TestAnswer" ADD CONSTRAINT "TestAnswer_submissionId_fkey" FOREIGN KEY ("submissionId") REFERENCES "TestSubmission"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TestAnswer" ADD CONSTRAINT "TestAnswer_questionId_fkey" FOREIGN KEY ("questionId") REFERENCES "TestQuestion"("id") ON DELETE CASCADE ON UPDATE CASCADE;
