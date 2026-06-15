CREATE TABLE "LessonPlan" (
                              "id" TEXT NOT NULL,
                              "sessionId" TEXT NOT NULL,
                              "teacherId" TEXT NOT NULL,
                              "date" TIMESTAMP(3) NOT NULL,
                              "title" TEXT NOT NULL,
                              "description" TEXT,
                              "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
                              "updatedAt" TIMESTAMP(3) NOT NULL,

                              CONSTRAINT "LessonPlan_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "LessonPlan_sessionId_date_key"
    ON "LessonPlan"("sessionId", "date");

ALTER TABLE "LessonPlan"
    ADD CONSTRAINT "LessonPlan_sessionId_fkey"
        FOREIGN KEY ("sessionId") REFERENCES "Session"("id")
            ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "LessonPlan"
    ADD CONSTRAINT "LessonPlan_teacherId_fkey"
        FOREIGN KEY ("teacherId") REFERENCES "User"("id")
            ON DELETE CASCADE ON UPDATE CASCADE;