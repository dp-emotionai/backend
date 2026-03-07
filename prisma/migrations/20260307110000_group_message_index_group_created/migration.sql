-- CreateIndex: speeds up WHERE groupId ORDER BY createdAt, id (cursor pagination, stable sort)
CREATE INDEX "GroupMessage_groupId_createdAt_id_idx" ON "GroupMessage"("groupId", "createdAt", "id");
