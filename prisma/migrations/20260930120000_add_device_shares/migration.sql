-- AlterTable
ALTER TABLE "User" ADD COLUMN     "googleRefreshToken" TEXT;

-- CreateTable
CREATE TABLE "DeviceShare" (
    "id" BIGSERIAL NOT NULL,
    "deviceId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "userId" BIGINT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DeviceShare_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DeviceShare_userId_idx" ON "DeviceShare"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "DeviceShare_deviceId_email_key" ON "DeviceShare"("deviceId", "email");

-- AddForeignKey
ALTER TABLE "DeviceShare" ADD CONSTRAINT "DeviceShare_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "Device"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeviceShare" ADD CONSTRAINT "DeviceShare_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
