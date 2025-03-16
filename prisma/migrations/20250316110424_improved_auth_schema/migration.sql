/*
  Warnings:

  - You are about to drop the column `expires` on the `Token` table. All the data in the column will be lost.
  - You are about to drop the column `token` on the `Token` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[value]` on the table `Token` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[verifyToken]` on the table `User` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `expiresAt` to the `Token` table without a default value. This is not possible if the table is not empty.
  - Added the required column `value` to the `Token` table without a default value. This is not possible if the table is not empty.

*/
-- DropIndex
DROP INDEX "Token_token_key";

-- AlterTable
ALTER TABLE "Token" DROP COLUMN "expires",
DROP COLUMN "token",
ADD COLUMN     "expiresAt" TIMESTAMP(3) NOT NULL,
ADD COLUMN     "value" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "isVerified" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "lockExpires" TIMESTAMP(3),
ADD COLUMN     "loginAttempts" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "verifyToken" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "Token_value_key" ON "Token"("value");

-- CreateIndex
CREATE UNIQUE INDEX "User_verifyToken_key" ON "User"("verifyToken");
