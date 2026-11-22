-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateTable
CREATE TABLE "Leaf" (
    "idx" INTEGER NOT NULL,
    "entry" JSONB NOT NULL,
    "leafHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Leaf_pkey" PRIMARY KEY ("idx")
);

-- CreateTable
CREATE TABLE "Sth" (
    "treeSize" INTEGER NOT NULL,
    "rootHash" TEXT NOT NULL,
    "timestamp" TEXT NOT NULL,
    "logSig" TEXT NOT NULL,
    "cosigs" JSONB NOT NULL DEFAULT '[]',

    CONSTRAINT "Sth_pkey" PRIMARY KEY ("treeSize")
);

