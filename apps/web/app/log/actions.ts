"use server";
import { getProof } from "@/lib/api";
export async function fetchProof(idx: number, treeSize: number) { return getProof(idx, treeSize); }
