import "./globals.css";
import { Hanken_Grotesk, Newsreader } from "next/font/google";
const head = Newsreader({ subsets: ["latin"], variable: "--font-head", style: ["normal", "italic"] });
const body = Hanken_Grotesk({ subsets: ["latin"], variable: "--font-body" });
import type { ReactNode } from "react";
import { Nav } from "@/components/nav";

export const metadata = { title: "Quorum", description: "Verifiable software updates: a release installs only if a quorum of witnesses has seen it" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${head.variable} ${body.variable}`}><body className="font-sans antialiased">
      <Nav />
      <main className="mx-auto w-full max-w-[1800px] px-6 py-12 sm:px-12">{children}</main>
    </body></html>
  );
}
