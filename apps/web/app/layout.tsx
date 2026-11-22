import "./globals.css";
import type { ReactNode } from "react";
import { Nav } from "@/components/nav";

export const metadata = { title: "Update Witness", description: "Transparency layer for software updates" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en"><body className="font-sans antialiased">
      <Nav />
      <main className="mx-auto w-full max-w-[1800px] px-6 py-12 sm:px-12">{children}</main>
    </body></html>
  );
}
