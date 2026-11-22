"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Radio, ShieldCheck } from "lucide-react";

const links = [["/", "Overview"], ["/releases", "Releases"], ["/log", "Log"], ["/witnesses", "Witnesses"], ["/fleet", "Fleet"], ["/attack", "Attack"], ["/verify", "Verify"]];

export function Nav() {
  const path = usePathname();
  return (
    <nav className="sticky top-0 z-20 border-b border-line bg-bg/70 backdrop-blur-xl">
      <div className="mx-auto flex max-w-[1800px] flex-wrap items-center gap-x-10 gap-y-3 px-6 py-5 sm:px-12">
        <Link href="/" className="flex items-center gap-3 text-xl font-semibold tracking-tight">
          <ShieldCheck className="size-7 text-ok" /> Update Witness
        </Link>
        <div className="flex flex-wrap gap-2">
          {links.map(([href, label]) => {
            const on = href === "/" ? path === "/" : path.startsWith(href);
            return <Link key={href} href={href} className={`rounded-full px-5 py-2 text-base transition ${on ? "bg-ink text-bg" : "text-mute hover:bg-line hover:text-ink"}`}>{label}</Link>;
          })}
        </div>
        <span className="ml-auto flex items-center gap-2 text-sm text-mute">
          <span className="animate-pulse-ring size-2.5 rounded-full bg-ok" /> <Radio className="size-4" /> live
        </span>
      </div>
    </nav>
  );
}
