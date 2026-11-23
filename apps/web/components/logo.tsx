/** Quorum mark: three witnesses, two of them agreeing (k of n). Filled = cosigned, outlined = not yet. */
export function Logo({ className = "size-8" }: { className?: string }) {
  return (
    <svg viewBox="0 0 48 48" className={className} role="img" aria-label="Quorum">
      <defs><linearGradient id="qg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#d9c7ff" /><stop offset="1" stopColor="#9d86e8" /></linearGradient></defs>
      <rect width="48" height="48" rx="13" fill="#0b0a10" />
      <circle cx="17" cy="19" r="9" fill="url(#qg)" fillOpacity=".92" />
      <circle cx="31" cy="19" r="9" fill="url(#qg)" fillOpacity=".92" style={{ mixBlendMode: "screen" }} />
      <circle cx="24" cy="31" r="9" fill="none" stroke="url(#qg)" strokeWidth="2" strokeDasharray="3 3" />
    </svg>
  );
}
