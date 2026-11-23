import { Title } from "@/components/ui";
import { Verifier } from "@/components/verifier";
import { publicVerifyConfig } from "@/lib/config";

export const dynamic = "force-dynamic";
export default function Verify() {
  return (<><Title sub="Paste a hash or drop a file. Every check runs in YOUR browser against the log and the witnesses, with keys pinned by this page, not fetched from them.">Public verifier</Title><Verifier cfg={publicVerifyConfig()} /></>);
}
