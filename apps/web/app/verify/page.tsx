import { Title } from "@/components/ui";
import { Verifier } from "@/components/verifier";
export default function Verify() {
  return (<><Title sub="Paste a hash or drop a file. Each verification check shows as a pass or fail row.">Public verifier</Title><Verifier /></>);
}
