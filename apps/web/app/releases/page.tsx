import { Title } from "@/components/ui";
import { ReleasesTable } from "@/components/releases-table";

export default function Releases() {
  return (<><Title sub="Everything the vendor has signed and appended to the public log.">Vendor console</Title><ReleasesTable /></>);
}
