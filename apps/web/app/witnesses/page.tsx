import { Title } from "@/components/ui";
import { AutoRefresh } from "@/components/refresh";
import { WitnessesView } from "@/components/witnesses-view";
import { getMonitorAlerts, getWitnesses } from "@/lib/api";

export const dynamic = "force-dynamic";
export default async function Witnesses() {
  const [witnesses, monitor] = await Promise.all([getWitnesses(), getMonitorAlerts()]);
  return (<><AutoRefresh /><Title sub="Three independent witnesses check the log only grows, cosign its head, and gossip to catch split views. This is each witness's own state.">Witness network</Title><WitnessesView witnesses={witnesses} monitor={monitor} /></>);
}
