import { AppSetupForm } from '@components/AppSetup/AppSetupForm';

export function ConnectNotionManual({ drive }: { drive: string }) {
  return <AppSetupForm app='notion' drive={drive} />;
}
