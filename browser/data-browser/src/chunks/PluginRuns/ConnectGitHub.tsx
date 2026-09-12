import { AppSetupForm } from '../../components/AppSetup/AppSetupForm';

/** Compatibility entrypoint for existing discovery links. The form is schema-driven. */
export function ConnectGitHub({
  drive,
  workspace,
}: {
  drive: string;
  workspace?: string;
}) {
  return (
    <AppSetupForm app='github-issues' drive={drive} workspace={workspace} />
  );
}
