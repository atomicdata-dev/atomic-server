/** Browser consent is local to one actor and installation, not a plugin name. */
export function grantIdentity(
  server: string,
  drive: string,
  actor: string,
  installation: string,
): string {
  return `atomic.plugins.ui.v2.${JSON.stringify([server, drive, actor, installation])}`;
}
