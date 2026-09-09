// @wc-ignore-file
import {
  manifest,
  type Config,
} from '../../../../../integrations/clockify/model';

/** Parse only the installer's JSON trailer. Never evaluate installed code. */
export function clockifyUpgrade(
  installed: string,
  bundle: string,
): string | undefined {
  const match = installed.match(
    /\nconst settings=(\{[^\n]+\});\nexport const manifest=(\{[^\n]+\});\s*$/,
  );
  if (!match) return;

  try {
    const config = JSON.parse(match[1]) as Config;
    const declaration = JSON.parse(match[2]);
    if (
      JSON.stringify(declaration) !==
        JSON.stringify(manifest(config.workspace, config.user)) ||
      !config.workspace ||
      !config.user ||
      !config.table ||
      !config.drive ||
      !config.properties?.identity
    )
      return;
    const next = `${bundle}\nconst settings=${JSON.stringify(config)};\nexport const manifest=${JSON.stringify(manifest(config.workspace, config.user))};`;

    return next === installed ? undefined : next;
  } catch {
    return;
  }
}
