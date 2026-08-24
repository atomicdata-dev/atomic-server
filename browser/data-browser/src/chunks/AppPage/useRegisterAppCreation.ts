import { useEffect } from 'react';
import { useStore } from '@tomic/react';
import { constructOpenURL } from '@helpers/navigation';
import { useNavigateWithTransition } from '@hooks/useNavigateWithTransition';
import { createApp } from '@tomic/lib';
import { registerBasicInstanceHandler } from '@components/forms/NewForm/useNewResourceUI';
import { useAppClass } from '@chunks/PluginRuns/runScript';
import { handOverAppKey } from './appAgent';
import { STARTER_APP_SOURCE } from './starter';

/**
 * Makes "App" in the New menu build a working app.
 *
 * An App is not one resource. It is an app, its own ontology, a row class, a
 * table for its rows, the plugin that renders it and an identity to write as.
 * The generic new-resource form can only make the first of those, so choosing
 * App there produced something that asked the user to fill in an entry point
 * by hand and could never work.
 *
 * Registered from an effect rather than at module load because the App class
 * is minted per drive, so its subject is not known until one is open. The
 * registry is keyed by subject, so several drives can each register their own.
 */
export function useRegisterAppCreation(drive: string | undefined): void {
  const store = useStore();
  const appClass = useAppClass(drive);
  const navigate = useNavigateWithTransition();

  useEffect(() => {
    if (!appClass || !drive) return;

    registerBasicInstanceHandler(appClass, async (parent, _create, ctx) => {
      const created = await createApp(ctx.store, {
        drive,
        name: 'New app',
        // Every app carries a glyph, so a sidebar of them stays scannable.
        // A placeholder here because nobody has said yet what this one is;
        // an app built from a description picks its own.
        emoji: '🧩',
        source: STARTER_APP_SOURCE,
      });

      // The node needs the key to write as this app when nobody is present.
      // Reported rather than thrown: the app works while you are here either
      // way, it just cannot act on its own yet.
      try {
        await handOverAppKey(ctx.store, {
          drive,
          app: created.app,
          secret: created.secret,
        });
      } catch (e) {
        ctx.store.notifyError(e as Error);
      }

      // `parent` is where the user asked for it. An app is created on the
      // drive so its agent's rights sit somewhere predictable, so this is
      // ignored rather than quietly honoured.
      void parent;

      navigate(constructOpenURL(created.app));
    });
  }, [store, drive, appClass, navigate]);
}
