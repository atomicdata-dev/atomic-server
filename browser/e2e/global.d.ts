import type { Resource, Store } from '@tomic/lib';

/**
 * A website config, as `starterWebsite` returns it.
 *
 * The authoritative shape is the zod schema in data-browser's
 * `chunks/Website/websiteModel.ts`. Only the fields the specs read or assign
 * are spelled out here: this project cannot import the app's own types, since
 * its modules pull in JSX and Vite-specific imports that the e2e tsconfig does
 * not compile.
 */
export interface WebsiteConfig {
  version: 1;
  title: string;
  pages: Array<{
    documents?: string[];
    media?: unknown[];
    tables?: unknown[];
    [key: string]: unknown;
  }>;
  [key: string]: unknown;
}

/** The website's hosting state, as the `/website-hosting` endpoint reports it. */
export interface HostingStatus {
  url: string;
  deployment?: string;
  state: null | {
    project: string;
    drive: string;
    revision: number;
    active: string | null;
    deployments: string[];
    versions?: Record<string, number>;
    history: Array<{ deployment: string | null; actor: string; at: number }>;
  };
}

/** A built, publishable copy of a website. Opaque to the specs. */
export interface WebsiteArtifact {
  version: 1;
  renderer: string;
  project: string;
  config: WebsiteConfig;
  createdAt?: string;
  [key: string]: unknown;
}

/** The schema `ensureSchema` registered for websites on a drive. */
export interface WebsiteSchema {
  classes?: Record<string, string>;
  properties?: Record<string, string>;
}

/**
 * App modules an E2E build exposes on `window`, so specs can drive them
 * against atomic-server's embedded bundle. See data-browser's
 * `helpers/e2eModules.ts`.
 */
export interface E2EModules {
  createTableFromSpec: {
    buildTableFromSpec(
      store: Store,
      spec: Record<string, unknown>,
      opts: {
        parent: string;
        driveSubject: string;
        addToOntology: (resource: Resource) => Promise<void>;
        installationKey?: string;
      },
    ): Promise<{ classSubject: string; [key: string]: unknown }>;
    resolveOntologyParent(store: Store, driveSubject: string): Promise<string>;
  };
  hostingClient: {
    hostingRequest<T = HostingStatus>(
      store: Store,
      project: string,
      path?: string,
      body?: unknown,
    ): Promise<T>;
  };
  optimizeWebsiteImage: {
    optimizeWebsiteImage(source: Blob): Promise<Blob>;
  };
  runScript: {
    createPlugin(
      store: Store,
      target: {
        parent: string;
        drive: string;
        localId?: string;
        workspace?: string;
        connections?: string[];
      },
      name?: string,
      source?: string,
      schemas?: Record<string, string>,
    ): Promise<string>;
  };
  tomicLib: {
    core: {
      classes: Record<string, string>;
      properties: Record<string, string>;
    };
    dataBrowser: {
      classes: Record<string, string>;
      properties: Record<string, string>;
    };
    ensureSchema(
      store: Store,
      drive: string,
      schema: unknown,
    ): Promise<{
      classes: Record<string, string>;
      properties: Record<string, string>;
    }>;
    findSchema(
      store: Store,
      drive: string,
      schema: unknown,
    ): Promise<{
      classes: Record<string, string>;
      properties: Record<string, string>;
    }>;
    pinPluginRelease(
      store: Store,
      target: { drive: string; plugin: string },
    ): Promise<{ id: string; [key: string]: unknown }>;
    pluginSchema(): unknown;
    taskSchema: {
      classes: Record<string, string>;
      properties: Record<string, string>;
      tags: Record<string, string>;
    };
  };
  websiteExport: {
    buildWebsiteArtifact(
      store: Store,
      project: string,
      config: WebsiteConfig,
    ): Promise<WebsiteArtifact>;
    saveWebsiteRelease(
      store: Store,
      drive: string,
      resource: Resource,
      artifact: WebsiteArtifact,
    ): Promise<HostingStatus>;
  };
  websiteModel: {
    createWebsite(
      store: Store,
      drive: string,
      config: WebsiteConfig,
    ): Promise<Resource>;
    readWebsite(
      store: Store,
      drive: string,
      resource: Resource,
    ): Promise<{
      config: WebsiteConfig;
      schema: WebsiteSchema;
      property: string;
    }>;
    starterWebsite(title?: string, document?: string): WebsiteConfig;
    updateWebsite(
      store: Store,
      drive: string,
      resource: Resource,
      config: WebsiteConfig,
    ): Promise<void>;
  };
  wsV2: {
    encodeSyncPush(
      driveSubject: string,
      entries: Array<{ subject: string; loroBytes: Uint8Array }>,
      last?: boolean,
    ): Uint8Array;
  };
}

declare global {
  interface Window {
    /** Set by data-browser `App.tsx` for debugging and e2e probes. */
    store: Store;
    /** Only present in a `VITE_E2E=true` build. See `helpers/e2eModules.ts`. */
    atomicE2E: E2EModules;
    __e2eLoad?: {
      longTasks: Array<{ start: number; duration: number }>;
      maxTimerLagMs: number;
    };
  }

  /** Opaque ranges over a form control's value — new enough that `lib.dom`
   * has no typing for it and most browsers no implementation. Optional here
   * for the same reason it is in `form-renderer/src/overflowHighlight.ts`:
   * the only interesting question is whether it exists. */
  interface HTMLInputElement {
    createValueRange?(start: number, end: number): AbstractRange;
  }
}
