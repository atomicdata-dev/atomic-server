// @wc-ignore-file
import { useContext, useEffect, useState } from 'react';
import { useRouter } from '@tanstack/react-router';
import {
  getClassesOnDrive,
  shortenSubject,
  textSearch,
  useStore,
} from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { AIProvider } from '../components/AI/aiContstants';
import { useAtomicMCPTools, TOOL_NAMES } from '../chunks/AI/useAtomicTools';
import {
  getSkillsSystemPromptPart,
  skillTools,
} from '../chunks/AI/skills/skill';
import {
  stringifyTree,
  useGetDriveStructure,
} from '../chunks/AI/useGetDriveStructure';
import { getDefaultAgent } from '../chunks/AI/AgentConfig';
import { useTools } from '../chunks/AI/useTools';
import { LazyMCPContext } from '../components/AI/MCP/LazyMCPProvider';
import atomicAgentPrompt from '../chunks/AI/system-prompts/atomic-agent.md?raw';
import {
  fillAgentPrompt,
  registerAiTools,
  withSearchFallback,
  type EmbedAiTool,
} from './aiTools';

/** The agent whose MCP tools (web search) the app's chat offers. */
const AGENT_ID = 'dev.atomicdata.atomic-agent';

/**
 * How long registering waits for the agent's MCP tools (a remote server)
 * before going without them; less than the app's wait for the first request.
 */
const MCP_SETTLE_MS = 8_000;

/** Pages opened since the host mounted (see the effect in the host). */
const effects = { count: 0 };

/**
 * Headless: builds the web chat's tools and prompt with the web app's own
 * hooks and hands them to {@link registerAiTools}, for the app's AI chat
 * (`?ai=1`). Renders nothing. `drive` is the drive the app's chat is about.
 */
export function AiToolsHost({ drive }: { drive?: string }): null {
  const store = useStore();
  const settings = useSettings();
  const router = useRouter();
  const getDriveTree = useGetDriveStructure();
  const { tools: atomic } = useAtomicMCPTools({
    editModel: { id: 'app', provider: AIProvider.Hosted },
    hosted: true,
  });

  // The agent's MCP tools (web search), as the web chat gets them.
  const { load: loadMcp } = useContext(LazyMCPContext);
  const getToolsForAgent = useTools();
  const agent = getDefaultAgent(AGENT_ID);
  const mcp = agent ? getToolsForAgent(agent) : {};
  const mcpLoaded = Object.keys(mcp).length > 0;
  const [mcpGaveUp, setMcpGaveUp] = useState(false);

  useEffect(() => {
    loadMcp();
    const timer = setTimeout(() => setMcpGaveUp(true), MCP_SETTLE_MS);

    return () => clearTimeout(timer);
  }, [loadMcp]);

  // The drive the tools work on (they read it from the settings).
  useEffect(() => {
    if (drive && drive !== settings.drive) settings.setDrive(drive);
  }, [drive, settings]);

  // Moving the page is not something a tool can do here (the page is not
  // shown); a tool that did is reported as failed.
  useEffect(() => {
    effects.count = 0;

    return router.history.subscribe(() => {
      effects.count++;
    });
  }, [router]);

  const current = settings.drive;
  const ready = (!drive || current === drive) && (mcpLoaded || mcpGaveUp);

  useEffect(() => {
    if (!ready) return;

    const all = {
      ...atomic.read,
      ...atomic.write,
      ...skillTools,
      ...mcp,
    } as Record<string, EmbedAiTool>;
    const search = all[TOOL_NAMES.SEMANTIC_SEARCH];

    if (search) {
      all[TOOL_NAMES.SEMANTIC_SEARCH] = withSearchFallback(
        search,
        (query, limit) =>
          textSearch(store, query, { parents: [current], limit }),
      );
    }

    registerAiTools({
      tools: all,
      uiEffects: () => effects.count,
      systemPrompt: () =>
        fillAgentPrompt(atomicAgentPrompt, {
          drive: current,
          driveTree: async () => stringifyTree(await getDriveTree()),
          customClasses: async () =>
            Promise.all(
              (await getClassesOnDrive(current, store)).map(
                async cls =>
                  `${(await store.getResource(cls)).title}: ${shortenSubject(cls)}`,
              ),
            ),
          now: new Date(),
          skills: getSkillsSystemPromptPart(),
        }),
    });
  });

  useEffect(() => () => registerAiTools(undefined), []);

  return null;
}
