// @ts-check
import { adapter as jsx } from '@wuchale/jsx';
import { defineConfig } from 'wuchale';
import { generateText } from 'ai';
import { createOpenRouter } from '@openrouter/ai-sdk-provider';

const OPENROUTER_MODEL = 'deepseek/deepseek-v4-flash';

/** Custom wuchale AI provider using the Vercel AI SDK + OpenRouter. */
function openRouterTranslator({
  apiKey = process.env.OPENROUTER_API_KEY,
  model = OPENROUTER_MODEL,
  batchSize = 50,
  group = {},
  parallel = 4,
} = {}) {
  if (!apiKey) {
    return null;
  }

  const openrouter = createOpenRouter({ apiKey });

  return {
    name: `OpenRouter (${model})`,
    batchSize,
    group,
    parallel,
    /**
     * Translate the content using the OpenRouter model.
     * @param {string} content - The content to translate.
     * @param {string} instruction - The instruction to use for the translation.
     * @returns {Promise<string>} The translated text.
     */
    translate: async (content, instruction) => {
      const { text } = await generateText({
        model: openrouter(model),
        system: instruction,
        prompt: content,
      });

      return text;
    },
  };
}

// These strings will not be translated when present in script scopes.
const IGNORE_MESSAGES = [
  'Content-Type',
  'Authorization',
  'Bearer',
  'ArrowDown',
  'ArrowUp',
  'Enter',
  'Escape',
  'Tab',
  'Backspace',
  'Delete',
  'Shift',
  'Ctrl',
  'Alt',
  'SHA-256',
];

// Any strings defined in these functions will not be translated.
const IGNORED_FUNCTIONS = ['effectFetch', 'JSON.stringify', 'JSON.parse'];

export default defineConfig({
  // sourceLocale is en by default
  locales: ['en', 'es', 'fr', 'de'],
  // `group` batches all target locales into ONE model request instead of one
  // request per locale. In dev this matters a lot: wuchale's Vite transform
  // BLOCKS the module (and thus the HMR update) until translation finishes,
  // so ungrouped locales cost 3 sequential-ish OpenRouter round-trips
  // (~6.5s measured) for every new string, vs ~1 round-trip grouped.
  ai: openRouterTranslator({ group: { en: [['es', 'fr', 'de']] } }),
  adapters: {
    main: jsx({
      loader: 'react',
      heuristic: ({ msgStr, details }) => {
        const [msg] = msgStr;

        if (details.scope === 'script') {
          // Ignore certain functions
          if (details.call && IGNORED_FUNCTIONS.includes(details.call)) {
            // console.log('Ignoring', msg);
            return false;
          }

          // Ignore certain messages
          if (IGNORE_MESSAGES.includes(msg)) {
            // console.log('Ignoring', msg);

            return false;
          }
        }

        // Ignore words that are in full caps and only contain letters, digits, and underscores
        if (msg === msg.toUpperCase() && /^[A-Z0-9_]+$/.test(msg)) {
          // console.log('Ignoring', msg);
          return false;
        }
      },
    }),
  },
});
