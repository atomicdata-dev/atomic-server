// @wc-ignore-file
import { tool } from 'ai';
import { z } from 'zod';
import { setLocalStorageValue, useLocalStorage } from '@hooks/useLocalStorage';

import { TOOL_NAMES } from '../useAtomicTools';
import tablesSkillContent from './tables/SKILL.md?raw';
import creatingTablesContent from './tables/references/creating-tables.md?raw';
import skillCreationContent from './skill-creation/SKILL.md?raw';
import ontologiesSkillContent from './ontologies/SKILL.md?raw';

import { stringToSlug } from '@helpers/stringToSlug';

export interface AgentSkillMeta {
  id: string;
  name: string;
  description: string;
  disabled?: boolean;
  license?: string;
  compatibility?: string;
  metadata?: Record<string, string>;
  allowedTools?: string[];
}

export interface AgentSkillReference {
  path: string;
  content: string;
}

export interface AgentSkill {
  meta: AgentSkillMeta;
  content: string;
  references: AgentSkillReference[];
}

const SKILLS_LOCAL_STORAGE_KEY = 'atomic.ai.user-skills';

export const atomicSkills: AgentSkill[] = [
  {
    meta: {
      id: 'atomic.skills.tables',
      name: 'table-resources',
      description:
        'Use this when you need to create or modify a [table](https://atomicdata.dev/classes/Table) resource or add/remove data from a table.',
    },
    content: tablesSkillContent,
    references: [
      {
        path: '/creating-tables',
        content: creatingTablesContent,
      },
    ],
  },
  {
    meta: {
      id: 'atomic.skills.skill-creation',
      name: 'skill-creation',
      description:
        'Use this the user asks you to create a new skill. This is not needed to use other skills.',
    },
    content: skillCreationContent,
    references: [],
  },
  {
    meta: {
      id: 'atomic.skills.ontologies',
      name: 'ontology-resources',
      description:
        'Use this skill when you need to build schemas, it contains instructions on how ontologies work and what steps are needed to create them.',
    },
    content: ontologiesSkillContent,
    references: [],
  },
];

function formatSkillsMeta(skills: AgentSkill[]): string {
  return skills
    .map(skill => `- ${skill.meta.name}: ${skill.meta.description}`)
    .join('\n');
}

export const getSkillsSystemPromptPart = () => {
  const allSkills = getAllEnabledSkills();

  return `
There are a few skills available to use if needed.
To read a skill, use the \`read_skill\` tool with the skill name from the list (e.g. create-table).
To load an extra file attached to a skill (paths like filesystem paths), use \`read_skill_reference\` with the skill name and the reference path.
The following skills are available:
${formatSkillsMeta(allSkills)}
`;
};

function getUserSkills(): AgentSkill[] {
  try {
    const data = localStorage.getItem(SKILLS_LOCAL_STORAGE_KEY);

    if (data) {
      return JSON.parse(data);
    }
  } catch (e) {
    console.error('Failed to parse user skills from localStorage', e);
  }

  return [];
}

export function getAllEnabledSkills(): AgentSkill[] {
  return [...atomicSkills, ...getUserSkills()].filter(s => !s.meta.disabled);
}

export function getAllSkills(): AgentSkill[] {
  return [...getUserSkills(), ...atomicSkills];
}

export function findSkillByName(name: string): AgentSkill | undefined {
  const trimmed = name.trim();

  return getAllEnabledSkills().find(s => s.meta.name === trimmed);
}

function isBundledSkillName(normalizedName: string): boolean {
  return atomicSkills.some(s => s.meta.name === normalizedName);
}

function generateUserSkillId(): string {
  return `user-skill.${crypto.randomUUID()}`;
}

function persistUserSkills(skills: AgentSkill[]): void {
  setLocalStorageValue(SKILLS_LOCAL_STORAGE_KEY, skills);
}

export const useSkillsConfig = () => {
  const [userSkills, setUserSkills] = useLocalStorage<AgentSkill[]>(
    SKILLS_LOCAL_STORAGE_KEY,
    [],
  );

  const saveUserSkills = (newSkills: AgentSkill[]) => {
    setUserSkills(newSkills);
  };

  return {
    userSkills,
    saveUserSkills,
  };
};

/** Normalize reference paths for matching (slashes, trim, leading ./). */
function normalizeSkillReferencePath(path: string): string {
  return path
    .trim()
    .replace(/\\/g, '/')
    .replace(/\/+/g, '/')
    .replace(/^\.\//, '')
    .replace(/^\/+/, '');
}

/** Tools for reading bundled skills and their references */
export const skillTools = {
  [TOOL_NAMES.READ_SKILL]: tool({
    description:
      'Read the full markdown content of a bundled agent skill. Pass the skill name exactly as listed above (e.g. create-table).',
    inputSchema: z.object({
      name: z
        .string()
        .min(1)
        .describe('Skill name from the list, e.g. create-table.'),
    }),
    execute: async ({ name }: { name: string }) => {
      const found = findSkillByName(name);

      if (!found) {
        return {
          error: `No skill named "${name.trim()}". Use a name from the skills list.`,
        };
      }

      return {
        name: found.meta.name,
        content: found.content,
      };
    },
    strict: true,
  }),
  [TOOL_NAMES.READ_SKILL_REFERENCE]: tool({
    description:
      'Read a supplementary markdown or text file bundled with a skill. Paths look like filesystem paths (e.g. docs/setup.md) and are listed in the skill when references exist. Use read_skill first if you need the main skill body.',
    inputSchema: z.object({
      skillName: z
        .string()
        .min(1)
        .describe('Skill name from the list, e.g. create-table.'),
      path: z
        .string()
        .min(1)
        .describe(
          'Reference path as given by the skill, similar to a file path (e.g. /example.json).',
        ),
    }),
    execute: async ({ skillName, path }) => {
      const found = findSkillByName(skillName);

      if (!found) {
        return {
          error: `No skill named "${skillName.trim()}". Use a name from the skills list.`,
        };
      }

      const normalized = normalizeSkillReferencePath(path);
      const ref = found.references.find(
        r => normalizeSkillReferencePath(r.path) === normalized,
      );

      if (!ref) {
        const available = found.references.map(r => r.path);

        return {
          error:
            available.length === 0
              ? `Skill "${found.meta.name}" has no bundled references.`
              : `No reference path "${path.trim()}" for skill "${found.meta.name}". Available paths: ${available.join(', ')}`,
        };
      }

      return {
        skillName: found.meta.name,
        path: ref.path,
        content: ref.content,
      };
    },
    strict: true,
  }),
  [TOOL_NAMES.CREATE_SKILL]: tool({
    description:
      'Create a new agent skill, or set override to update a saved user skill by name. You provide the name, description, content and optional references. Only use this tool when the user explicitly asks you to build or change a skill.',
    inputSchema: z.object({
      name: z
        .string()
        .nonempty()
        .describe(
          'The name of the new skill (shown to both the user and the agent).',
        ),
      description: z
        .string()
        .nonempty()
        .describe(
          'The short description of when to use the skill (shown to both the user and the agent).',
        ),
      content: z
        .string()
        .nonempty()
        .describe(
          'The main markdown body of the skill (instructions for the agent).',
        ),
      references: z
        .array(
          z.object({
            path: z.string().describe('The path of the reference.'),
            content: z.string().describe('The content of the reference.'),
          }),
        )
        .optional()
        .describe(
          'Optional supplementary files referenced by path from the skill.',
        ),
      override: z
        .boolean()
        .optional()
        .describe(
          'If true, replace the existing user-saved skill with this name. Omit or false to create only when the name is free.',
        ),
    }),
    execute: async ({ name, description, content, references, override }) => {
      const normalizedName = stringToSlug(name);

      if (!normalizedName) {
        return { error: 'Skill name cannot be empty.' };
      }

      const userSkills = getUserSkills();
      const userIndex = userSkills.findIndex(
        s => s.meta.name === normalizedName,
      );

      if (override === true) {
        if (isBundledSkillName(normalizedName)) {
          return {
            error: `Cannot override bundled skill "${normalizedName}".`,
          };
        }

        if (userIndex === -1) {
          return {
            error: `No user skill named "${normalizedName}" to update. Omit override to create a new skill.`,
          };
        }

        const prev = userSkills[userIndex];
        const updated: AgentSkill = {
          meta: {
            ...prev.meta,
            name: normalizedName,
            description: description.trim(),
          },
          content,
          references: references ?? [],
        };
        const next = [...userSkills];
        next[userIndex] = updated;
        persistUserSkills(next);

        return {
          id: updated.meta.id,
          name: updated.meta.name,
          message: `Skill "${updated.meta.name}" was updated and saved.`,
        };
      }

      if (findSkillByName(normalizedName)) {
        return {
          error: `A skill named "${normalizedName}" already exists. Pass override: true to replace a user skill, or choose a different name.`,
        };
      }

      const newSkill: AgentSkill = {
        meta: {
          id: generateUserSkillId(),
          name: normalizedName,
          description: description.trim(),
        },
        content,
        references: references ?? [],
      };

      const next = [...userSkills, newSkill];
      persistUserSkills(next);

      return {
        id: newSkill.meta.id,
        name: newSkill.meta.name,
        message: `Skill "${newSkill.meta.name}" was created and saved.`,
      };
    },
    strict: true,
  }),
};
