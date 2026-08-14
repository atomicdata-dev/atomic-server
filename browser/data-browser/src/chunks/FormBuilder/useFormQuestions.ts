import {
  core,
  forms,
  useArray,
  useResources,
  type Resource,
} from '@tomic/react';
import { useMemo } from 'react';
import type { FormFieldType } from './fieldTypes';

export interface FormQuestionRef {
  subject: string;
  pageSubject: string;
  label: string;
  mapsTo: string;
  type: FormFieldType | string;
  choiceOptions?: string[];
}

/**
 * Every input FormField in the form, in page then field order. Layout
 * blocks are skipped — they have no `form-maps-to` to condition on.
 */
export function useFormQuestions(form: Resource): FormQuestionRef[] {
  const [pages] = useArray(form, forms.properties.formPages);
  const pageResources = useResources(pages);

  const fieldSubjects = useMemo(() => {
    const subjects: string[] = [];

    for (const pageSubject of pages) {
      const page = pageResources.get(pageSubject);
      const fields =
        (page?.get(forms.properties.formFields) as string[] | undefined) ?? [];
      subjects.push(...fields);
    }

    return subjects;
  }, [pages, pageResources]);

  const fieldResources = useResources(fieldSubjects);

  return useMemo(() => {
    const questions: FormQuestionRef[] = [];

    for (const pageSubject of pages) {
      const page = pageResources.get(pageSubject);
      const fields =
        (page?.get(forms.properties.formFields) as string[] | undefined) ?? [];

      for (const fieldSubject of fields) {
        const field = fieldResources.get(fieldSubject);

        if (
          !field ||
          field.loading ||
          !field.hasClasses(forms.classes.formField)
        ) {
          continue;
        }

        questions.push({
          subject: fieldSubject,
          pageSubject,
          label:
            (field.get(core.properties.name) as string | undefined) ??
            'Untitled',
          mapsTo:
            (field.get(forms.properties.formMapsTo) as string | undefined) ??
            '',
          type:
            (field.get(forms.properties.formFieldType) as string | undefined) ??
            'short-text',
          choiceOptions: choiceOptionsFrom(
            field.get(forms.properties.formFieldOptions),
          ),
        });
      }
    }

    return questions;
  }, [pages, pageResources, fieldResources]);
}

/** Questions the current field/page is allowed to condition on: earlier
 * in document order. Page conditions only see earlier pages, so a page
 * can't hide itself based on a question it contains. */
export function previousQuestions(
  questions: FormQuestionRef[],
  pages: string[],
  opts: { beforeField?: string; beforePage?: string },
): FormQuestionRef[] {
  if (opts.beforePage) {
    const idx = pages.indexOf(opts.beforePage);

    if (idx <= 0) return [];

    const allowed = new Set(pages.slice(0, idx));

    return questions.filter(q => allowed.has(q.pageSubject));
  }

  if (opts.beforeField) {
    const out: FormQuestionRef[] = [];

    for (const q of questions) {
      if (q.subject === opts.beforeField) break;

      out.push(q);
    }

    return out;
  }

  return questions;
}

function choiceOptionsFrom(raw: unknown): string[] | undefined {
  if (raw === undefined || raw === null) return undefined;

  let parsed: { options?: string[] } | undefined;

  if (typeof raw === 'string') {
    try {
      parsed = JSON.parse(raw) as { options?: string[] };
    } catch {
      return undefined;
    }
  } else if (typeof raw === 'object') {
    parsed = raw as { options?: string[] };
  }

  return parsed?.options;
}
