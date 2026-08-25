import {
  core,
  forms,
  useArray,
  useResources,
  type Resource,
} from '@tomic/react';
import { useMemo } from 'react';
import type { FieldOption } from '@tomic/form-renderer';
import type { FormFieldType } from './fieldTypes';

export interface FormQuestionRef {
  subject: string;
  pageSubject: string;
  label: string;
  mapsTo: string;
  type: FormFieldType | string;
  /** Resolved options of a choice question, so a condition can offer labels
   * while storing the option's subject. */
  choiceOptions?: FieldOption[];
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

  // Choice options live on the mapped Property's `allowsOnly`, so resolving
  // them takes two more hops: the Properties, then their Tags. A question
  // borrowing another column's tags mirrors them here too (see
  // `applyOptionsSource`), so it lands in the same place. A *row*-sourced
  // question has no fixed list — `choiceOptions` stays undefined and
  // `ConditionsEditor` falls back to a free-text value input.
  const propertySubjects = useMemo(
    () =>
      [...fieldResources.values()]
        .map(f => f.get(forms.properties.formMapsTo) as string | undefined)
        .filter((s): s is string => !!s),
    [fieldResources],
  );
  const propertyResources = useResources(propertySubjects);

  const tagSubjects = useMemo(
    () =>
      [...propertyResources.values()].flatMap(
        p => (p.get(core.properties.allowsOnly) as string[] | undefined) ?? [],
      ),
    [propertyResources],
  );
  const tagResources = useResources(tagSubjects);

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
          choiceOptions: choiceOptionsFor(
            field.get(forms.properties.formMapsTo) as string | undefined,
          ),
        });
      }
    }

    return questions;

    function choiceOptionsFor(mapsTo?: string): FieldOption[] | undefined {
      const property = mapsTo ? propertyResources.get(mapsTo) : undefined;
      const tags = property?.get(core.properties.allowsOnly) as
        | string[]
        | undefined;

      if (!tags?.length) return undefined;

      return tags.map(subject => {
        const tag = tagResources.get(subject);
        const nonEmpty = (value: unknown) =>
          typeof value === 'string' && value !== '' ? value : undefined;

        return {
          value: subject,
          // Same precedence as `useTitle`: the free-text name, else the slug.
          label:
            nonEmpty(tag?.get(core.properties.name)) ??
            nonEmpty(tag?.get(core.properties.shortname)) ??
            subject,
        };
      });
    }
  }, [pages, pageResources, fieldResources, propertyResources, tagResources]);
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
