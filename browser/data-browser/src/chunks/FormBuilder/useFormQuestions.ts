import {
  core,
  forms,
  getEffectiveConstraint,
  useArray,
  useResource,
  useResources,
  useStore,
  useString,
  useValue,
  type Resource,
  type Store,
} from '@tomic/react';
import { optionSubjects } from '@helpers/withConstraint';
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

  // Choice options are the `enum` of the data class's constraint for the
  // mapped column, so resolving them takes two more hops: the Properties (for
  // columns that predate the class map), then their Tags. A question borrowing
  // another column's tags mirrors them here too (see `applyOptionsSource`), so
  // it lands in the same place. A *row*-sourced question has no fixed list —
  // `choiceOptions` stays undefined and `ConditionsEditor` falls back to a
  // free-text value input.
  const store = useStore();
  const [dataClassSubject] = useString(form, forms.properties.formDataClass);
  const dataClass = useResource(dataClassSubject);
  // Read so a change to the class's constraints re-renders this hook.
  const [classConstraints] = useValue(dataClass, core.properties.constraints);
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
      [...propertyResources.keys()].flatMap(subject =>
        columnTags(store, dataClassSubject, subject, classConstraints),
      ),
    [store, dataClassSubject, propertyResources, classConstraints],
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
      const tags = mapsTo
        ? columnTags(store, dataClassSubject, mapsTo, classConstraints)
        : undefined;

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
  }, [
    pages,
    pageResources,
    fieldResources,
    tagResources,
    store,
    dataClassSubject,
    classConstraints,
  ]);
}

/**
 * The option Tags of a column: the `enum` of the data class's constraint, or
 * the Property's legacy `allowsOnly`. `classConstraints` is the class's raw
 * `constraints` value: it is not read here (the store is), but passing it makes
 * callers recompute when the class's map changes.
 */
function columnTags(
  store: Store,
  dataClassSubject: string | undefined,
  propertySubject: string,
  _classConstraints: unknown,
): string[] {
  return optionSubjects(
    getEffectiveConstraint(
      store,
      dataClassSubject ? [dataClassSubject] : [],
      propertySubject,
    ),
  );
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
