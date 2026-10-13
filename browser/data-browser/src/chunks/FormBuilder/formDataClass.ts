// @wc-ignore-file
import {
  forms,
  setClassConstraint,
  useEffectiveConstraint,
  useResource,
  useString,
  type Constraint,
  type Resource,
} from '@tomic/react';
import { createContext, useCallback, useContext } from 'react';
import { optionSubjects } from '@helpers/withConstraint';

/**
 * The data class of the form being built. Every column's options and limits
 * are in its `constraints` map, so the settings panels read and write them
 * there. Provided by `FormBuilderPage`.
 */
export const FormDataClassContext = createContext<string | undefined>(
  undefined,
);

/** The data class of the form being built, if the panel sits inside one. */
export function useFormDataClass(): Resource {
  return useResource(useContext(FormDataClassContext));
}

/**
 * What applies to the column a question maps to: the data class's constraint,
 * with the Property's legacy `allowsOnly` / `classtype` / `min` / `max` as the
 * fallback for columns that predate the class map.
 */
export function useFieldConstraint(field: Resource): Constraint {
  const dataClassSubject = useContext(FormDataClassContext);
  const [mapsTo] = useString(field, forms.properties.formMapsTo);

  return useEffectiveConstraint(
    dataClassSubject ? [dataClassSubject] : [],
    mapsTo,
  );
}

/**
 * The option Tags of a choice question's column, and a setter that writes them
 * to the `enum` of the data class's constraint for it (keeping the other
 * keywords, such as `maxItems: 1`). Reading falls back to the Property's
 * legacy `allowsOnly`, so a form that predates the class map still lists its
 * options and moves them to the class on its first edit.
 */
export function useColumnOptions(
  propertySubject: string | undefined,
): [string[], (next: string[]) => Promise<void>] {
  const dataClassSubject = useContext(FormDataClassContext);
  const dataClass = useResource(dataClassSubject);
  const constraint = useEffectiveConstraint(
    dataClassSubject ? [dataClassSubject] : [],
    propertySubject,
  );

  const setOptions = useCallback(
    async (next: string[]) => {
      if (!propertySubject || !dataClassSubject) {
        throw new Error('This question has no data class to hold its options');
      }

      await setClassConstraint(dataClass, propertySubject, { enum: next });
      await dataClass.save();
    },
    [dataClass, dataClassSubject, propertySubject],
  );

  return [optionSubjects(constraint), setOptions];
}
