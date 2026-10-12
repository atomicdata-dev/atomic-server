import {
  useEffectiveConstraint,
  type Constraint,
  type Property,
  type Resource,
} from '@tomic/react';

/** The subjects of a constraint's `enum`, i.e. the options of a select. */
export const optionSubjects = (constraint: Constraint): string[] =>
  (constraint.enum ?? []).filter((v): v is string => typeof v === 'string');

/**
 * A Property with a constraint laid over it: `allowsOnly`
 * becomes the class `enum` and `classType` the class `class`. Lets the readers
 * that take a plain `Property` (filters, quick add, row actions, input fields)
 * see class constraints without each one knowing about the class map.
 */
export const withConstraint = (
  property: Property,
  constraint: Constraint,
): Property => {
  const options = optionSubjects(constraint);

  return {
    ...property,
    allowsOnly: options.length > 0 ? options : property.allowsOnly,
    classType: constraint.class ?? property.classType,
  };
};

/**
 * `property` as it applies to `resource`: its classes' `constraints` over the
 * Property's legacy `allowsOnly` and `classtype`. A resource whose classes are
 * unknown (or have no map) gets the Property back as it is.
 */
export function useConstrainedProperty(
  resource: Resource,
  property: Property,
): Property {
  const constraint = useEffectiveConstraint(
    resource.getClasses(),
    property.subject,
  );

  if (property.loading || property.error) return property;

  return withConstraint(property, constraint);
}
