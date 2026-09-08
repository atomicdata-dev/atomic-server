// @wc-ignore-file
import { Datatype, type SchemaSpec } from '../../browser/lib/src/index.js';

/**
 * Code-first ontology for the trivial demo Pets collection. Shared within a
 * drive until frozen schema package distribution lands, same as the other
 * integrations' schemas.
 */
export function petsSchema(): SchemaSpec {
  const fields: Array<[string, string, string, Datatype]> = [
    ['pet-species', 'Species', 'The kind of animal, e.g. Dog or Cat.', Datatype.STRING],
    ['pet-breed', 'Breed', 'The breed or variety of the animal.', Datatype.STRING],
    ['pet-age', 'Age', 'Age in years.', Datatype.INTEGER],
    ['pet-mood', 'Mood', 'A playful, one-word description of the demo pet.', Datatype.STRING],
    [
      'pet-source-id',
      'Source identity',
      'Demo-source-qualified identity used to avoid duplicate imports. Not a display name.',
      Datatype.STRING,
    ],
  ];
  return {
    properties: fields.map(([shortname, name, description, datatype]) => ({
      shortname,
      name,
      description,
      datatype,
    })),
    classes: [
      {
        shortname: 'pet',
        name: 'Pet',
        description:
          'A demo companion animal. Static sample data, not a live provider.',
        requires: ['pet-species', 'pet-source-id'],
        recommends: ['pet-breed', 'pet-age', 'pet-mood'],
      },
    ],
  };
}
