import { JSONADParser } from './parse.js';

const EXAMPLE_SUBJECT = 'http://example.com/1';
const EXAMPLE_SUBJECT2 = 'http://example.com/2';
const EXAMPLE_SUBJECT3 = 'http://example.com/3';
const EXAMPLE_SUBJECT4 = 'http://example.com/4';

const STRING_PROPERTY = 'http://some-string-property';
const NUMBER_PROPERTY = 'http://some-number-property';
const BOOLEAN_PROPERTY = 'http://some-boolean-property';
const NESTED_RESOURCE_PROPERTY = 'http://some-nested-resource-property';
describe('parse.ts', () => {
  it('parses a JSON-AD object and returns it as a resource', () => {
    const jsonObject = {
      '@id': EXAMPLE_SUBJECT,
      [STRING_PROPERTY]: 'Hoi',
      [NUMBER_PROPERTY]: 10,
      [BOOLEAN_PROPERTY]: true,
    };

    const parser = new JSONADParser();
    const [resource] = parser.parseObject(jsonObject);

    expect(resource.get(STRING_PROPERTY)).toBe('Hoi');
    expect(resource.get(NUMBER_PROPERTY)).toBe(10);
    expect(resource.get(BOOLEAN_PROPERTY)).toBe(true);
  });

  it('parses a JSON-AD object with a nested resource', () => {
    const jsonObjectWithID = {
      '@id': EXAMPLE_SUBJECT,
      [NESTED_RESOURCE_PROPERTY]: {
        '@id': EXAMPLE_SUBJECT2,
        [STRING_PROPERTY]: 'Hoi',
      },
    };

    const jsonObjectWithoutID = {
      '@id': EXAMPLE_SUBJECT,
      [NESTED_RESOURCE_PROPERTY]: {
        [STRING_PROPERTY]: 'Hoi',
      },
    };

    const jsonWithArrayOfResources = {
      '@id': EXAMPLE_SUBJECT,
      [NESTED_RESOURCE_PROPERTY]: [
        {
          '@id': EXAMPLE_SUBJECT2,
          [STRING_PROPERTY]: 'Hoi',
        },
        EXAMPLE_SUBJECT3,
        {
          [STRING_PROPERTY]: 'Hoi',
        },
      ],
    };

    const parser = new JSONADParser();
    const [resource1, parsedResources1] = parser.parseObject(jsonObjectWithID);

    const [resource2, parsedResources2] =
      parser.parseObject(jsonObjectWithoutID);

    const [resource3, parsedResources3] = parser.parseObject(
      jsonWithArrayOfResources,
    );

    expect(resource1.get(NESTED_RESOURCE_PROPERTY)).toBe(EXAMPLE_SUBJECT2);
    expect(parsedResources1).toHaveLength(2);
    expect(parsedResources1[1].get(STRING_PROPERTY)).toBe('Hoi');

    expect(resource2.get(NESTED_RESOURCE_PROPERTY)).toEqual({
      [STRING_PROPERTY]: 'Hoi',
    });

    expect(parsedResources2).toHaveLength(1);

    expect(resource3.get(NESTED_RESOURCE_PROPERTY)).toEqual([
      EXAMPLE_SUBJECT2,
      EXAMPLE_SUBJECT3,
      { [STRING_PROPERTY]: 'Hoi' },
    ]);

    expect(parsedResources3).toHaveLength(2);
  });

  it('parses an array of jsonObjects', () => {
    const array = [
      {
        '@id': EXAMPLE_SUBJECT,
        [STRING_PROPERTY]: 'First Resource',
      },
      {
        '@id': EXAMPLE_SUBJECT2,
        [STRING_PROPERTY]: 'Second Resource',
      },
      {
        '@id': EXAMPLE_SUBJECT3,
        [STRING_PROPERTY]: 'Third Resource',
        [NESTED_RESOURCE_PROPERTY]: {
          '@id': EXAMPLE_SUBJECT4,
          [STRING_PROPERTY]: 'Fourth Resource',
        },
      },
    ];

    const parser = new JSONADParser();
    const [resources, parsedResources] = parser.parseArray(array);

    expect(resources).toHaveLength(3);
    expect(parsedResources).toHaveLength(4);
  });

  it('Handles resources without an ID', () => {
    const jsonObject = {
      [STRING_PROPERTY]: 'Hoi',
    };

    const parser = new JSONADParser();
    const [resource] = parser.parseObject(jsonObject, 'my-new-id');

    expect(resource.get(STRING_PROPERTY)).toBe('Hoi');
    expect(resource.getSubject()).toBe('my-new-id');
  });
});
