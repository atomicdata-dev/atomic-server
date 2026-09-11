// @wc-ignore-file
/**
 * Trivial static demo data. Deliberately not fetched from anywhere: this
 * integration exists to exercise the touch points a real provider plugin
 * would use (ontology, import mapping, sandboxed run, installable connection)
 * without needing an external API, secret or live account.
 */
export interface DemoPet {
  id: string;
  name: string;
  species: string;
  breed: string;
  age: number;
  mood: string;
}

export function demoPets(): DemoPet[] {
  return [
    { id: '1', name: 'Rex', species: 'Dog', breed: 'Labrador', age: 3, mood: 'Playful' },
    { id: '2', name: 'Whiskers', species: 'Cat', breed: 'Siamese', age: 5, mood: 'Curious' },
    { id: '3', name: 'Tweety', species: 'Bird', breed: 'Canary', age: 1, mood: 'Cheerful' },
    { id: '4', name: 'Nibbles', species: 'Rabbit', breed: 'Holland Lop', age: 2, mood: 'Shy' },
    { id: '5', name: 'Bubbles', species: 'Fish', breed: 'Goldfish', age: 1, mood: 'Calm' },
  ];
}
