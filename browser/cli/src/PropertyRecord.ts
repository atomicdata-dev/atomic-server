import { __INTERNAL_GET_KNOWN_SUBJECT_MAPPING } from '@tomic/lib';

export class PropertyRecord {
  private knownProperties: Set<string>;
  private missingProperties = new Set<string>();

  public constructor() {
    this.knownProperties = new Set();
    // __INTERNAL_GET_KNOWN_SUBJECT_MAPPING().keys(),
  }

  public repordPropertyDefined(subject: string) {
    this.knownProperties.add(subject);

    if (this.missingProperties.has(subject)) {
      this.missingProperties.delete(subject);
    }
  }

  public reportPropertyUsed(subject: string) {
    if (!this.knownProperties.has(subject)) {
      this.missingProperties.add(subject);
    }
  }

  public getMissingProperties(): string[] {
    return Array.from(this.missingProperties);
  }
}
