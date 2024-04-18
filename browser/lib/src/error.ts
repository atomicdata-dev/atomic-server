import { Resource, properties } from './index.js';

export enum ErrorType {
  Unauthorized = 'Unauthorized',
  NotFound = 'NotFound',
  Server = 'Server',
  Client = 'Client',
}

/** Pass any error. If the error is an AtomicError and it's Unauthorized, return true */
export function isUnauthorized(error?: Error): boolean {
  if (error instanceof AtomicError) {
    if (error.type === ErrorType.Unauthorized) {
      return true;
    } else if (error.message.includes('Unauthorized')) {
      return true;
    }
  }

  return false;
}

export function isAtomicError(error: Error): error is AtomicError {
  return error instanceof AtomicError;
}

/**
 * Atomic Data Errors have an additional Type, which tells the client what kind
 * of error to render.
 */
export class AtomicError extends Error {
  public type: ErrorType;

  /** Creates an AtomicError. The message can be either a plain string, or a JSON-AD Error Resource */
  public constructor(message: string, type = ErrorType.Client) {
    super(message);
    // https://stackoverflow.com/questions/31626231/custom-error-class-in-typescript
    Object.setPrototypeOf(this, AtomicError.prototype);
    this.type = type;
    this.message = message;

    // The server should send Atomic Data Errors, which are JSON-AD resources with a Description.
    try {
      const parsed = JSON.parse(message);
      const description = parsed[properties.description];

      if (description) {
        this.message = description;
      }
    } catch (e) {
      // ignore
    }

    if (!this.message) {
      this.message = this.createMessage();
    }
  }

  public static fromResource(r: Resource): AtomicError {
    const err = new AtomicError(r.get(properties.description)!.toString());

    return err;
  }

  public createMessage(): string {
    switch (this.type) {
      case ErrorType.Unauthorized:
        return "You don't have the rights to do this.";
      case ErrorType.NotFound:
        return '404 Not found.';
      case ErrorType.Server:
        return '500 Unknown server error.';
      default:
        return 'Unknown error.';
    }
  }
}
