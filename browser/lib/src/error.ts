import { core } from './ontologies/core.js';
import type { Resource } from './resource.js';

export function getMessageForErrorType(error: Error) {
  if (isAtomicError(error)) {
    switch (error.type) {
      case ErrorType.NotFound:
        return 'Resource not found';
      case ErrorType.Unauthorized:
        return 'Unauthorized';
      case ErrorType.Server:
        return 'Server error';
      case ErrorType.Client:
        return 'Something went wrong';
      case ErrorType.Transport:
        return 'Could not reach the server';
    }
  } else {
    return 'Error loading resource';
  }
}

export enum ErrorType {
  Unauthorized = 'Unauthorized',
  NotFound = 'NotFound',
  Server = 'Server',
  Client = 'Client',
  /**
   * The request never got an answer: the fetch itself threw, or we knew
   * up front we were offline. Says nothing about the resource — only
   * that this client couldn't reach the server.
   */
  Transport = 'Transport',
}

/**
 * True when the error means "we couldn't reach the server", as opposed to
 * something the server told us about the resource (404, 401, 500).
 *
 * The distinction decides two things: whether a failed fetch may overwrite
 * state we already hold locally (it may not — an unreachable server is no
 * evidence about the resource), and whether reconnecting should retry the
 * resource (it should).
 */
export function isTransportError(error?: Error): boolean {
  return error instanceof AtomicError && error.type === ErrorType.Transport;
}

/**
 * The message a fetch fails with when the Store has no server to ask and the
 * local database does not hold the resource. Named so callers can tell this
 * apart from other transport errors: it means "nothing here", not "try again".
 */
export const NOT_AVAILABLE_LOCALLY_MESSAGE =
  'Offline: resource not available locally. Reconnect to fetch.';

/**
 * The same situation for a drive this device registered as local-only: no
 * server will ever be asked, and the local database has no copy. Signing out
 * leaves that registration in place while the (per-agent) database goes, so a
 * signed-out visitor to a drive they made here ends up exactly where a visitor
 * to one they never held does — and should be sent the same way, to sign in.
 */
export const LOCAL_ONLY_NOT_FOUND_MESSAGE =
  'This resource belongs to a local-only drive but was not found in local storage.';

/** True when the resource failed because no copy of it exists on this device. */
export function isNotAvailableLocally(error?: Error): boolean {
  return (
    isTransportError(error) &&
    (error!.message === NOT_AVAILABLE_LOCALLY_MESSAGE ||
      error!.message === LOCAL_ONLY_NOT_FOUND_MESSAGE)
  );
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

/** True when the error indicates the resource does not exist (e.g. no root resource yet). */
export function isNotFound(error?: Error): boolean {
  if (error instanceof AtomicError && error.type === ErrorType.NotFound) {
    return true;
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
  /**
   * Structured commit-error classification (F5, planning/unified-sync.md):
   * see `ws-v2.ts`'s `ErrorCode` / `lib/src/sync/protocol.rs`'s
   * `error_code`. `undefined` when the error didn't come from a commit
   * response (or predates this field) — callers fall back to matching
   * `message` text, as before.
   */
  public code?: number;

  /** Creates an AtomicError. The message can be either a plain string, or a JSON-AD Error Resource */
  public constructor(message: string, type = ErrorType.Client, code?: number) {
    super(message);
    // https://stackoverflow.com/questions/31626231/custom-error-class-in-typescript
    Object.setPrototypeOf(this, AtomicError.prototype);
    this.type = type;
    this.code = code;
    this.message = message;

    // The server should send Atomic Data Errors, which are JSON-AD resources with a Description.
    try {
      const parsed = JSON.parse(message);
      const description = parsed[core.properties.description];

      if (description) {
        this.message = description;
      }

      // F5 (planning/unified-sync.md): the HTTP `/commit` error body sets
      // this alongside `description` — see `server/src/errors.rs`. Only
      // trust it if the constructor caller didn't already pass one in
      // (the WS path decodes its own `code` off the binary frame).
      const errorCode = parsed['https://atomicdata.dev/properties/errorCode'];

      if (this.code === undefined && typeof errorCode === 'number') {
        this.code = errorCode;
      }
    } catch (e) {
      // ignore
    }

    if (!this.message) {
      this.message = this.createMessage();
    }
  }

  public static fromResource(r: Resource): AtomicError {
    const err = new AtomicError(r.get(core.properties.description)!.toString());

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

/** An operation cancelled by this client, rather than refused by the server. */
export class RequestCancelledError extends Error {
  override name = 'RequestCancelledError';
}

/**
 * The readable part of a failed HTTP response from an Atomic server.
 *
 * The server answers errors with a JSON-AD Error resource, which carries a
 * plain description alongside a Loro update and a class list. Showing the whole
 * body in a toast buries one sentence under a kilobyte of base64 — so this
 * returns the description, and falls back to the raw text only when the body is
 * not one of ours.
 */
export function errorMessageFromResponse(body: string, status: number): string {
  try {
    const parsed = JSON.parse(body);
    const description = parsed?.[core.properties.description];

    if (typeof description === 'string' && description.length > 0) {
      return description;
    }
  } catch {
    // Not JSON: fall through to the body itself.
  }

  const trimmed = body.trim();

  if (trimmed.length === 0) return `Request failed (${status})`;

  // A stray HTML error page is no more useful than the status alone.
  return trimmed.length > 300 ? `Request failed (${status})` : trimmed;
}
