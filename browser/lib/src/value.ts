import { JSONADParser } from './parse.js';
import type { Resource } from './resource.js';

export type JSONPrimitive = string | number | boolean;
export type JSONValue = JSONPrimitive | JSONObject | JSONArray | undefined;
export type JSONObject = { [member: string]: JSONValue };
export type JSONArray = Array<JSONValue>;

/**
 * Tries to convert the value as an array of resources, which can be both URLs
 * or Nested Resources. Throws an error when fails
 */
export function valToArray(val?: JSONValue): JSONArray {
  if (val === undefined) {
    throw new Error(`Not an array: ${val}, is ${typeof val}`);
  }

  if (val.constructor === Array) {
    // TODO: check this better
    return val;
  }

  throw new Error(`Not an array: ${val}, is a ${typeof val}`);
}

/** Tries to make a boolean from this value. Throws if it is not a boolean. */
export function valToBoolean(val?: JSONValue): boolean {
  if (typeof val !== 'boolean') {
    throw new Error(`Not a boolean: ${val}, is a ${typeof val}`);
  }

  return val;
}

/**
 * Tries to convert the value (timestamp or date) to a JS Date. Throws an error
 * when fails.
 */
export function valToDate(val?: JSONValue): Date {
  // If it's a unix epoch timestamp...
  if (typeof val === 'number') {
    const date = new Date(0); // The 0 there is the key, which sets the date to the epoch
    date.setUTCMilliseconds(val);

    return date;
  }

  if (typeof val === 'string') {
    return new Date(val.toString());
  }

  throw new Error(`Cannot be converted into Date: ${val}, is a ${typeof val}`);
}

/** Returns a number of the value, or throws an error */
export function valToNumber(val?: JSONValue): number {
  if (typeof val !== 'number') {
    throw new Error(`Not a number: ${val}, is a ${typeof val}`);
  }

  return val;
}

/** Returns a default string representation of the value. */
export function valToString(val: JSONValue): string {
  // val && val.toString();
  return val?.toString() ?? 'undefined';
}

/** Returns either the URL of the resource, or the NestedResource itself. */
export function valToResource(val: JSONValue): string | Resource {
  if (typeof val === 'string') {
    return val;
  }

  if (val instanceof Date) {
    throw new Error(`Not a resource: ${val}, is a Date`);
  }

  if (val?.constructor === Array) {
    throw new Error(`Not a resource: ${val}, is an Array`);
  }

  if (typeof val === 'object') {
    const parser = new JSONADParser();
    const [resource] = parser.parseObject(val as JSONObject, 'nested-resource');

    return resource;
  }

  if (typeof val !== 'object') {
    throw new Error(`Not a resource: ${val}, is a ${typeof val}`);
  }

  throw new Error(`Not a resource: ${val}, is a ${typeof val}`);
}
