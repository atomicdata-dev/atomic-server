/**
 * # @tomic/lib Documentation
 *
 * Core typescript library for handling JSON-AD parsing, storing Atomic Data,
 * signing Commits, and more.
 *
 * [github repository](https://github.com/atomicdata-dev/atomic-data-browser)
 *
 * ## Features
 *
 * - Fetching Atomic Data
 * - Parsing JSON-AD
 * - Storing Atomic Data
 * - Data Validation
 * - Creating and signing {@link Commit}
 *
 * ## Usage
 *
 * You'll probably want to start by initializing a {@link Store}. Use methods
 * from the Store to load Resources. Use the {@link Resource} class to access,
 * edit and validate the data in a Resource. Use `Resource.save()` to save and
 * send edits to resources as Commits, or use the {@link Commit} class if you
 * need more control.
 *
 * ## Usage with react
 *
 * See `@tomic/react`, which provides various hooks for easy data usage.
 *
 * @module
 */

export * from './agent.js';
export * from './authentication.js';
export * from './class.js';
export * from './client.js';
export * from './commit.js';
export * from './error.js';
export * from './endpoints.js';
export * from './datatypes.js';
export * from './parse.js';
export * from './search.js';
export * from './resource.js';
export * from './store.js';
export * from './value.js';
export * from './urls.js';
export * from './truncate.js';
export * from './collection.js';
export * from './collectionBuilder.js';
