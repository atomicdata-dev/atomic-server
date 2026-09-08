/** NodeNext cannot follow this package subpath's bundled declaration file. */
declare module 'loro-crdt/web' {
  export * from 'loro-crdt';
  const init: (input?: unknown) => Promise<unknown>;

  export default init;
}
