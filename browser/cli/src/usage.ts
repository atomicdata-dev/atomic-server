export const usage = `
ad-generate <command>

Commands:
  ontologies  Generates typescript files for ontologies specified in the config file.
  ontology    Pushes a JSON Schema or ontology file to the server and pins its property IDs in a lockfile (push, lock, check). Run it without arguments for details.
  init        Creates a template config file.
  connect     Gives this machine its own key for the server, approved in the app,
              so private ontologies can be read without an agent secret.
`;
