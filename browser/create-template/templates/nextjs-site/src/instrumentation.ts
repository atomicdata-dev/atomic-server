export async function register() {
  const ontologies = await import('@/ontologies');
  ontologies.initOntologies();
}
