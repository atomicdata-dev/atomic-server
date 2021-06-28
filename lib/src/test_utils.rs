use crate::{Store, Storelike, parse::parse_ad3};

/// Creates a populated Store with an agent (testman) and one test resource (_:test)
pub fn init_store() -> Store {
  let string =
      String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"hi\"]");
  let store = Store::init().unwrap();
  store.populate().unwrap();
  let atoms = parse_ad3(&string).unwrap();
  let agent = store.create_agent(None).unwrap();
  store.set_default_agent(agent);
  store.add_atoms(atoms).unwrap();
  store
}
