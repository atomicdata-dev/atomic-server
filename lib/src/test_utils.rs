use crate::{Store, Storelike};

/// Creates a populated Store with an agent (testman) and one test resource (_:test)
pub fn init_store() -> Store {
  let store = Store::init().unwrap();
  store.populate().unwrap();
  let agent = store.create_agent(None).unwrap();
  store.set_default_agent(agent);
  store
}
