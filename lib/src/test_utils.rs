/// Creates a populated Store with an agent (testman) and one test resource (_:test)
#[cfg(test)]
pub fn init_store() -> crate::Store {
    use crate::Storelike;

    let store = crate::Store::init().unwrap();
    store.populate().unwrap();
    let agent = store.create_agent(None).unwrap();
    store.set_default_agent(agent);
    store
}
