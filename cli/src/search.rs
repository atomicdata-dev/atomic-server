use atomic_lib::{errors::AtomicResult, urls, Storelike};

pub fn search(context: &crate::Context, query: String) -> AtomicResult<()> {
    let opts = atomic_lib::client::search::SearchOpts {
        limit: Some(10),
        include: Some(true),
        ..Default::default()
    };
    let subject = atomic_lib::client::search::build_search_subject(
        &context.read_config().server,
        &query,
        opts,
    );
    let resource = context.store.get_resource(&subject)?;
    let members = resource
        .get(urls::ENDPOINT_RESULTS)
        .expect("No members?")
        .to_subjects(None)
        .unwrap();
    if members.is_empty() {
        println!("No results found.");
        println!("URL: {}", subject);
        return Ok(());
    } else {
        for member in members {
            println!("{}", member);
        }
    }
    Ok(())
}
