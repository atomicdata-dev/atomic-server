// required by atomic data lib
use atomic_lib::Storelike;
use atomic_lib::parse::parse_json_ad_resource;
//required by fluvio 

use async_std::stream::StreamExt;
use fluvio::FluvioError;
use fluvio::Offset;

const FLUVIO_TOPIC: &str = "atomic-data";
#[async_std::main]
async fn main() {
    // Collect our arguments into a slice of &str
    let args: Vec<String> = std::env::args().collect();
    let args_slice: Vec<&str> = args.iter().map(|s| &**s).collect();

    let result = match &*args_slice {
        [_, "produce_record"] => record().await,
        [_, "consume_record"] => consume().await,
        _ => {
            println!("Usage: atomic [produce|consume]");
            return;
        }
    };

    if let Err(err) = result {
        println!("Got error: {}", err);
    }
}
async fn produce(key: &str, value: &str) -> Result<(), FluvioError> {
    let producer = fluvio::producer(FLUVIO_TOPIC).await?;
    producer.send(key, value).await?;
    producer.flush().await?;
    Ok(())
}

async fn consume() -> Result<(), FluvioError> {


    let store = atomic_lib::Store::init().unwrap();
    let consumer = fluvio::consumer(FLUVIO_TOPIC, 0).await?;
    let mut stream = consumer.stream(Offset::beginning()).await?;

    // Iterate over all events in the topic
    while let Some(Ok(record)) = stream.next().await {
        let key_bytes = record.key().unwrap();
        let subject = String::from_utf8_lossy(key_bytes).to_string();
        let value = String::from_utf8_lossy(record.value()).to_string();
        let resource = parse_json_ad_resource(&value, &store);
        match resource {
            Ok(mut resource) => {
                println!("Saving resource:{}",&subject);
                //  same way as in basic example
                let agent = store.create_agent(Some("my_agent")).unwrap();
                store.set_default_agent(agent);
                resource.save_locally(&store).unwrap();
                println!("Saved resource:{}",&subject);
                },
            Err(e) => println!("error parsing resource: {e:?}"),
        }
        // println!("Consumed record: Key={}, value={:#?}", subject, resource);
    }
    Ok(())
}
async fn record()->Result<(), FluvioError> {
    //  Save and emit new resource record - class Article
    let tags = r#"["tag1","tag2"]"#;

    // Import the `Storelike` trait to get access to most functions
    use atomic_lib::Storelike;
    // Start with initializing the in-memory store
    let store = atomic_lib::Store::init().unwrap();
    // Pre-load the default Atomic Data Atoms (from atomicdata.dev),
    // this is not necessary, but will probably make your project a bit faster
    store.populate().unwrap();
    // We can create a new Resource, linked to the store.
    // Note that since this store only exists in memory, it's data cannot be accessed from the internet.
    // Let's make a new Property instance! Let's create "Article".
    let mut new_property =
        atomic_lib::Resource::new_instance("https://atomicdata.dev/classes/Article", &store)
            .unwrap();
    // And add a description for that Property
    new_property
        .set_propval_shortname("description", "Article", &store)
        .unwrap();
    new_property
        .set_propval_shortname("name", "Name", &store)
        .unwrap();
    new_property
        .set_propval_shortname("tags", tags, &store)
        .unwrap();
    // A subject URL for the new resource has been created automatically.
    let subject = new_property.get_subject().clone();
    // Now we need to make sure these changes are also applied to the store.
    // In order to change things in the store, we should use Commits,
    // which are signed pieces of data that contain state changes.
    // Because these are signed, we need an Agent, which has a private key to sign Commits.
    let agent = store.create_agent(Some("my_agent")).unwrap();
    store.set_default_agent(agent);
    new_property.save_locally(&store).unwrap();
    if let Ok(json) = &new_property.to_json_ad() {
        println!("{json}");
        produce(&subject, &json).await;
        println!("New article saved and emitted");
    }        
    
    
    // Now the changes to the resource applied to the store, and we can fetch the newly created resource!
    let fetched_new_resource = store.get_resource(&subject).unwrap();
    assert!(
        fetched_new_resource
            .get_shortname("description", &store)
            .unwrap()
            .to_string()
            == "Article"
    );
    Ok(())
}
