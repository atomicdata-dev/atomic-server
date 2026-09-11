//! The embedding lifecycle must not bind HTTP before handing control to a native adapter.
use atomic_lib::{agents::ForAgent, storelike::Query, urls, Resource, Storelike, Subject, Value};
use atomic_server_lib::{config, serve};

#[actix_web::test]
async fn native_node_works_when_http_port_is_occupied() {
    // Hold the configured port for the entire test: startup cannot secretly
    // bind it, and opting into HTTP must fail without destroying local data.
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unique = format!("http_optional_{}", atomic_lib::utils::random_string(10));
    let mut config = config::build_temp_config(&unique).unwrap();
    config.opts.ip = std::net::Ipv4Addr::LOCALHOST.into();
    config.opts.port = occupied.local_addr().unwrap().port().into();

    serve::run_node(config, |appstate| async move {
        let node = appstate.node();
        let mut events = node.db().subscribe_events();
        let (_agent, drive) = node.db().setup("Native user").await?;
        let drive = Subject::from(drive);
        let mut document = Resource::new("did:ad:placeholder".into());
        document.set_unsafe(urls::NAME.into(), Value::String("No HTTP needed".into()))?;
        document.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.clone()))?;
        let created = document.save_as_genesis(node.db()).await?;
        let subject = created.commit.subject;

        let found = node
            .query(&Query {
                property: Some(urls::PARENT.into()),
                value: Some(Value::AtomicUrl(drive)),
                for_agent: ForAgent::Sudo,
                ..Query::new()
            })
            .await?;
        assert!(found.subjects.contains(&subject));

        let error = serve::serve_http(appstate)
            .await
            .expect_err("the occupied HTTP port must fail");
        assert!(error.to_string().contains("Cannot bind"), "{error}");
        let stored = node.db().get_resource(&subject).await?;
        assert_eq!(stored.get(urls::NAME)?.to_string(), "No HTTP needed");
        let mut edited = stored;
        edited
            .set(
                urls::NAME.into(),
                Value::String("Still writable".into()),
                node.db(),
            )
            .await?;
        edited.save(node.db()).await?;
        assert_eq!(
            node.db()
                .get_resource(&subject)
                .await?
                .get(urls::NAME)?
                .to_string(),
            "Still writable"
        );
        let mut observed = false;
        while let Ok(event) = events.try_recv() {
            if let atomic_lib::db::DbEvent::Changed {
                subject: changed, ..
            } = event
            {
                observed |= changed.pure_id() == subject.pure_id();
            }
        }
        assert!(
            observed,
            "native subscribers must see local mutations without WebSocket"
        );
        node.db().flush()?;
        Ok(())
    })
    .await
    .expect("native startup and CRUD must be independent of HTTP binding");
}

#[actix_web::test]
async fn hosted_embedder_hook_still_runs_before_http_binding() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unique = format!(
        "http_optional_hook_{}",
        atomic_lib::utils::random_string(10)
    );
    let mut config = config::build_temp_config(&unique).unwrap();
    config.opts.ip = std::net::Ipv4Addr::LOCALHOST.into();
    config.opts.port = occupied.local_addr().unwrap().port().into();
    let called = std::cell::Cell::new(false);
    let error = serve::serve_with_hook(config, |appstate| {
        assert!(appstate.node().agent().is_some());
        appstate
            .managed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        called.set(true);
    })
    .await
    .expect_err("binding must fail after the embedder configures the node");
    assert!(
        called.get(),
        "managed embedders must get the ready hook before bind"
    );
    assert!(error.to_string().contains("Cannot bind"), "{error}");
}
