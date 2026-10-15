//! Sorting a query by `sortOrder` must fall back to `createdAt` for resources
//! without an explicit key: both live on one numeric axis, so positioned
//! resources (fractional keys, e.g. a table row inserted below another)
//! interleave with untouched ones and no migration is ever needed.
//! Run: cargo test -p atomic_lib --features db-redb --test sort_order_fallback
#![cfg(feature = "db-redb")]

use atomic_lib::{
    agents::ForAgent,
    storelike::{Query, QueryResult},
    urls, Db, Storelike, Subject, Value,
};

#[tokio::test]
async fn sort_order_falls_back_to_created_at() {
    let store = Db::init_temp("sort_order_fallback").await.unwrap();
    let (_agent, drive) = store.setup("Alice").await.unwrap();

    let table = store
        .create_resource(urls::FOLDER, &drive, "Table", None)
        .await
        .unwrap();

    // Two rows ordered by creation time only (no explicit key).
    let row1 = store
        .create_resource(urls::FOLDER, &table, "Row 1", None)
        .await
        .unwrap();
    // Ensure distinct createdAt timestamps.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let row2 = store
        .create_resource(urls::FOLDER, &table, "Row 2", None)
        .await
        .unwrap();

    // A row explicitly positioned between them: sortOrder = midpoint of the
    // neighbors' createdAt values (the client's insert-below computation).
    let created_at = |subject: &str| {
        let store = &store;
        let subject = Subject::from(subject.to_string());
        async move {
            store
                .get_resource(&subject)
                .await
                .unwrap()
                .get(urls::CREATED_AT)
                .unwrap()
                .to_int()
                .unwrap()
        }
    };
    let key1 = created_at(&row1).await as f64;
    let key2 = created_at(&row2).await as f64;
    let between = store
        .create_resource(
            urls::FOLDER,
            &table,
            "Row between",
            Some(vec![(urls::SORT_ORDER, Value::Float((key1 + key2) / 2.0))]),
        )
        .await
        .unwrap();

    let query = Query {
        property: Some(urls::PARENT.into()),
        value: Some(Value::AtomicUrl(table.clone().into())),
        filters: Vec::new(),
        expression_filters: Vec::new(),
        limit: None,
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: Some(urls::SORT_ORDER.into()),
        sort_desc: false,
        include_external: false,
        exclude_trashed: false,
        include_nested: false,
        for_agent: ForAgent::Sudo,
        drive: Some(atomic_lib::db::drive_prefix_from_subject(&Subject::from(
            table.clone(),
        ))),
        aggregation: None,
    };

    let QueryResult { subjects, .. } = store.query(&query).await.unwrap();
    let order: Vec<String> = subjects.iter().map(|s| s.to_string()).collect();

    assert_eq!(
        order,
        vec![row1, between, row2],
        "explicitly positioned row must interleave with createdAt-ordered rows"
    );
}

/// Same as above, but the query filter is watched BEFORE the rows exist — the
/// live table scenario. Rows are then indexed incrementally at commit time,
/// where genesis metadata (`createdAt`) may not be materialized into propvals
/// yet. The fallback must still find the creation time or every unkeyed row
/// lands on the NO_VALUE key (sorting after all keyed rows, in random order).
#[tokio::test]
async fn fallback_applies_to_incrementally_indexed_rows() {
    let store = Db::init_temp("sort_order_incremental").await.unwrap();
    let (_agent, drive) = store.setup("Alice").await.unwrap();

    let table = store
        .create_resource(urls::FOLDER, &drive, "Table", None)
        .await
        .unwrap();

    let query = Query {
        property: Some(urls::PARENT.into()),
        value: Some(Value::AtomicUrl(table.clone().into())),
        filters: Vec::new(),
        expression_filters: Vec::new(),
        limit: None,
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: Some(urls::SORT_ORDER.into()),
        sort_desc: false,
        include_external: false,
        exclude_trashed: false,
        include_nested: false,
        for_agent: ForAgent::Sudo,
        drive: Some(atomic_lib::db::drive_prefix_from_subject(&Subject::from(
            table.clone(),
        ))),
        aggregation: None,
    };

    // Watch the filter while the table is still empty, like a table page
    // being open during row entry.
    let QueryResult { subjects, .. } = store.query(&query).await.unwrap();
    assert!(subjects.is_empty());

    let row1 = store
        .create_resource(urls::FOLDER, &table, "Row 1", None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let row2 = store
        .create_resource(urls::FOLDER, &table, "Row 2", None)
        .await
        .unwrap();

    let created_at = |subject: &str| {
        let store = &store;
        let subject = Subject::from(subject.to_string());
        async move {
            store
                .get_resource(&subject)
                .await
                .unwrap()
                .get(urls::CREATED_AT)
                .unwrap()
                .to_int()
                .unwrap()
        }
    };
    let key1 = created_at(&row1).await as f64;
    let key2 = created_at(&row2).await as f64;
    let between = store
        .create_resource(
            urls::FOLDER,
            &table,
            "Row between",
            Some(vec![(urls::SORT_ORDER, Value::Float((key1 + key2) / 2.0))]),
        )
        .await
        .unwrap();

    let QueryResult { subjects, .. } = store.query(&query).await.unwrap();
    let order: Vec<String> = subjects.iter().map(|s| s.to_string()).collect();

    assert_eq!(
        order,
        vec![row1, between, row2],
        "rows indexed incrementally (filter watched before creation) must sort by the createdAt fallback"
    );
}
