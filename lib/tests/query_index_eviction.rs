//! A row that is edited until it no longer satisfies a filter must leave that
//! filter's results.
//!
//! The query index caches the members of every watched query, so a narrowed
//! view is answered from that cache rather than by re-scanning. Eviction is
//! therefore not an optimisation but the correctness condition: whatever writes
//! a resource has to delete the entries its *previous* values earned it.
//!
//! `apply_commit` gets this right by construction (it is handed both the old and
//! the new resource). `add_resource` — the path the browser's local database
//! takes for every write it makes, and the CLI's `--import` — only has the new
//! one, and used to evict against it. These tests pin the whole-resource write
//! path specifically, because that is the one that was wrong.
//! Run: cargo test -p atomic_lib --features db-redb --test query_index_eviction
#![cfg(feature = "db-redb")]

use atomic_lib::{
    agents::ForAgent,
    storelike::{FilterOperator, PropVal, Query},
    urls, Db, Resource, Storelike, Subject, Value,
};

/// Stands in for a "quantity" column: any numeric property the store already
/// knows will do.
const QUANTITY: &str = urls::FILESIZE;

/// "Quantity at most `max`", sorted by quantity — the shape the data-browser
/// sends for a filtered table view.
fn low_stock_query(table: &str, max: i64) -> Query {
    Query {
        property: Some(urls::PARENT.into()),
        value: Some(Value::AtomicUrl(table.to_string().into())),
        filters: vec![PropVal {
            property: Some(QUANTITY.into()),
            value: Some(Value::Integer(max)),
            operator: FilterOperator::LessThanOrEqual,
        }],
        expression_filters: Vec::new(),
        limit: None,
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: Some(QUANTITY.into()),
        sort_desc: false,
        include_external: false,
        exclude_trashed: false,
        include_nested: false,
        for_agent: ForAgent::Sudo,
        drive: Some(atomic_lib::db::drive_prefix_from_subject(&Subject::from(
            table.to_string(),
        ))),
        aggregation: None,
    }
}

async fn stock_table(store: &Db, drive: &str) -> String {
    let table = store
        .create_resource(urls::FOLDER, drive, "Stock", None)
        .await
        .unwrap();

    for (name, quantity) in [("Screws", 2), ("Nails", 3), ("Bolts", 40)] {
        store
            .create_resource(
                urls::FOLDER,
                &table,
                name,
                Some(vec![(QUANTITY, Value::Integer(quantity))]),
            )
            .await
            .unwrap();
    }

    table
}

/// Rewrites `subject`'s quantity the way a whole-resource write does: read the
/// stored resource, change one value, hand the result to `add_resource`.
async fn restock(store: &Db, subject: &Subject, quantity: i64) {
    let mut resource = store.get_resource(subject).await.unwrap();
    resource
        .set_string(QUANTITY.into(), &quantity.to_string(), store)
        .await
        .unwrap();
    store.add_resource(&resource).await.unwrap();
}

/// The rows a query answers with, by name, in the order the index returned them.
/// Names come from re-reading each subject: `resources` is only populated for
/// queries that ask for it, and what is under test here is membership.
async fn names_in_order(store: &Db, query: &Query) -> Vec<String> {
    let result = store.query(query).await.unwrap();
    let mut names = Vec::new();

    for subject in &result.subjects {
        names.push(name_of(store, subject).await);
    }

    names
}

async fn name_of(store: &Db, subject: &Subject) -> String {
    store
        .get_resource(subject)
        .await
        .unwrap()
        .get_shortname("name", store)
        .await
        .unwrap()
        .to_string()
}

/// The same, sorted — for assertions that are about membership, not order.
async fn names_in(store: &Db, query: &Query) -> Vec<String> {
    let mut names = names_in_order(store, query).await;
    names.sort();
    names
}

/// Subjects are DIDs, so rows are located by the name they were given.
async fn subject_named(store: &Db, query: &Query, name: &str) -> Subject {
    let result = store.query(query).await.unwrap();

    for subject in &result.subjects {
        if name_of(store, subject).await == name {
            return subject.clone();
        }
    }

    panic!("no row named {name} in the query's results")
}

#[tokio::test]
async fn a_row_edited_out_of_a_filter_leaves_its_results() {
    let store = Db::init_temp("index_eviction_leaves").await.unwrap();
    let (_agent, drive) = store.setup("Alice").await.unwrap();
    let table = stock_table(&store, &drive).await;

    let query = low_stock_query(&table, 3);

    // Opening the view is what starts the index watching this filter, so it has
    // to happen before the edit — a filter nobody ever asked for has no cached
    // members to go stale.
    assert_eq!(
        names_in(&store, &query).await,
        vec!["Nails".to_string(), "Screws".to_string()],
        "two rows start out at or below 3"
    );

    let nails = subject_named(&store, &query, "Nails").await;

    // Restocked well past the threshold: it is no longer a low-stock row.
    restock(&store, &nails, 40).await;

    assert_eq!(
        names_in(&store, &query).await,
        vec!["Screws".to_string()],
        "the restocked row must be gone from the filtered view, not merely re-sorted"
    );
}

#[tokio::test]
async fn a_row_edited_into_a_filter_appears_and_is_sorted_by_its_new_value() {
    let store = Db::init_temp("index_eviction_enters").await.unwrap();
    let (_agent, drive) = store.setup("Alice").await.unwrap();
    let table = stock_table(&store, &drive).await;

    let query = low_stock_query(&table, 3);
    assert_eq!(names_in(&store, &query).await.len(), 2);

    // The mirror image: fixing eviction must not cost us admission. Bolts is
    // above the threshold, so it has to be looked up in the unfiltered query.
    let unfiltered = Query {
        filters: Vec::new(),
        ..low_stock_query(&table, 3)
    };
    let bolts = subject_named(&store, &unfiltered, "Bolts").await;

    restock(&store, &bolts, 1).await;

    assert_eq!(
        names_in_order(&store, &query).await,
        vec![
            "Bolts".to_string(),
            "Screws".to_string(),
            "Nails".to_string()
        ],
        "the row joins the view, filed under its new quantity (1, 2, 3)"
    );
}

#[tokio::test]
async fn a_row_that_stays_a_member_but_moves_is_listed_once() {
    let store = Db::init_temp("index_eviction_resorts").await.unwrap();
    let (_agent, drive) = store.setup("Alice").await.unwrap();
    let table = stock_table(&store, &drive).await;

    let query = low_stock_query(&table, 3);
    assert_eq!(
        names_in_order(&store, &query).await,
        vec!["Screws".to_string(), "Nails".to_string()],
        "2 before 3"
    );

    // Still low stock, but sorted differently now. Membership is unchanged, so
    // nothing about this edit looks like an eviction — and yet the entry has to
    // move, because the sort value is part of its key. Deleting the key the new
    // value implies (rather than the one the entry is actually filed under)
    // leaves the old entry behind and adds a second, listing one row twice.
    let screws = subject_named(&store, &query, "Screws").await;
    restock(&store, &screws, 3).await;

    let names = names_in_order(&store, &query).await;
    assert_eq!(
        names.len(),
        2,
        "two rows match, so two rows are listed: {names:?}"
    );
    assert_eq!(
        store.query(&query).await.unwrap().count,
        2,
        "and the count agrees with the rows"
    );
}

#[tokio::test]
async fn rewriting_a_row_without_touching_the_filtered_value_keeps_it() {
    let store = Db::init_temp("index_eviction_untouched").await.unwrap();
    let (_agent, drive) = store.setup("Alice").await.unwrap();
    let table = stock_table(&store, &drive).await;

    let query = low_stock_query(&table, 3);
    let before = names_in(&store, &query).await;

    // Evicting too eagerly would be just as wrong as not evicting: a write that
    // leaves the filtered value alone must leave membership alone.
    let screws = subject_named(&store, &query, "Screws").await;

    let mut resource: Resource = store.get_resource(&screws).await.unwrap();
    resource
        .set_string(urls::DESCRIPTION.into(), "Now with a description", &store)
        .await
        .unwrap();
    store.add_resource(&resource).await.unwrap();

    assert_eq!(
        names_in(&store, &query).await,
        before,
        "an unrelated edit changes nothing about who matches"
    );
}
