//! Bridge-level tests for the canvas editing session.
//!
//! These cover the layer the Flutter app actually calls — the cached, editable
//! `Resource` that `push_stroke` appends to — rather than the sync transport
//! underneath it (that lives in `atomic_lib`'s two-node `sync::iroh_e2e`
//! suite). The bugs that live here are *cache coherence* ones: the store
//! learns about a peer's stroke, the long-lived cached editing session does
//! not, and everything computed from that session is then computed from a
//! drawing that is missing strokes.
//!
//! Note what is deliberately *not* claimed below. Appending a stroke and
//! calling `save_locally` cannot lose a peer's op on its own: the commit is
//! imported into a freshly-read store doc, and a Loro import never removes
//! ops. The damage comes from *reads* off the stale session — an index-based
//! delete, or a whole-list rewrite computed from a list that was already
//! missing a stroke.
//!
//! The store is a process-global `OnceLock`, so every test shares one database
//! and isolates by taking its own canvas.

use super::*;

/// One database for the whole test binary — `state::DB` is a `OnceLock` and
/// cannot be re-set. Tests isolate by canvas, not by store.
/// Tests run in parallel against one store, and `create_drive` and the home
/// lists (favorites, conversations) are all read-modify-write on the private
/// drive: without this one-at-a-time lock one test's save overwrites another's.
pub(crate) static PRIVATE_DRIVE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) async fn shared_drive() -> &'static str {
    static SETUP: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();

    SETUP
        .get_or_init(|| async {
            let dir =
                std::env::temp_dir().join(format!("atomic-bridge-tests-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();

            open_db(dir.to_string_lossy().into_owned()).await.unwrap();
            setup("Test device".to_string())
                .await
                .unwrap()
                .drive_subject
        })
        .await
        .as_str()
}

/// Land a stroke in the store the way a peer's does: build the sender's view
/// of the doc, add their stroke, and hand the exported state to the same
/// `resolve_update` / `persist_update` pair the Iroh and WS receive sides use.
///
/// Crucially this never touches `CANVAS_CACHE`, so an already-cached editing
/// session stays stale afterwards — which is the condition under test.
async fn peer_stroke_arrives(subject: &str, color: u32) {
    let store = db().unwrap();

    let mut peer_side = store.get_resource(&subject.into()).await.unwrap();
    peer_side.ensure_materialized().unwrap();
    peer_side
        .push_list_item(
            CANVAS_STROKE_DATA,
            serde_json::json!({ "color": color, "path": [[9.0, 9.0]] }),
        )
        .unwrap();
    let update = peer_side.materialized_state().unwrap();

    let resolved = atomic_lib::sync::ws_apply::resolve_update(store.as_ref(), subject, &update)
        .await
        .expect("peer update should resolve");
    atomic_lib::sync::ws_apply::persist_update(store.as_ref(), subject, resolved)
        .await
        .unwrap();
}

/// Stroke colours as the *store* sees them.
async fn stored_colors(subject: &str) -> Vec<u64> {
    colors_of(&load_canvas_strokes(subject.to_string()).await.unwrap())
}

/// Stroke colours as a *cached editing session* sees them — the list the
/// Flutter UI draws, and the one `set_strokes` / `delete_stroke` index into.
fn colors_in_session(resource: &atomic_lib::Resource) -> Vec<u64> {
    match resource.get(CANVAS_STROKE_DATA) {
        Ok(atomic_lib::Value::Json(v)) => colors_of(&serde_json::to_string(v).unwrap()),
        _ => vec![],
    }
}

fn colors_of(json: &str) -> Vec<u64> {
    serde_json::from_str::<Vec<serde_json::Value>>(json)
        .unwrap()
        .iter()
        .map(|s| s["color"].as_u64().unwrap())
        .collect()
}

#[tokio::test]
async fn strokes_pushed_through_the_editing_session_all_persist() {
    let drive = shared_drive().await;
    assert!(!drive.is_empty());
    let canvas = create_canvas("Sequential".to_string()).await.unwrap();

    for color in 1..=3 {
        push_stroke(
            canvas.clone(),
            format!(r#"{{"color":{color},"path":[[0.0,0.0]]}}"#),
        )
        .await
        .unwrap();
    }

    assert_eq!(stored_colors(&canvas).await, vec![1, 2, 3]);
}

/// The mechanism behind "my strokes got reverted", tested directly.
///
/// A peer's stroke reaches the store while an editing session is held. That
/// session's copy of the drawing does not have it and nothing tells it so —
/// the cache-invalidation listener is async, and a fast next stroke beats it.
/// Holding the session across the peer's write reproduces exactly that window
/// with no timing dependence: the only thing that can put the peer's stroke
/// back into this session is `refresh_editing_session`.
///
/// Everything the user does next is computed from this list, so a session
/// left short a stroke is what a later erase or undo writes back.
#[tokio::test]
async fn refresh_catches_a_held_session_up_on_a_peer_stroke() {
    let _ = shared_drive().await;
    let store = db().unwrap();
    let canvas = create_canvas("Concurrent".to_string()).await.unwrap();

    push_stroke(canvas.clone(), r#"{"color":1,"path":[[0.0,0.0]]}"#.into())
        .await
        .unwrap();

    // Hold the session, then let a peer's stroke land behind its back. The
    // listener may drop the cache entry, but this resource is unaffected —
    // which is the production race, not an artificial one.
    let mut guard = get_canvas(&canvas).await.unwrap();
    peer_stroke_arrives(&canvas, 2).await;
    let resource = guard.as_mut().unwrap();

    assert_eq!(stored_colors(&canvas).await, vec![1, 2]);
    assert_eq!(
        colors_in_session(resource),
        vec![1],
        "the held session must genuinely be stale, or this proves nothing"
    );

    refresh_editing_session(resource, store.as_ref(), &canvas);

    assert_eq!(
        colors_in_session(resource),
        vec![1, 2],
        "catching up must bring the peer's stroke into the editing session"
    );
}

/// The outcome the user cares about: drawing after a peer's stroke arrives
/// keeps all three strokes. Broader than the test above — either the
/// synchronous catch-up or the async cache listener can deliver it.
#[tokio::test]
async fn a_peer_stroke_survives_a_following_local_stroke() {
    let _ = shared_drive().await;
    let canvas = create_canvas("Following".to_string()).await.unwrap();

    push_stroke(canvas.clone(), r#"{"color":1,"path":[[0.0,0.0]]}"#.into())
        .await
        .unwrap();

    peer_stroke_arrives(&canvas, 2).await;

    push_stroke(canvas.clone(), r#"{"color":3,"path":[[0.0,0.0]]}"#.into())
        .await
        .unwrap();

    assert_eq!(stored_colors(&canvas).await, vec![1, 2, 3]);
}

/// A whole-list rewrite (erase, undo) is computed from the session's list, so
/// it is only safe if that list already includes the peer's stroke. This is
/// the path that turns a stale read into real content loss: every individual
/// Loro op merges fine, but rewriting the list from stale content deletes the
/// peer's stroke on purpose.
#[tokio::test]
async fn a_whole_list_rewrite_after_a_peer_stroke_keeps_the_peer_stroke() {
    let _ = shared_drive().await;
    let canvas = create_canvas("Rewrite".to_string()).await.unwrap();

    push_stroke(canvas.clone(), r#"{"color":1,"path":[[0.0,0.0]]}"#.into())
        .await
        .unwrap();
    push_stroke(canvas.clone(), r#"{"color":2,"path":[[0.0,0.0]]}"#.into())
        .await
        .unwrap();

    peer_stroke_arrives(&canvas, 3).await;

    // What an erase does: take the list the UI is showing, drop one stroke,
    // write the rest back. Read through the session, exactly like the app.
    let remaining: Vec<serde_json::Value> = {
        let json = load_canvas_strokes(canvas.clone()).await.unwrap();
        serde_json::from_str::<Vec<serde_json::Value>>(&json)
            .unwrap()
            .into_iter()
            .filter(|s| s["color"].as_u64() != Some(1))
            .collect()
    };
    set_strokes(canvas.clone(), serde_json::to_string(&remaining).unwrap())
        .await
        .unwrap();

    assert_eq!(
        stored_colors(&canvas).await,
        vec![2, 3],
        "erasing stroke 1 must not also erase the peer's stroke 3"
    );
}

/// Catching up must be idempotent. `refresh_editing_session` runs before every
/// single stroke, so if importing an already-known snapshot re-applied its
/// operations, strokes would duplicate on every push rather than merge.
#[tokio::test]
async fn refreshing_an_already_current_session_changes_nothing() {
    let _ = shared_drive().await;
    let canvas = create_canvas("Idempotent".to_string()).await.unwrap();

    push_stroke(canvas.clone(), r#"{"color":1,"path":[[0.0,0.0]]}"#.into())
        .await
        .unwrap();

    let store = db().unwrap();
    let mut guard = get_canvas(&canvas).await.unwrap();
    let resource = guard.as_mut().unwrap();
    for _ in 0..3 {
        refresh_editing_session(resource, store.as_ref(), &canvas);
    }
    drop(guard);

    assert_eq!(stored_colors(&canvas).await, vec![1]);
}

/// Two canvases must not share an editing session — the cache is keyed by
/// subject, and a collision would cross-contaminate drawings.
#[tokio::test]
async fn editing_sessions_are_isolated_per_canvas() {
    let _ = shared_drive().await;
    let first = create_canvas("First".to_string()).await.unwrap();
    let second = create_canvas("Second".to_string()).await.unwrap();

    push_stroke(first.clone(), r#"{"color":10,"path":[[0.0,0.0]]}"#.into())
        .await
        .unwrap();
    push_stroke(second.clone(), r#"{"color":20,"path":[[0.0,0.0]]}"#.into())
        .await
        .unwrap();

    assert_eq!(stored_colors(&first).await, vec![10]);
    assert_eq!(stored_colors(&second).await, vec![20]);
}
