use crate::{appstate::AppState, errors::AtomicServerResult};
use actix_web::{web, HttpResponse};
use atomic_lib::{
    sync::engine::{ingest_commit_json, CommitIngestOpts},
    Db,
};

#[cfg(test)]
mod benchmark;
#[cfg(test)]
mod durability_tests;

/// Send and process a Commit.
/// Currently only accepts JSON-AD
#[tracing::instrument(skip(appstate))]
pub async fn post_commit(
    appstate: web::Data<AppState>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
    body: String,
) -> AtomicServerResult<HttpResponse> {
    if appstate.config.opts.slow_mode {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_number = rng.gen_range(100..1000);
        tokio::time::sleep(tokio::time::Duration::from_millis(random_number)).await;
    }
    let store = &appstate.store;
    // Spend the write budget of the identity the commit *proves*, not the
    // one it claims. The `signer` field is attacker-controlled until the
    // signature over the body checks out, and keying the limiter on the
    // claimed signer let anyone who knew a victim's public DID drain the
    // victim's budget with forged commits and lock them out of writing. A
    // body that proves no signer (junk, no signature, a signature that does
    // not verify) spends the peer address's anonymous budget instead, like
    // every other unsigned write. That budget is charged after the check
    // rather than gating it: behind a reverse proxy every client shares one
    // peer address, and refusing to even look at signed commits once that
    // shared budget is spent would turn the same flood into an outage for
    // everyone.
    let for_agent = match atomic_lib::sync::engine::verify_commit_signer(store, &body).await {
        Ok(signer) => atomic_lib::agents::ForAgent::AgentSubject(signer),
        Err(refused) => {
            crate::helpers::enforce_write_rate_limit(
                &appstate,
                &req,
                &atomic_lib::agents::ForAgent::Public,
            )?;
            return Err(refused.into());
        }
    };
    crate::helpers::enforce_write_rate_limit(&appstate, &req, &for_agent)?;
    let message = apply_commit_json(store, &context.origin, &body, None).await?;

    Ok(HttpResponse::Ok()
        .content_type("application/ad+json")
        .body(message))
}

/// Apply a signed JSON-AD commit sent by a client. Delegates to the sync
/// engine's [`ingest_commit_json`] with hub policy: subject-ownership and
/// Loro-causality are enforced, the WS commit monitor's `source_id` is
/// threaded through for echo suppression, and live-peer fanout is left
/// unsuppressed (that suppression is per-`source_id`, handled by the commit
/// monitor).
pub async fn apply_commit_json(
    store: &Db,
    origin: &str,
    body: &str,
    source_id: Option<String>,
) -> AtomicServerResult<String> {
    let message = ingest_commit_json(
        store,
        body,
        &CommitIngestOpts::hub(source_id, Some(origin.to_string())),
    )
    .await?;

    // HTTP success and WS COMMIT_OK let callers discard their pending edit.
    // redb applies with Durability::None; waiting for the periodic flush would
    // leave acknowledged writes vulnerable to a crash before the next tick.
    // Keep blocking disk I/O off the async worker, and propagate failures so
    // neither transport can report success without a durable commit point.
    let durable_store = store.clone();
    tokio::task::spawn_blocking(move || durable_store.flush())
        .await
        .map_err(|e| format!("Commit durability task failed: {e}"))??;

    crate::metrics::commit_applied();

    Ok(message)
}
