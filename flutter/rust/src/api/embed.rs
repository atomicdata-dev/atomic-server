//! The embedded renderer's channel into the store.

/// One call from the page: `method` and its arguments (a JSON array), answered
/// as JSON. The page's `NativeClientDb` is the other end
/// (`browser/lib/src/client-db.native.ts`).
pub async fn embed_call(method: String, args_json: String) -> Result<String, String> {
    crate::embed::call(&method, &args_json).await
}
