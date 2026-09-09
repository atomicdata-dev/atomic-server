//! Read-only peer inspection before the user chooses to fetch a workspace.
use super::{peer, protocol};
use crate::{errors::AtomicResult, Db, Storelike};
use iroh::Endpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspacePeer {
    pub node_id: String,
    pub name: Option<String>,
}

/// Authenticate and request just the workspace resource to check read access.
/// Discard its snapshot: no import, SYNC, subscription or remembered pairing.
pub async fn inspect_workspace(
    endpoint: &Endpoint,
    node_id: &str,
    drive: &str,
    store: &Db,
) -> AtomicResult<WorkspacePeer> {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let remote: iroh::NodeId = node_id.parse::<iroh::NodeId>().map_err(|e| e.to_string())?;
        let conn = endpoint
            .connect(remote, peer::ATOMIC_ALPN)
            .await
            .map_err(|e| e.to_string())?;
        let result = async {
            let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
            let auth = protocol::encode_auth(
                &store.get_default_agent()?,
                &peer::auth_subject_for(drive, &remote.to_string()),
            )?;
            send.write_u32(auth.len() as u32)
                .await
                .map_err(|e| e.to_string())?;
            send.write_all(&auth).await.map_err(|e| e.to_string())?;
            let mut authenticated = false;
            let mut name = None;
            loop {
                let len = recv.read_u32().await? as usize;
                if len == 0 || len > protocol::IROH_PREAUTH_FRAME_MAX_BYTES {
                    return Err("Invalid discovery response size".into());
                }
                let mut frame = vec![0; len];
                recv.read_exact(&mut frame)
                    .await
                    .map_err(|e| e.to_string())?;
                match frame[0] {
                    protocol::tag::ERROR => {
                        let error =
                            protocol::decode_error(&frame[1..]).ok_or("Invalid discovery error")?;
                        return Err(error.message.into());
                    }
                    protocol::tag::AUTH_OK if !authenticated => {
                        authenticated = true;
                        let get = protocol::encode_get(1, drive);
                        send.write_u32(get.len() as u32)
                            .await
                            .map_err(|e| e.to_string())?;
                        send.write_all(&get).await.map_err(|e| e.to_string())?;
                    }
                    protocol::tag::HELLO if authenticated => {
                        name = protocol::decode_hello(&frame[1..]);
                    }
                    protocol::tag::UPDATE if authenticated => {
                        let update = protocol::decode_update(&frame[1..])
                            .ok_or("Invalid workspace response")?;
                        if update.request_id != 1
                            || update.subject != drive
                            || update.loro_bytes.is_empty()
                        {
                            return Err("Unexpected workspace response".into());
                        }
                        return Ok(WorkspacePeer {
                            node_id: node_id.to_string(),
                            name,
                        });
                    }
                    protocol::tag::AUTH if authenticated => {} // No data is served back.
                    _ => return Err("Unexpected discovery frame".into()),
                }
            }
        }
        .await;
        conn.close(0u32.into(), b"workspace inspection complete");
        result
    })
    .await
    .map_err(|_| "Workspace discovery timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inspection_checks_access_without_importing_or_pairing() {
        let source = Db::init_temp("inspect_source").await.unwrap();
        let (alice, drive) = source.setup("Alice").await.unwrap();
        let (node_id, router) = peer::start(source.clone()).await.unwrap();
        let client = Db::init_temp("inspect_client").await.unwrap();
        client.set_default_agent(alice.clone());
        let endpoint = Endpoint::builder().bind().await.unwrap();
        endpoint
            .add_node_addr(router.endpoint().node_addr().await.unwrap())
            .unwrap();
        let found = inspect_workspace(&endpoint, &node_id.to_string(), &drive, &client)
            .await
            .unwrap();
        assert_eq!(found.node_id, node_id.to_string());
        assert!(found.name.is_some());
        assert!(
            peer::get_known_peers(&client).is_empty(),
            "inspection must not pair"
        );
        assert!(
            client
                .get_resource(&crate::Subject::from_raw(&drive, None))
                .await
                .is_err(),
            "inspection must not import the drive"
        );
        let stranger = crate::agents::Agent::new(Some("Stranger")).unwrap();
        client.set_default_agent(stranger);
        assert!(
            inspect_workspace(&endpoint, &node_id.to_string(), &drive, &client)
                .await
                .is_err()
        );
        client.set_default_agent(alice);
        let imported = peer::sync_drive_with_peer_using(
            &endpoint,
            &node_id.to_string(),
            &drive,
            &client,
            true,
        )
        .await
        .unwrap();
        assert!(imported > 0, "explicit fetch imports data");
        assert!(client
            .get_resource(&crate::Subject::from_raw(&drive, None))
            .await
            .is_ok());
        endpoint.close().await;
        router.shutdown().await.unwrap();
    }
}
