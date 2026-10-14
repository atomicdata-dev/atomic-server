//! The accept side of the Iroh transport (`handle_stream`) and the sync
//! engine's `SYNC_PUSH` answer, exercised the way a hostile or merely
//! confused peer would hit them: frames before AUTH, AUTH for one drive
//! followed by a handshake for another, and a push from an agent with
//! no write right. Each refusal must be *visible* — an `ERROR` frame with
//! a registered code — never a silent drop or a `SYNC_OK` for nothing.
use super::initiator_trust_tests::private_drive_with_child;
use super::*;
use crate::sync::protocol::{self, error_code, tag};
use crate::Db;

/// `(request_id, code, message)` of an ERROR frame, or `None` for any
/// other frame.
fn parse_error(frame: &[u8]) -> Option<(u16, u16, String)> {
    if frame.first() != Some(&tag::ERROR) || frame.len() < 5 {
        return None;
    }
    let request_id = u16::from_be_bytes([frame[1], frame[2]]);
    let code = u16::from_be_bytes([frame[3], frame[4]]);
    let message = String::from_utf8_lossy(&frame[5..]).into_owned();
    Some((request_id, code, message))
}

/// A SYNC_PUSH frame carrying the owner's current snapshot of `child`,
/// as a peer that replays it would send it.
async fn push_frame_for(
    db: &Db,
    owner: &crate::agents::Agent,
    drive: &str,
    child: &str,
) -> Vec<u8> {
    let snapshots = crate::sync::engine::collect_readable_snapshots(
        db,
        &ForAgent::AgentSubject(owner.subject.clone()),
        &[child.to_string()],
        None,
    )
    .await;
    assert_eq!(snapshots.len(), 1, "owner can read its own child");
    let entries: Vec<(&str, &[u8])> = snapshots
        .iter()
        .map(|(s, b)| (s.as_str(), b.as_slice()))
        .collect();
    protocol::encode_sync_push(drive, &entries, true)
}

#[tokio::test]
async fn import_sync_push_refuses_agent_without_write_right() {
    let db = Db::init_temp("gate_import_stranger").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (drive, child) = private_drive_with_child(&db, &alice).await;
    let mallory = crate::agents::Agent::new(Some("Mallory")).unwrap();

    let frame = push_frame_for(&db, &alice, &drive, &child).await;
    let push = protocol::decode_sync_push(&frame[1..]).unwrap();

    for (who, agent) in [
        ("Public", ForAgent::Public),
        (
            "a stranger",
            ForAgent::AgentSubject(mallory.subject.clone()),
        ),
    ] {
        let rejected = crate::sync::engine::import_sync_push(&push, &db, &agent, false)
            .await
            .expect_err(&format!(
                "{who} must not be able to push into a private drive"
            ));
        assert_eq!(rejected.drive, drive);
        assert!(
            rejected.reason.contains("no write right"),
            "reason names the cause: {}",
            rejected.reason
        );
    }

    // The owner's push is admitted — the refusal is about rights, not a
    // blanket one.
    crate::sync::engine::import_sync_push(
        &push,
        &db,
        &ForAgent::AgentSubject(alice.subject.clone()),
        false,
    )
    .await
    .expect("the owner may push into its own drive");
}

/// The wire-level consequence: a refused push is answered with ERROR
/// `SYNC_REJECTED`, and there is no `SYNC_OK` anywhere in the response.
/// Before this, the engine answered `SYNC_OK` for a push it had dropped,
/// so the sender believed its data had landed.
#[tokio::test]
async fn rejected_sync_push_is_answered_with_error_not_sync_ok() {
    let db = Db::init_temp("gate_push_error_frame").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (drive, child) = private_drive_with_child(&db, &alice).await;
    let mallory = crate::agents::Agent::new(Some("Mallory")).unwrap();

    let frame = push_frame_for(&db, &alice, &drive, &child).await;
    let mut as_mallory = ForAgent::AgentSubject(mallory.subject.clone());
    let responses = crate::sync::engine::handle_frame(&frame, &db, &mut as_mallory).await;

    assert!(
        !responses.iter().any(|f| f.first() == Some(&tag::SYNC_OK)),
        "a rejected push must never be acknowledged with SYNC_OK"
    );
    let (request_id, code, message) = responses
        .iter()
        .find_map(|f| parse_error(f))
        .expect("a rejected push is answered with an ERROR frame");
    assert_eq!(
        request_id, 0,
        "connection-level error, not tied to a request"
    );
    assert_eq!(code, error_code::SYNC_REJECTED);
    assert!(
        message.contains(&drive),
        "the message names the drive so the sender can act on it: {message}"
    );

    // And the owner's push still gets its SYNC_OK.
    let mut as_alice = ForAgent::AgentSubject(alice.subject.clone());
    let responses = crate::sync::engine::handle_frame(&frame, &db, &mut as_alice).await;
    assert!(
        responses.iter().any(|f| f.first() == Some(&tag::SYNC_OK)),
        "the owner's push is acknowledged"
    );
}

/// Dial a running accept side with a raw endpoint and return the stream.
async fn raw_stream(
    router: &Router,
    node_id: &NodeId,
) -> (
    iroh::Endpoint,
    iroh::endpoint::SendStream,
    iroh::endpoint::RecvStream,
) {
    let ep = iroh::Endpoint::builder().bind().await.unwrap();
    let addr = router.endpoint().node_addr().await.unwrap();
    ep.add_node_addr(addr).unwrap();
    let conn = ep.connect(*node_id, ATOMIC_ALPN).await.unwrap();
    let (send, recv) = conn.open_bi().await.unwrap();
    (ep, send, recv)
}

async fn write_frame(send: &mut iroh::endpoint::SendStream, frame: &[u8]) {
    send.write_all(&frame_with_len(frame)).await.unwrap();
}

/// The next frame from the accept side, or `None` once it closed the
/// stream. The unsolicited HELLO and the auth-back AUTH the accept side
/// sends after AUTH_OK are skipped; they are not what these tests are
/// about.
async fn read_frame(recv: &mut iroh::endpoint::RecvStream) -> Option<Vec<u8>> {
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), recv.read_u32())
            .await
            .expect("accept side answers within 10s")
            .ok()?;
        let mut buf = vec![0u8; n as usize];
        recv.read_exact(&mut buf).await.ok()?;
        // Not the answer being waited for: the accept side's handshake
        // chatter, the KEEPALIVE its live loop sends after
        // `KEEPALIVE_INTERVAL` of silence, and the live fan-out
        // (`UPDATE`, signed-destroy `COMMIT`) of writes made by the
        // *other* tests in this process, which reaches every stream in
        // the process-global peer registry. None of these tests waits
        // for a fan-out frame.
        if !matches!(
            buf.first(),
            Some(&tag::HELLO)
                | Some(&tag::AUTH)
                | Some(&tag::KEEPALIVE)
                | Some(&tag::UPDATE)
                | Some(&tag::COMMIT)
        ) {
            return Some(buf);
        }
    }
}

/// A handshake frame before AUTH — here a SYNC for a *public* drive,
/// which the old code would happily have served as `Public` — gets
/// `AUTH_REQUIRED` and a closed stream. Fail closed on identity.
#[tokio::test]
async fn iroh_sync_before_auth_is_refused_and_stream_closed() {
    let db = Db::init_temp("gate_iroh_preauth").await.unwrap();
    let (_alice, drive) = db.setup("Alice").await.unwrap();
    let (node_id, router) = start(db.clone()).await.unwrap();

    let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
    let sync = protocol::encode_sync(&drive, "", &[], &std::collections::HashMap::new());
    write_frame(&mut send, &sync).await;

    let reply = read_frame(&mut recv)
        .await
        .expect("an ERROR frame, not silence");
    let (_, code, message) = parse_error(&reply).expect("ERROR frame");
    assert_eq!(code, error_code::AUTH_REQUIRED, "{message}");
    assert!(
        read_frame(&mut recv).await.is_none(),
        "the accept side closes the stream after refusing"
    );
}

/// `AUTH.requestedSubject` is bound to the drive of the handshake that
/// follows: an AUTH signed for drive X does not open drive Y.
#[tokio::test]
async fn iroh_auth_for_one_drive_does_not_open_another() {
    let db = Db::init_temp("gate_iroh_binding").await.unwrap();
    let (alice, drive) = db.setup("Alice").await.unwrap();
    let (node_id, router) = start(db.clone()).await.unwrap();

    let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
    let auth = protocol::encode_auth(
        &alice,
        &auth_subject_for("did:key:z6MkSomeOtherDrive", &node_id.to_string()),
    )
    .unwrap();
    write_frame(&mut send, &auth).await;
    let reply = read_frame(&mut recv).await.expect("AUTH_OK");
    assert_eq!(reply.first(), Some(&tag::AUTH_OK), "AUTH itself is valid");

    let sync = protocol::encode_sync(&drive, "", &[], &std::collections::HashMap::new());
    write_frame(&mut send, &sync).await;
    let reply = read_frame(&mut recv)
        .await
        .expect("an ERROR frame, not a SYNC_DIFF");
    let (_, code, message) = parse_error(&reply).expect("ERROR frame");
    assert_eq!(code, error_code::AUTH_REQUIRED, "{message}");
    assert!(message.contains(&drive), "{message}");
    assert!(read_frame(&mut recv).await.is_none(), "stream closed");
}

/// The happy path through the same raw stream, so the two refusals
/// above are known to be about the gate and not about the fixture:
/// AUTH for the drive, then SYNC of it, yields a handshake answer.
#[tokio::test]
async fn iroh_auth_then_sync_for_same_drive_is_served() {
    let db = Db::init_temp("gate_iroh_happy").await.unwrap();
    let (alice, drive) = db.setup("Alice").await.unwrap();
    let (node_id, router) = start(db.clone()).await.unwrap();

    let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
    write_frame(
        &mut send,
        &protocol::encode_auth(&alice, &auth_subject_for(&drive, &node_id.to_string())).unwrap(),
    )
    .await;
    assert_eq!(
        read_frame(&mut recv).await.unwrap().first(),
        Some(&tag::AUTH_OK)
    );

    let sync = protocol::encode_sync(&drive, "", &[], &std::collections::HashMap::new());
    write_frame(&mut send, &sync).await;
    let reply = read_frame(&mut recv).await.expect("a handshake answer");
    assert!(
        matches!(
            reply.first(),
            Some(&tag::SYNC_DIFF) | Some(&tag::SYNC_PUSH) | Some(&tag::SYNC_OK)
        ),
        "expected a sync answer, got 0x{:02x}",
        reply[0]
    );
}

/// Complete the handshake on a raw stream as `owner` for `drive` and
/// drain the accept side's answer until it has transitioned to live mode
/// A proof that does not name this node is refused: signed for another
/// node it is a capture a middleman could replay; without any node id it
/// is a pre-binding dialer, honoured only from a peer we paired with.
#[tokio::test]
async fn iroh_auth_must_name_this_node() {
    let db = Db::init_temp("gate_iroh_node_binding").await.unwrap();
    let (alice, drive) = db.setup("Alice").await.unwrap();
    let (node_id, router) = start(db.clone()).await.unwrap();

    // Signed for some other node: a replayed capture.
    let other_node = "did:ad:node:".to_string() + &"ab".repeat(32);
    let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
    let auth = protocol::encode_auth(&alice, &auth_subject_for(&drive, &other_node)).unwrap();
    write_frame(&mut send, &auth).await;
    let reply = read_frame(&mut recv).await.expect("an ERROR frame");
    let (_, code, message) = parse_error(&reply).expect("ERROR frame");
    assert_eq!(code, error_code::AUTH_FAILED, "{message}");
    assert!(
        message.contains("CHALLENGE") || message.contains("nonce"),
        "{message}"
    );

    // No node id at all, from a peer this node never paired with.
    let (_ep2, mut send, mut recv) = raw_stream(&router, &node_id).await;
    write_frame(&mut send, &protocol::encode_auth(&alice, &drive).unwrap()).await;
    let reply = read_frame(&mut recv).await.expect("an ERROR frame");
    let (_, code, message) = parse_error(&reply).expect("ERROR frame");
    assert_eq!(code, error_code::AUTH_FAILED, "{message}");
    assert!(message.contains("must name this node"), "{message}");
}

/// (the client sent an empty version vector, so the server pushes
/// everything and expects nothing back).
async fn handshake_to_live(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    owner: &crate::agents::Agent,
    drive: &str,
    node_id: &str,
) {
    write_frame(
        send,
        &protocol::encode_auth(owner, &auth_subject_for(drive, node_id)).unwrap(),
    )
    .await;
    let reply = read_frame(recv).await.expect("AUTH_OK");
    assert_eq!(reply.first(), Some(&tag::AUTH_OK));
    assert!(
        protocol::decode_auth_ok(&reply[1..])
            .iter()
            .any(|c| c == "signed-destroy"),
        "AUTH_OK advertises this build's capabilities"
    );

    let sync = protocol::encode_sync(drive, "", &[], &std::collections::HashMap::new());
    write_frame(send, &sync).await;
    loop {
        let reply = read_frame(recv).await.expect("a handshake answer");
        match reply.first() {
            Some(&tag::SYNC_OK) => break,
            Some(&tag::SYNC_PUSH) => {
                let push = protocol::decode_sync_push(&reply[1..]).unwrap();
                if push.last {
                    break;
                }
            }
            Some(&tag::SYNC_DIFF) => continue,
            other => panic!("unexpected handshake frame {other:?}"),
        }
    }
    // Give the accept side a moment to register the live loop.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
}

/// A naked `DESTROY` frame carries no signature, so it authorises
/// nothing — not even from the drive's owner, on an authenticated live
/// link. The resource survives. (planning/serverless-p2p.md, principle 3.)
#[tokio::test]
async fn naked_destroy_on_the_live_link_is_ignored() {
    let db = Db::init_temp("gate_iroh_naked_destroy").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (drive, child) = private_drive_with_child(&db, &alice).await;
    let (node_id, router) = start(db.clone()).await.unwrap();

    let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
    handshake_to_live(&mut send, &mut recv, &alice, &drive, &node_id.to_string()).await;

    write_frame(&mut send, &protocol::encode_destroy(0, &child)).await;
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;

    let subject = crate::Subject::from_raw(&child, None);
    assert!(
        db.get_resource(&subject).await.is_ok(),
        "a naked DESTROY must never remove a resource"
    );
    assert!(
        !crate::sync::tombstones::is_tombstoned(&db, &child),
        "and must not leave a tombstone that would poison later imports"
    );
}

/// The same delete as a signed destroy `COMMIT` is applied: the live
/// loop routes it through the engine's COMMIT arm, which verifies the
/// signature and the signer's rights like any other write.
#[tokio::test]
async fn signed_destroy_commit_on_the_live_link_is_applied() {
    let db = Db::init_temp("gate_iroh_signed_destroy").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (drive, child) = private_drive_with_child(&db, &alice).await;
    let (node_id, router) = start(db.clone()).await.unwrap();

    let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
    handshake_to_live(&mut send, &mut recv, &alice, &drive, &node_id.to_string()).await;

    let subject = crate::Subject::from_raw(&child, None);
    let resource = db.get_resource(&subject).await.unwrap();
    // A bare destroy: no property edits ride along, so the only thing
    // the receiver validates is the signature and the signer's rights.
    let mut builder = crate::commit::CommitBuilder::new(subject.clone());
    builder.destroy(true);
    let commit = builder.sign(&alice, &db, &resource).await.unwrap();
    // The same serialisation the live push loop forwards.
    let commit_json = commit
        .into_resource(&db)
        .await
        .unwrap()
        .to_json_ad(None)
        .unwrap();
    write_frame(&mut send, &protocol::encode_commit(0, &commit_json)).await;

    // The engine answers the COMMIT: COMMIT_OK, or an ERROR that says
    // why it was refused (which is the useful failure message here).
    let reply = read_frame(&mut recv)
        .await
        .expect("an answer to the COMMIT");
    if let Some((_, code, message)) = parse_error(&reply) {
        panic!("signed destroy commit refused (code {code}): {message}");
    }
    assert_eq!(reply.first(), Some(&tag::COMMIT_OK), "expected COMMIT_OK");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while db.get_resource(&subject).await.is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "COMMIT_OK was answered but the resource is still there after 5s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// A destroy commit signed by an agent without write rights is refused by
/// the same COMMIT arm — the connection's identity does not matter, the
/// signature does.
#[tokio::test]
async fn signed_destroy_from_stranger_on_the_live_link_is_refused() {
    let db = Db::init_temp("gate_iroh_stranger_destroy").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (drive, child) = private_drive_with_child(&db, &alice).await;
    let mallory = db.create_agent(Some("Mallory")).await.unwrap();
    let (node_id, router) = start(db.clone()).await.unwrap();

    let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
    handshake_to_live(&mut send, &mut recv, &alice, &drive, &node_id.to_string()).await;

    let subject = crate::Subject::from_raw(&child, None);
    let resource = db.get_resource(&subject).await.unwrap();
    let mut builder = crate::commit::CommitBuilder::new(subject.clone());
    builder.destroy(true);
    let commit = builder.sign(&mallory, &db, &resource).await.unwrap();
    let commit_json = commit
        .into_resource(&db)
        .await
        .unwrap()
        .to_json_ad(None)
        .unwrap();
    write_frame(&mut send, &protocol::encode_commit(0, &commit_json)).await;

    let reply = read_frame(&mut recv).await.expect("an ERROR frame");
    let (_, code, message) = parse_error(&reply).expect("ERROR frame");
    assert_eq!(code, error_code::UNAUTHORIZED_WRITE, "{message}");
    assert!(
        db.get_resource(&subject).await.is_ok(),
        "Mallory's destroy must not be applied"
    );
}
