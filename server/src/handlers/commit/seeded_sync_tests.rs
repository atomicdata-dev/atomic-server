//! Reproducible fault schedules at the shared sync-engine boundary.
//! Two real redb replicas; a field ownership ledger is independent of Loro's
//! merge algorithm. Network scheduling is simulated, not an OS crash test.
use atomic_lib::{
    agents::ForAgent,
    db::trees::Tree,
    errors::AtomicResult,
    sync::{engine, protocol},
    urls, Db, Storelike, Value,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone)]
struct Packet {
    target: usize,
    bytes: Vec<u8>,
}

#[derive(serde::Serialize)]
struct Expected {
    subject: String,
    name: String,
    description: String,
    deleted: bool,
}

struct Random(u64);
impl Random {
    fn pick(&mut self, length: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % length as u64) as usize
    }
}

fn require(condition: bool, message: impl Into<String>) -> AtomicResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}

async fn snapshot(db: &Db, drive: &str, subject: &str, target: usize) -> AtomicResult<Packet> {
    let key = atomic_lib::Subject::from_raw(subject, None).pure_id();
    let bytes = db
        .kv
        .get(Tree::LoroSnapshots, key.as_bytes())?
        .ok_or("missing local snapshot")?;
    Ok(Packet {
        target,
        bytes: protocol::encode_sync_push(drive, &[(subject, &bytes)], true),
    })
}

async fn deliver(db: &Db, agent: &ForAgent, packet: &Packet) -> Vec<Vec<u8>> {
    engine::handle_frame_full(&packet.bytes, db, &mut agent.clone())
        .await
        .frames
}

async fn campaign(seed: u64, dir: &std::path::Path, trace: &mut Vec<String>) -> AtomicResult<()> {
    let mut random = Random(seed);
    let paths = [dir.join("a"), dir.join("b")];
    let mut replicas = vec![super::open(&paths[0]).await, super::open(&paths[1]).await];
    let (owner, drive) = replicas[0].setup("Seeded sync").await?;
    replicas[1]
        .load_agent_from_secret(&owner.build_secret()?)
        .await?;
    let agent = ForAgent::from(owner.clone());
    let bootstrap = snapshot(&replicas[0], &drive, &drive, 1).await?;
    require(
        deliver(&replicas[1], &agent, &bootstrap)
            .await
            .contains(&protocol::encode_sync_ok(&drive)),
        "bootstrap rejected",
    )?;
    let mut model = Vec::new();
    let mut packets: Vec<Packet> = Vec::new();
    let mut destroys = Vec::new();

    // Every shuffled block contains every operation kind, rather than hoping a
    // short random sample happens to exercise deletion, restart and disk error.
    for block in 0..8 {
        let mut kinds: Vec<usize> = (0..9).collect();
        for i in (1..kinds.len()).rev() {
            let j = random.pick(i + 1);
            kinds.swap(i, j);
        }
        // Create a new resource on both replicas before this block's edits.
        let name = format!("seed-{seed}-resource-{block}");
        let subject = replicas[0]
            .create_resource(
                "https://atomicdata.dev/classes/Folder",
                &drive,
                &name,
                Some(vec![(urls::DESCRIPTION, Value::String("initial".into()))]),
            )
            .await?;
        let initial = snapshot(&replicas[0], &drive, &subject, 1).await?;
        require(
            deliver(&replicas[1], &agent, &initial)
                .await
                .contains(&protocol::encode_sync_ok(&drive)),
            "creation rejected",
        )?;
        model.push(Expected {
            subject,
            name,
            description: "initial".into(),
            deleted: false,
        });
        trace.push(format!(
            "block {block}: create resource {}",
            model.len() - 1
        ));
        for kind in kinds {
            let active: Vec<usize> = model
                .iter()
                .enumerate()
                .filter_map(|(i, item)| (!item.deleted).then_some(i))
                .collect();
            let index = active[random.pick(active.len())];
            let random_side = random.pick(2);
            let side = match kind {
                0 | 1 => kind,
                7 => 0,
                _ => random_side,
            };
            trace.push(format!(
                "block {block}: kind={kind} side={side} resource={index} queue={}",
                packets.len()
            ));
            match kind {
                0 | 1 => {
                    // A exclusively edits name, B exclusively edits description.
                    // Thus expected values do not depend on a CRDT tie-breaker.
                    let side = kind;
                    let value = format!("seed-{seed}-block-{block}-field-{kind}");
                    let prop = if side == 0 {
                        urls::NAME
                    } else {
                        urls::DESCRIPTION
                    };
                    let mut resource = replicas[side]
                        .get_resource(&model[index].subject.as_str().into())
                        .await?;
                    resource.set_unsafe(prop.into(), Value::String(value.clone()))?;
                    resource.save_locally(&replicas[side]).await?;
                    if side == 0 {
                        model[index].name = value;
                    } else {
                        model[index].description = value;
                    }
                    packets.push(
                        snapshot(&replicas[side], &drive, &model[index].subject, 1 - side).await?,
                    );
                }
                2 => {
                    // Deliver a randomly delayed update.
                    if !packets.is_empty() {
                        let packet = packets.remove(random.pick(packets.len()));
                        require(
                            deliver(&replicas[packet.target], &agent, &packet)
                                .await
                                .contains(&protocol::encode_sync_ok(&drive)),
                            "delivery rejected",
                        )?;
                    }
                }
                3 => {
                    // Duplicate delivery: version history must not grow.
                    let packet =
                        snapshot(&replicas[side], &drive, &model[index].subject, 1 - side).await?;
                    let db = &replicas[packet.target];
                    deliver(db, &agent, &packet).await;
                    let before = snapshot(db, &drive, &model[index].subject, side).await?;
                    deliver(db, &agent, &packet).await;
                    let after = snapshot(db, &drive, &model[index].subject, side).await?;
                    let version = |packet: Packet| {
                        let entry = protocol::decode_sync_push(&packet.bytes[1..]).unwrap();
                        atomic_lib::loro::AtomicLoroDoc::vv_map_from_snapshot(
                            &entry.entries[0].loro_bytes,
                        )
                        .unwrap()
                    };
                    require(
                        version(before) == version(after),
                        "duplicate grew CRDT history",
                    )?;
                }
                4 => {
                    // Disconnect loses an in-flight packet; reconcile repairs it.
                    if !packets.is_empty() {
                        packets.remove(random.pick(packets.len()));
                    }
                }
                5 => {
                    // Reload persisted local state, not a graceful-crash claim.
                    replicas[side].flush()?;
                    // Drop every database handle before reopening the file.
                    let old = replicas.remove(side);
                    drop(old);
                    replicas.insert(side, super::open(&paths[side]).await);
                    // Credentials are restored separately from resource storage.
                    replicas[side].set_default_agent(owner.clone());
                }
                6 => {
                    // The write lands in memory, but its durability barrier fails.
                    let packet =
                        snapshot(&replicas[side], &drive, &model[index].subject, 1 - side).await?;
                    let target = packet.target;
                    let original = replicas[target].kv.clone();
                    let fail = Arc::new(AtomicBool::new(true));
                    replicas[target].kv = Arc::new(super::FlushGate {
                        inner: original.clone(),
                        fail: fail.clone(),
                    });
                    let replies = deliver(&replicas[target], &agent, &packet).await;
                    fail.store(false, Ordering::SeqCst);
                    replicas[target].kv = original;
                    require(
                        !replies.contains(&protocol::encode_sync_ok(&drive)),
                        "failed disk flush was acknowledged",
                    )?;
                    packets.push(packet);
                }
                7 => {
                    // Capture stale state, then delete. Replaying it must not resurrect.
                    if active.len() > 1 {
                        packets
                            .push(snapshot(&replicas[0], &drive, &model[index].subject, 1).await?);
                        let mut resource = replicas[0]
                            .get_resource(&model[index].subject.as_str().into())
                            .await?;
                        let response = resource.destroy(&replicas[0]).await?;
                        let json =
                            atomic_lib::client::commit_to_wire_json(&response.commit, &replicas[0])
                                .await?;
                        destroys.push(protocol::encode_commit(7, &json));
                        model[index].deleted = true;
                    }
                }
                8 => {
                    // Partition: accumulate fresh snapshots without delivering them.
                    packets.push(
                        snapshot(&replicas[side], &drive, &model[index].subject, 1 - side).await?,
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    trace.push(format!(
        "expected ledger: {}",
        serde_json::to_string(&model)?
    ));
    // Restore connectivity. Apply signed deletions first, then deliberately
    // replay all stale packets. The deletion policy must dominate these updates.
    for bytes in destroys {
        let replies = engine::handle_frame_full(&bytes, &replicas[1], &mut agent.clone())
            .await
            .frames;
        require(
            replies
                .iter()
                .any(|frame| frame[0] == protocol::tag::COMMIT_OK),
            "delete rejected",
        )?;
    }
    while !packets.is_empty() {
        let packet = packets.remove(random.pick(packets.len()));
        require(
            deliver(&replicas[packet.target], &agent, &packet)
                .await
                .contains(&protocol::encode_sync_ok(&drive)),
            "replay rejected",
        )?;
    }
    // Two fixed exchanges suffice for disjoint edits; no polling until the test
    // happens to pass. Always build snapshots on the current persisted history.
    for side in [0, 1] {
        for item in model.iter().filter(|item| !item.deleted) {
            let packet = snapshot(&replicas[side], &drive, &item.subject, 1 - side).await?;
            require(
                deliver(&replicas[1 - side], &agent, &packet)
                    .await
                    .contains(&protocol::encode_sync_ok(&drive)),
                "final reconcile rejected",
            )?;
        }
    }
    for (side, db) in replicas.iter().enumerate() {
        let members = db
            .query(&atomic_lib::storelike::Query::new_prop_val(
                urls::PARENT,
                &drive,
            ))
            .await?;
        for item in &model {
            let member = members
                .resources
                .iter()
                .any(|resource| resource.get_subject().as_str() == item.subject);
            let resource = db.get_resource(&item.subject.as_str().into()).await;
            if item.deleted {
                require(
                    resource.is_err() && !member,
                    format!("replica {side}: deleted resource resurrected"),
                )?;
            } else {
                let resource = resource?;
                require(member, format!("replica {side}: missing query member"))?;
                require(
                    resource.get(urls::NAME)?.to_string() == item.name,
                    format!("replica {side}: name lost"),
                )?;
                require(
                    resource.get(urls::DESCRIPTION)?.to_string() == item.description,
                    format!("replica {side}: description lost"),
                )?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn seeded_sync_failure_schedules() {
    let seeds = std::env::var("ATOMIC_SYNC_SEED")
        .map(|seed| vec![seed.parse::<u64>().expect("decimal ATOMIC_SYNC_SEED")])
        .unwrap_or_else(|_| vec![1, 42, 24301, 3735928559]);
    for seed in seeds {
        assert_ne!(seed, 0, "xorshift seed must be nonzero");
        let dir = tempfile::tempdir().unwrap();
        let mut trace = vec![format!("seed={seed}; 8 blocks; 9 operations per block")];
        if let Err(error) = campaign(seed, dir.path(), &mut trace).await {
            let evidence = dir.keep();
            std::fs::write(evidence.join("schedule.log"), trace.join("\n")).unwrap();
            panic!(
                "seed={seed}: {error}; evidence={}; replay with ATOMIC_SYNC_SEED={seed}",
                evidence.display()
            );
        }
    }
}
