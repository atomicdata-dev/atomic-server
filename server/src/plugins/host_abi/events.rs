//! `atomic:host/events`: the pull stream.
//!
//! In this slice the stream is an in-memory queue per installation
//! ([`HostAbiRegistry::push_event`]). A restart forgets it, and nothing feeds
//! it from the trigger edges yet. The interface is the final one: a cursor
//! that only moves forward and an `ack` that moves the checkpoint.

use super::{
    bindings::atomic::host::events::{self, Event},
    code, error,
    run::AbiState,
    HostError,
};

/// Most events one `next` returns.
const MAX_EVENTS: u32 = 100;

fn parse_cursor(cursor: &str) -> Result<u64, HostError> {
    cursor.parse().map_err(|_| {
        error(
            code::INVALID_ARGUMENT,
            "the cursor is not one this host gave",
        )
    })
}

impl events::Host for AbiState {
    async fn next(&mut self, cursor: Option<String>, max: u32) -> Result<Vec<Event>, HostError> {
        let after = cursor.as_deref().map(parse_cursor).transpose()?;
        let app = &self.host;
        Ok(self.host.registry.next_events(
            &app.drive,
            &app.installation,
            after,
            max.clamp(1, MAX_EVENTS) as usize,
        ))
    }

    async fn ack(&mut self, cursor: String) -> Result<(), HostError> {
        let up_to = parse_cursor(&cursor)?;
        let app = &self.host;
        self.host
            .registry
            .ack_events(&app.drive, &app.installation, up_to);
        Ok(())
    }
}
