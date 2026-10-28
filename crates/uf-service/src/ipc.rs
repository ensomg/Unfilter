//! The pipe server loop: accepts tray/UI clients on the ADR-005 named pipe,
//! drives the [`Orchestrator`] with their requests, and pushes status events
//! back to every connected client.
//!
//! The request→response mapping is a pure [`Dispatcher`] method, unit-tested
//! without any pipe. [`serve`] is the Windows glue around it: one listener
//! thread accepting clients, one reader thread per client, and a shared set of
//! per-client writers so an event raised by one client (or the background
//! monitor) reaches all of them. Each client's writes are serialised by a
//! per-client lock so response and event bytes never interleave.

use std::sync::{Arc, Mutex};

use uf_ipc::{Event, Request, ServerMessage};

use crate::orchestrator::Orchestrator;

/// Maps client requests onto the shared orchestrator. Pure: no I/O, so the
/// full request→response/event behaviour is testable without a pipe.
pub struct Dispatcher {
    orch: Arc<Mutex<Orchestrator>>,
}

impl Dispatcher {
    /// Wrap a shared orchestrator.
    pub fn new(orch: Arc<Mutex<Orchestrator>>) -> Self {
        Dispatcher { orch }
    }

    /// Handle one correlated request, returning the response to send back to the
    /// originating client and any events to broadcast to all clients.
    pub fn on_request(&self, id: u64, request: Request) -> (ServerMessage, Vec<ServerMessage>) {
        let (payload, events) = self
            .orch
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .handle(request);
        let response = ServerMessage::Response { id, payload };
        let events = events.into_iter().map(wrap_event).collect();
        (response, events)
    }
}

fn wrap_event(event: Event) -> ServerMessage {
    ServerMessage::Event { event }
}

#[cfg(windows)]
pub use win::serve;

#[cfg(windows)]
mod win {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use uf_ipc::PROTOCOL_VERSION;
    use uf_ipc::pipe::{FrameReader, PipeServer, PipeStream, server_handshake, write_frame};
    use uf_ipc::{ClientMessage, ServerMessage};

    use super::Dispatcher;
    use crate::orchestrator::Orchestrator;

    /// A connected client's write end, lock-guarded so responses and broadcast
    /// events never interleave on the wire.
    type Writer = Arc<Mutex<PipeStream>>;

    /// The set of connected clients' writers, for broadcasting events.
    #[derive(Clone, Default)]
    struct Clients(Arc<Mutex<Vec<Writer>>>);

    impl Clients {
        fn add(&self, w: Writer) {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).push(w);
        }

        /// Write a frame to every client, dropping any that error.
        fn broadcast(&self, msg: &ServerMessage) {
            let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
            guard.retain(|w| {
                let mut s = w.lock().unwrap_or_else(|e| e.into_inner());
                write_frame(&mut *s, msg).is_ok()
            });
        }

        /// Forget writers whose `Arc` only we still hold (clients that ended).
        fn prune(&self) {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|w| Arc::strong_count(w) > 1);
        }
    }

    /// Run the pipe server until the returned-from shutdown handle fires. Blocks
    /// the calling thread. `orch` is shared with any background worker.
    pub fn serve(name: &str, orch: Arc<Mutex<Orchestrator>>) -> std::io::Result<()> {
        let mut server = PipeServer::bind(name)?;
        let clients = Clients::default();
        loop {
            match server.accept()? {
                Some(stream) => {
                    let dispatcher = Dispatcher::new(Arc::clone(&orch));
                    let client_set = clients.clone();
                    // A failed clone just drops this client (fail-safe).
                    if let Ok(write_end) = stream.try_clone() {
                        thread::spawn(move || {
                            handle_client(stream, write_end, dispatcher, client_set);
                        });
                    }
                    clients.prune();
                }
                None => return Ok(()), // shutdown requested
            }
        }
    }

    fn handle_client(
        read_end: PipeStream,
        write_end: PipeStream,
        dispatcher: Dispatcher,
        clients: Clients,
    ) {
        let writer: Writer = Arc::new(Mutex::new(write_end));
        let mut reader = FrameReader::new(read_end);

        // Handshake: one message in, Hello out (version-checked by the helper).
        {
            let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
            if server_handshake(&mut reader, &mut *w).is_err() {
                return; // bad version / not Hello: helper already replied, close.
            }
        }
        clients.add(Arc::clone(&writer));

        loop {
            match reader.read_message::<ClientMessage>() {
                Ok(Some(ClientMessage::Request { id, request })) => {
                    let (response, events) = dispatcher.on_request(id, request);
                    {
                        let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
                        if write_frame(&mut *w, &response).is_err() {
                            break;
                        }
                    }
                    for ev in &events {
                        clients.broadcast(ev);
                    }
                }
                // A second Hello mid-session is ignored; anything unreadable or a
                // closed pipe ends this client.
                Ok(Some(ClientMessage::Hello { .. })) => {
                    let _ = PROTOCOL_VERSION;
                }
                Ok(None) => break,
                Err(e) if e.is_fatal() => break,
                Err(_) => continue, // oversized/!json frame: skip, keep serving
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uf_ipc::{ConnState, ResponsePayload};
    use uf_probe::{Fingerprint, ProfileCache};

    use crate::config::Config;

    fn dispatcher() -> Dispatcher {
        let orch = Orchestrator::new(&Config::default(), Fingerprint(1), ProfileCache::new());
        Dispatcher::new(Arc::new(Mutex::new(orch)))
    }

    #[test]
    fn get_status_responds_with_id_and_no_events() {
        let d = dispatcher();
        let (resp, events) = d.on_request(42, Request::GetStatus);
        match resp {
            ServerMessage::Response { id, payload } => {
                assert_eq!(id, 42);
                assert!(matches!(payload, ResponsePayload::Status { .. }));
            }
            _ => panic!("expected response"),
        }
        assert!(events.is_empty());
    }

    #[test]
    fn connect_emits_a_status_event() {
        let d = dispatcher();
        let (resp, events) = d.on_request(1, Request::Connect);
        assert!(matches!(resp, ServerMessage::Response { id: 1, .. }));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ServerMessage::Event {
                event: Event::Status { status },
            } => assert_eq!(status.state, ConnState::Scanning),
            _ => panic!("expected a status event"),
        }
    }

    #[test]
    fn shared_orchestrator_keeps_state_across_requests() {
        let orch = Arc::new(Mutex::new(Orchestrator::new(
            &Config::default(),
            Fingerprint(1),
            ProfileCache::new(),
        )));
        let d = Dispatcher::new(Arc::clone(&orch));
        d.on_request(1, Request::Connect);
        let (resp, _) = d.on_request(2, Request::GetStatus);
        match resp {
            ServerMessage::Response {
                payload: ResponsePayload::Status { status },
                ..
            } => assert_eq!(status.state, ConnState::Scanning),
            _ => panic!("expected status"),
        }
    }
}
