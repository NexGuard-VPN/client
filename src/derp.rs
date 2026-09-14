use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::derpframe::{self, FRAME_RELAY, KEY_LEN};

const QUEUE_DEPTH: usize = 256;
const READ_BUF: usize = 32 * 1024;
const COMPACT_THRESHOLD: usize = 64 * 1024;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const IDLE_SLEEP: Duration = Duration::from_micros(500);
const DERP_PATH: &str = "/derp";
const DERP_PROTOCOL: &str = "nexguard-derp";
const PEER_HEADER: &str = "X-NexGuard-Peer";
const TOKEN_HEADER: &str = "X-NexGuard-Token";

pub type Packet = ([u8; KEY_LEN], Vec<u8>);

pub struct DerpClient {
    outbound: SyncSender<Packet>,
    inbound: Receiver<Packet>,
    connected: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
}

impl DerpClient {
    pub fn start(
        host: String,
        token: String,
        public_key_b64: String,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let (out_tx, out_rx) = sync_channel::<Packet>(QUEUE_DEPTH);
        let (in_tx, in_rx) = sync_channel::<Packet>(QUEUE_DEPTH);
        let connected = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicU64::new(0));

        let thread_connected = Arc::clone(&connected);
        std::thread::spawn(move || {
            let mut backoff = RECONNECT_MIN;
            while !shutdown.load(Ordering::Relaxed) {
                match crate::dial::upgrade(
                    &host,
                    DERP_PATH,
                    DERP_PROTOCOL,
                    &[
                        (PEER_HEADER, &public_key_b64),
                        (TOKEN_HEADER, &token),
                    ],
                ) {
                    Ok(mut stream) => {
                        backoff = RECONNECT_MIN;
                        thread_connected.store(true, Ordering::Relaxed);
                        run_session(&mut stream, &out_rx, &in_tx, &shutdown);
                        thread_connected.store(false, Ordering::Relaxed);
                    }
                    Err(_) => {
                        backoff = (backoff * 2).min(RECONNECT_MAX);
                    }
                }
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(backoff);
            }
        });

        Self {
            outbound: out_tx,
            inbound: in_rx,
            connected,
            dropped,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub fn send(&self, dst: &[u8; KEY_LEN], data: &[u8]) -> bool {
        if !self.is_connected() {
            return false;
        }
        match self.outbound.try_send((*dst, data.to_vec())) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn try_recv(&self) -> Option<Packet> {
        self.inbound.try_recv().ok()
    }
}

fn run_session<S: Read + Write>(
    stream: &mut S,
    outbound: &Receiver<Packet>,
    inbound: &SyncSender<Packet>,
    shutdown: &AtomicBool,
) {
    let mut pending: Vec<u8> = Vec::with_capacity(READ_BUF);
    let mut read_buf = vec![0u8; READ_BUF];
    let mut write_buf: Vec<u8> = Vec::with_capacity(READ_BUF);
    let mut last_keepalive = Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        let mut did_work = false;

        loop {
            match outbound.try_recv() {
                Ok((dst, data)) => {
                    derpframe::encode_relay(&mut write_buf, &dst, &data);
                    did_work = true;
                    if write_buf.len() >= READ_BUF {
                        break;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }

        if last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
            last_keepalive = Instant::now();
            derpframe::encode_keepalive(&mut write_buf);
        }

        if !write_buf.is_empty() {
            if stream.write_all(&write_buf).is_err() || stream.flush().is_err() {
                return;
            }
            write_buf.clear();
        }

        match stream.read(&mut read_buf) {
            Ok(0) => return,
            Ok(n) => {
                pending.extend_from_slice(&read_buf[..n]);
                did_work = true;
            }
            Err(e) if is_retryable(&e) => {}
            Err(_) => return,
        }

        let mut consumed = 0;
        loop {
            match derpframe::next_frame(&pending[consumed..]) {
                Ok(Some((frame, size))) => {
                    if frame.kind == FRAME_RELAY {
                        if let Some((src, data)) = derpframe::split_addressed(frame.payload) {
                            let _ = inbound.try_send((src, data.to_vec()));
                        }
                    }
                    consumed += size;
                }
                Ok(None) => break,
                Err(()) => return,
            }
        }

        if consumed > 0 {
            pending.drain(..consumed);
        }
        if pending.capacity() > COMPACT_THRESHOLD && pending.is_empty() {
            pending.shrink_to_fit();
        }

        if !did_work {
            std::thread::sleep(IDLE_SLEEP);
        }
    }
}

fn is_retryable(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}
