use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crossbeam_channel::{Receiver, Sender, bounded};
use logos_chat::{AddressedEnvelope, DeliveryMsgId, DeliveryService, InboundPayload, Transport};

#[derive(Debug, thiserror::Error)]
pub enum FileTransportError {
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Clone, Debug)]
pub struct FileTransport {
    transport_dir: PathBuf,
    inbound_rx: Option<Receiver<InboundPayload>>,
}

impl FileTransport {
    /// All instances pointing at the same `transport_dir` share one broadcast bus.
    ///
    /// Messages are written to `{transport_dir}/{delivery_address}/{hours_since_epoch}.bin`
    /// as length-prefixed frames (`[u32 BE length][payload bytes]`). A background
    /// thread reads all files under `transport_dir` and forwards every frame to the
    /// inbound stream the client drains via [`Transport::inbound`] (discarding frames
    /// it cannot decrypt).
    pub fn new(transport_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(transport_dir)?;

        let (tx, rx) = bounded(1024);
        let dir = transport_dir.to_path_buf();

        thread::Builder::new()
            .name("file-transport".into())
            .spawn(move || poll_reader(dir, tx))?;

        Ok(Self {
            transport_dir: transport_dir.to_path_buf(),
            inbound_rx: Some(rx),
        })
    }
}

impl DeliveryService for FileTransport {
    type Error = FileTransportError;

    fn publish(
        &mut self,
        envelope: AddressedEnvelope,
    ) -> Result<Option<DeliveryMsgId>, FileTransportError> {
        let addr_dir = self.transport_dir.join(&envelope.delivery_address);
        fs::create_dir_all(&addr_dir)?;

        let filename = format!("{}.bin", current_hour());
        let path = addr_dir.join(filename);

        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        let len = envelope.data.len() as u32;
        file.write_all(&len.to_be_bytes())?;
        file.write_all(&envelope.data)?;
        Ok(None)
    }

    fn subscribe(&mut self, _delivery_address: &str) -> Result<(), Self::Error> {
        // FileTransport does not support filtering
        Ok(())
    }

    fn fetch_messages(
        &mut self,
        _delivery_address: &str,
        _delivery_msg_ids: &[DeliveryMsgId],
    ) -> Result<(), Self::Error> {
        // It gives no ids: the reader forwards every frame on disk from the first.
        Ok(())
    }
}

impl Transport for FileTransport {
    fn inbound(&mut self) -> Receiver<InboundPayload> {
        self.inbound_rx
            .take()
            .expect("FileTransport::inbound called more than once")
    }
}

/// Hours since Unix epoch — used as the rolling filename.
fn current_hour() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 3600
}

fn poll_reader(transport_dir: PathBuf, tx: Sender<InboundPayload>) {
    // Maps absolute file path → number of bytes already consumed.
    let mut offsets: BTreeMap<PathBuf, u64> = BTreeMap::new();

    loop {
        let bin_files = collect_bin_files(&transport_dir);

        for path in bin_files {
            let offset = offsets.entry(path.clone()).or_insert(0);

            let file = match File::open(&path) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let mut reader = BufReader::new(file);
            if reader.seek(SeekFrom::Start(*offset)).is_err() {
                continue;
            }

            loop {
                let mut len_buf = [0u8; 4];
                if reader.read_exact(&mut len_buf).is_err() {
                    break; // no complete header yet
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut payload = vec![0u8; len];
                if reader.read_exact(&mut payload).is_err() {
                    break; // partial frame — wait for writer to finish
                }
                let _ = tx.try_send(InboundPayload {
                    data: payload,
                    delivery_info: None,
                });
                *offset += (4 + len) as u64;
            }
        }

        thread::sleep(Duration::from_millis(100));
    }
}

/// Walk `transport_dir/*/` and collect all `*.bin` files, sorted by path
/// (address subdir first, then filename = hour order).
fn collect_bin_files(transport_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(addr_entries) = fs::read_dir(transport_dir) else {
        return files;
    };
    for addr_entry in addr_entries.flatten() {
        let addr_path = addr_entry.path();
        if !addr_path.is_dir() {
            continue;
        }
        let Ok(file_entries) = fs::read_dir(&addr_path) else {
            continue;
        };
        for file_entry in file_entries.flatten() {
            let p = file_entry.path();
            if p.extension().is_some_and(|e| e == "bin") {
                files.push(p);
            }
        }
    }
    files.sort();
    files
}
