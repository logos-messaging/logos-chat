//! Reads the trace records a scenario logs.

use libchat::{ParticipantId, SignerKey};
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

const TARGET: &str = "libchat::mls_trace";
/// The ops' spans, whose fields name the signer and the conversation.
const OPS: [&str; 2] = [
    "libchat::conversation::group_v2",
    "libchat::conversation::group_v3",
];

/// A client as the records name it.
pub struct Member {
    pub signer: String,
    pub participant: String,
}

impl Member {
    /// Shortens a signer and a participant the way the records do.
    pub fn new(signer: SignerKey, participant: ParticipantId) -> Self {
        let short = |id: String| id.chars().take(8).collect();
        Self {
            signer: short(signer.to_string()),
            participant: short(participant.to_string()),
        }
    }
}

/// `members` as an `epoch` record lists them.
pub fn signers(members: &[&Member]) -> String {
    let entries: Vec<String> = members
        .iter()
        .map(|m| format!("{}:{}", m.signer, m.participant))
        .collect();
    entries.join(",")
}

/// The records `member` wrote of the epochs it entered and the conversations
/// it left, as name and epoch, in order.
pub fn written_by<'a>(records: &'a [Record], member: &Member) -> Vec<(&'a str, u64)> {
    records
        .iter()
        .filter(|r| {
            matches!(r.name.as_str(), "epoch" | "left") && r.fields["signer"] == member.signer
        })
        .map(|r| (r.name.as_str(), r.epoch()))
        .collect()
}

/// One trace record: its name and what it says.
#[derive(Debug)]
pub struct Record {
    pub name: String,
    pub fields: BTreeMap<String, String>,
}

impl Record {
    /// The epoch the record is about.
    pub fn epoch(&self) -> u64 {
        self.fields["epoch"].parse().expect("epoch number")
    }
}

/// Runs `scenario` and returns what it returned with the trace records it
/// logged, in the order written. A record's `signer` and `convo` are
/// read off the span of the op that wrote it.
pub fn trace_of<T>(scenario: impl FnOnce() -> T) -> (T, Vec<Record>) {
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .without_time()
            .with_filter(
                Targets::new()
                    .with_target(TARGET, Level::TRACE)
                    .with_targets(OPS.map(|ops| (ops, Level::INFO))),
            ),
    );
    let result = tracing::subscriber::with_default(subscriber, scenario);
    let log = String::from_utf8(buffer.0.lock().unwrap().clone()).expect("utf-8 log");
    let start = format!("{TARGET}: ");
    let records = log
        .lines()
        .filter_map(|line| line.split_once(start.as_str()))
        .map(|(prefix, record)| {
            let mut words = record.split_whitespace();
            let name = words.next().expect("record name").to_string();
            let mut fields = BTreeMap::new();
            let span_fields = prefix
                .rfind('{')
                .map(|open| &prefix[open + 1..prefix.rfind('}').expect("span fields")]);
            let context = span_fields
                .into_iter()
                .flat_map(str::split_whitespace)
                .filter(|word| word.starts_with("signer=") || word.starts_with("convo="));
            for word in context.chain(words) {
                let (key, value) = word.split_once('=').expect("key=value");
                let repeated = fields.insert(key.to_string(), value.to_string());
                assert!(repeated.is_none(), "{key} twice in {prefix}{record}");
            }
            Record { name, fields }
        })
        .collect();
    (result, records)
}

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
