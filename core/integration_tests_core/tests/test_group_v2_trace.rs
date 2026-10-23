use integration_tests_core::TestHarness;
use libchat::{ParticipantId, SignerKey};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex};
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

const TARGET: &str = "libchat::mls_trace";

#[test]
fn members_record_each_epoch_they_hold_and_their_own_removal() {
    // Three commits, each of its own kind: one adds Pax, one removes Pax and
    // adds Mira, who takes the leaf Pax held, and one only removes Mira. Only
    // members added after the group was created are removed, so no removal
    // starts a steward election.
    let ((convo_id, [saro, raya, pax, mira]), records) = trace_of(|| {
        let mut harness = TestHarness::<4>::new(|_, _| {});
        // Pax, removed with its leaf refilled, still reads frames and rejects
        // each one.
        harness.tolerate_inbound_errors();
        let members: [Member; 4] = std::array::from_fn(|i| {
            let client = harness.client(i);
            Member::new(client.signer_key(), client.account())
        });
        let (raya, pax, mira) = (
            harness.raya().account(),
            harness.pax().account(),
            harness.mira().account(),
        );

        let convo_id = harness
            .saro()
            .create_group_convo_v2(&[raya], "", "")
            .expect("saro create");
        harness.process_until_label("raya joins", |h| h.raya().convo_count() == 1);

        harness
            .raya()
            .group_add_participants(&convo_id, std::slice::from_ref(&pax))
            .expect("raya add pax");
        harness.process_until_label("pax joins", |h| {
            h.pax().convo_count() == 1
                && h.saro().group_signers(&convo_id).map_or(0, |m| m.len()) == 3
        });

        harness
            .saro()
            .group_remove_participants(&convo_id, &[pax])
            .expect("saro remove pax");
        harness
            .saro()
            .group_add_participants(&convo_id, std::slice::from_ref(&mira))
            .expect("saro add mira");
        harness.process_until_label("mira replaces pax", |h| h.mira().convo_count() == 1);

        harness
            .saro()
            .group_remove_participants(&convo_id, &[mira])
            .expect("saro remove mira");
        harness.process_until_label("mira removed", |h| {
            h.saro().group_signers(&convo_id).map_or(0, |m| m.len()) == 2
                && h.raya().group_signers(&convo_id).map_or(0, |m| m.len()) == 2
        });

        // Saro and Raya still share an epoch, and by the time the message
        // lands every client has read the last commit.
        harness
            .saro()
            .send_content(&convo_id, b"still here")
            .expect("saro send");
        harness.process_until_label("raya receives", |h| {
            h.raya().check(&convo_id, b"still here")
        });

        (convo_id, members)
    });

    let runs: Vec<(&str, &str)> = records
        .iter()
        .filter(|r| r.name == "run")
        .map(|r| {
            (
                r.fields["installation"].as_str(),
                r.fields["account"].as_str(),
            )
        })
        .collect();
    let cores: Vec<(&str, &str)> = [&saro, &raya, &pax, &mira]
        .iter()
        .map(|m| (m.installation.as_str(), m.account.as_str()))
        .collect();
    assert_eq!(runs, cores, "each core names its installation and account");

    let created = written_by(&records, &saro)[0].1;
    let (added, swapped, removed) = (created + 1, created + 2, created + 3);

    assert_eq!(
        written_by(&records, &saro),
        [
            ("epoch", created),
            ("epoch", added),
            ("epoch", swapped),
            ("epoch", removed)
        ]
    );
    assert_eq!(written_by(&records, &raya), written_by(&records, &saro));
    assert_eq!(
        written_by(&records, &pax),
        [("epoch", added), ("left", swapped)]
    );
    assert_eq!(
        written_by(&records, &mira),
        [("epoch", swapped), ("left", removed)]
    );

    let mut states = BTreeSet::new();
    for (epoch, members) in [
        (created, vec![&saro, &raya]),
        (added, vec![&saro, &raya, &pax]),
        (swapped, vec![&saro, &raya, &mira]),
        (removed, vec![&saro, &raya]),
    ] {
        let held: Vec<&Record> = records
            .iter()
            .filter(|r| r.name == "epoch" && r.epoch() == epoch)
            .collect();
        let held_as: BTreeSet<&str> = held.iter().map(|r| r.fields["state"].as_str()).collect();
        assert_eq!(held_as.len(), 1, "epoch {epoch} is held in one state");
        states.extend(held_as);
        for record in held {
            assert_eq!(record.fields["roster"], roster(&members));
            assert_eq!(record.fields["members"], members.len().to_string());
        }
    }
    assert_eq!(states.len(), 4, "each epoch has a state of its own");
    // Frames go on reaching the two that were removed, Pax in a seat Mira
    // then held, and neither records anything of the conversation it left.
    for gone in [&pax, &mira] {
        let last = records
            .iter()
            .rfind(|r| r.fields["installation"] == gone.installation)
            .expect("a record");
        assert_eq!(last.name, "left");
    }

    let sent: Vec<&Record> = records.iter().filter(|r| r.name == "sent").collect();
    let reads: Vec<&Record> = records.iter().filter(|r| r.name == "received").collect();
    let ([post], [read]) = (&sent[..], &reads[..]) else {
        panic!("one post sent and read: {sent:?} {reads:?}");
    };
    assert_eq!(post.fields["installation"], saro.installation);
    assert_eq!(
        post.epoch(),
        removed,
        "the post is sent at the epoch saro holds"
    );
    assert_eq!(read.fields["installation"], raya.installation);
    assert_eq!(read.fields["from"], saro.installation);
    assert_eq!(
        read.fields["frame"], post.fields["frame"],
        "one frame at both ends"
    );
    assert_eq!(read.epoch(), post.epoch());

    assert!(
        records
            .iter()
            .filter(|r| r.name != "run")
            .all(|r| r.fields["convo"] == convo_id)
    );
}

/// A client as the records name it.
struct Member {
    installation: String,
    account: String,
}

impl Member {
    /// Shortens a signer and an account the way the records do.
    fn new(installation: SignerKey, account: ParticipantId) -> Self {
        let short = |id: String| id.chars().take(8).collect();
        Self {
            installation: short(installation.to_string()),
            account: short(account.to_string()),
        }
    }
}

/// `members` as an `epoch` record lists them.
fn roster(members: &[&Member]) -> String {
    let entries: Vec<String> = members
        .iter()
        .map(|m| format!("{}:{}", m.installation, m.account))
        .collect();
    entries.join(",")
}

/// The records `member` wrote of the epochs it held and the conversations it
/// left, as name and epoch, in order.
fn written_by<'a>(records: &'a [Record], member: &Member) -> Vec<(&'a str, u64)> {
    records
        .iter()
        .filter(|r| {
            matches!(r.name.as_str(), "epoch" | "left")
                && r.fields["installation"] == member.installation
        })
        .map(|r| (r.name.as_str(), r.epoch()))
        .collect()
}

/// One trace record: its name and what it says.
#[derive(Debug)]
struct Record {
    name: String,
    fields: BTreeMap<String, String>,
}

impl Record {
    /// The epoch the record is about.
    fn epoch(&self) -> u64 {
        self.fields["epoch"].parse().expect("epoch number")
    }
}

/// Runs `scenario` and returns what it returned with the trace records it
/// logged, in the order written.
fn trace_of<T>(scenario: impl FnOnce() -> T) -> (T, Vec<Record>) {
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .without_time()
            .with_filter(Targets::new().with_target(TARGET, Level::TRACE)),
    );
    let result = tracing::subscriber::with_default(subscriber, scenario);
    let log = String::from_utf8(buffer.0.lock().unwrap().clone()).expect("utf-8 log");
    let start = format!("{TARGET}: ");
    let records = log
        .lines()
        .filter_map(|line| line.split_once(start.as_str()))
        .map(|(_, record)| {
            let mut words = record.split_whitespace();
            let name = words.next().expect("record name").to_string();
            let mut fields = BTreeMap::new();
            for word in words {
                let (key, value) = word.split_once('=').expect("key=value");
                let repeated = fields.insert(key.to_string(), value.to_string());
                assert!(repeated.is_none(), "{key} twice in {record}");
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
