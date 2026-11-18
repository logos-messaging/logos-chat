mod records;

use integration_tests_core::TestHarness;
use records::{Member, Record, signers, trace_of, written_by};
use std::collections::BTreeSet;

#[test]
fn members_record_each_epoch_they_enter_and_their_own_removal() {
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
                r.fields["signer"].as_str(),
                r.fields["participant"].as_str(),
            )
        })
        .collect();
    let cores: Vec<(&str, &str)> = [&saro, &raya, &pax, &mira]
        .iter()
        .map(|m| (m.signer.as_str(), m.participant.as_str()))
        .collect();
    assert_eq!(runs, cores, "each core names its signer and participant");

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
        let entered: Vec<&Record> = records
            .iter()
            .filter(|r| r.name == "epoch" && r.epoch() == epoch)
            .collect();
        let entered_in: BTreeSet<&str> =
            entered.iter().map(|r| r.fields["state"].as_str()).collect();
        assert_eq!(entered_in.len(), 1, "epoch {epoch} has one state");
        states.extend(entered_in);
        for record in entered {
            assert_eq!(record.fields["signers"], signers(&members));
            assert_eq!(record.fields["members"], members.len().to_string());
        }
    }
    assert_eq!(states.len(), 4, "each epoch has a state of its own");
    // Frames go on reaching the two that were removed, Pax in a seat Mira
    // then held, and neither records anything of the conversation it left.
    for gone in [&pax, &mira] {
        let last = records
            .iter()
            .rfind(|r| r.fields["signer"] == gone.signer)
            .expect("a record");
        assert_eq!(last.name, "left");
    }

    let sent: Vec<&Record> = records.iter().filter(|r| r.name == "sent").collect();
    let reads: Vec<&Record> = records.iter().filter(|r| r.name == "received").collect();
    let ([post], [read]) = (&sent[..], &reads[..]) else {
        panic!("one post sent and read: {sent:?} {reads:?}");
    };
    assert_eq!(post.fields["signer"], saro.signer);
    assert_eq!(
        post.epoch(),
        removed,
        "the post is sent at saro's own epoch"
    );
    assert_eq!(read.fields["signer"], raya.signer);
    assert_eq!(read.fields["from"], saro.signer);
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
