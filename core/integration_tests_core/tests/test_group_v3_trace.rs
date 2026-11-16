mod records;

use integration_tests_core::TestHarness;
use records::{Member, Record, signers, trace_of, written_by};
use std::collections::BTreeSet;
use std::time::Duration;

#[test]
fn members_record_each_epoch_they_enter_and_what_became_of_each_post() {
    // Saro adds Raya, then Raya adds Pax. Saro sends one message while
    // Raya's commit is deferred, and one after it is finalized.
    let ((convo_id, [saro, raya, pax], post_ids), records) = trace_of(|| {
        let mut harness = TestHarness::<3>::new(|_, _| {});
        let members: [Member; 3] = std::array::from_fn(|i| {
            let client = harness.client(i);
            Member::new(client.signer_key(), client.account())
        });
        let (raya, pax) = (harness.raya().account(), harness.pax().account());

        let convo_id = harness
            .saro()
            .create_group_convo_v3(&[raya], "", "")
            .expect("saro create");
        harness.process_until_label("raya joins", |h| h.raya().convo_count() == 1);

        harness
            .raya()
            .group_add_participants(&convo_id, std::slice::from_ref(&pax))
            .expect("raya add pax");
        // Saro gets Raya's commit with no time passing, and sends before it
        // finalizes the commit. Pax's channel starts at that commit, so Pax
        // gets the message, but it is from the epoch before Pax joined.
        harness.process(Duration::ZERO);
        let before_id = harness
            .saro()
            .send_content(&convo_id, b"before pax")
            .expect("saro send before pax");
        harness.process_until_label("pax joins", |h| {
            h.pax().convo_count() == 1
                && h.saro().group_signers(&convo_id).map_or(0, |m| m.len()) == 3
                && h.raya().group_signers(&convo_id).map_or(0, |m| m.len()) == 3
        });

        let after_id = harness
            .saro()
            .send_content(&convo_id, b"after pax")
            .expect("saro send after pax");
        // The second message depends on the first, so Pax fetches it.
        harness.process_until_label("both read it", |h| {
            h.raya().check(&convo_id, b"after pax") && h.pax().check(&convo_id, b"after pax")
        });

        (convo_id, members, [before_id, after_id])
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
    let cores: Vec<(&str, &str)> = [&saro, &raya, &pax]
        .iter()
        .map(|m| (m.signer.as_str(), m.participant.as_str()))
        .collect();
    assert_eq!(runs, cores, "each core names its signer and participant");

    let (created, raya_added, pax_added) = (0, 1, 2);
    assert_eq!(
        written_by(&records, &saro),
        [
            ("epoch", created),
            ("epoch", raya_added),
            ("epoch", pax_added)
        ]
    );
    assert_eq!(
        written_by(&records, &raya),
        [("epoch", raya_added), ("epoch", pax_added)]
    );
    assert_eq!(written_by(&records, &pax), [("epoch", pax_added)]);

    let mut states = BTreeSet::new();
    for (epoch, members) in [
        (created, vec![&saro]),
        (raya_added, vec![&saro, &raya]),
        (pax_added, vec![&saro, &raya, &pax]),
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
    assert_eq!(states.len(), 3, "each epoch has a state of its own");

    let sent: Vec<&Record> = records.iter().filter(|r| r.name == "sent").collect();
    let [before, after] = &sent[..] else {
        panic!("two posts sent: {sent:?}");
    };
    for ((post, epoch), id) in [(before, raya_added), (after, pax_added)]
        .into_iter()
        .zip(&post_ids)
    {
        assert_eq!(post.fields["signer"], saro.signer);
        assert_eq!(post.epoch(), epoch, "a post is sent at saro's own epoch");
        assert_eq!(
            &post.fields["frame"], id,
            "a frame is named by its message id"
        );
    }

    let fates = |name: &str| -> Vec<(&str, &str, u64)> {
        records
            .iter()
            .filter(|r| r.name == name)
            .map(|r| {
                (
                    r.fields["signer"].as_str(),
                    r.fields["frame"].as_str(),
                    r.epoch(),
                )
            })
            .collect()
    };
    let (before_frame, after_frame) = (
        before.fields["frame"].as_str(),
        after.fields["frame"].as_str(),
    );
    assert_eq!(
        fates("received"),
        [
            (raya.signer.as_str(), before_frame, raya_added),
            (raya.signer.as_str(), after_frame, pax_added),
            (pax.signer.as_str(), after_frame, pax_added),
        ]
    );
    assert!(
        records
            .iter()
            .filter(|r| r.name == "received")
            .all(|r| r.fields["from"] == saro.signer)
    );
    // Pax cannot read the first message: it is from the epoch before Pax joined.
    assert_eq!(
        fates("unreadable"),
        [(pax.signer.as_str(), before_frame, raya_added)]
    );
    assert!(
        records
            .iter()
            .filter(|r| r.name == "unreadable")
            .all(|r| r.fields["why"] == "epoch")
    );

    assert!(
        records
            .iter()
            .filter(|r| r.name != "run")
            .all(|r| r.fields["convo"] == convo_id)
    );
}
