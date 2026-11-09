use std::time::Duration;

use components::LocalBroadcaster;
use integration_tests_core::TestHarness;
use libchat::DeliveryService as _;
use libchat::test_support::group_v3_wire;

fn group_of_saro_and_raya() -> (TestHarness<3>, String) {
    let mut h = TestHarness::<3>::new(|_, _| {});
    let raya = [h.raya().account()];
    let convo = h.saro().create_group_convo_v3(&raya, "", "").unwrap();
    h.process_until(|h| h.raya().convo_count() == 1);
    (h, convo)
}

/// A consumer of the shared wire that sees every frame published to `convo_id`
/// from now on.
fn watch(h: &mut TestHarness<3>, convo_id: &str) -> LocalBroadcaster {
    let mut wire = h.client_mut(0).ds().new_consumer();
    wire.subscribe(&group_v3_wire::delivery_address(convo_id))
        .expect("subscribe");
    wire
}

fn drain(wire: &mut LocalBroadcaster) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| wire.poll().map(|(data, _)| data)).collect()
}

/// Steps virtual time past the commit finalization delay, so every pending
/// commit is merged (or dropped) and its Welcomes and beacons are out.
fn settle<const N: usize>(h: &mut TestHarness<N>) {
    for _ in 0..125 {
        h.process(Duration::from_secs(1));
    }
}

fn commits(frames: &[Vec<u8>]) -> usize {
    frames
        .iter()
        .filter(|f| group_v3_wire::is_commit(f))
        .count()
}

/// Saro and Raya each add Pax in the same epoch, and neither hears the other's
/// commit before finalizing its own, so each moves to a different next epoch
/// and neither can read the other's. Pax joins Saro's branch first.
fn fork<const N: usize>(h: &mut TestHarness<N>, convo: &str) {
    let pax = [h.client(2).account()];
    for i in 0..2 {
        h.client_mut(i)
            .ds()
            .reject_publishes(|e| group_v3_wire::is_commit(&e.data));
    }
    h.client_mut(0).group_add_participants(convo, &pax).unwrap();
    h.client_mut(1).group_add_participants(convo, &pax).unwrap();
    h.tolerate_inbound_errors();
    settle(h);
    for i in 0..2 {
        h.client_mut(i).ds().accept_all_publishes();
    }
    settle(h);
}

#[test]
fn a_forked_member_is_readded_once_and_everyone_hears_each_other() {
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo);

    h.saro().send_content(&convo, b"lost").unwrap();
    h.process(Duration::from_secs(1));
    assert!(
        !h.raya().check(&convo, b"lost"),
        "the group should be forked"
    );

    let mut wire = watch(&mut h, &convo);
    let asked = h.raya().group_request_readd(&convo).unwrap();
    assert!(
        asked > 0,
        "Raya heard Saro's beacon, so has a branch to ask"
    );
    h.process(Duration::from_secs(2));
    assert_eq!(commits(&drain(&mut wire)), 1, "exactly one repair");
    // Saro merges the repair before she sends, whoever answered.
    settle(&mut h);
    h.saro().send_content(&convo, b"welcome back").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"welcome back"));
    h.raya().send_content(&convo, b"thanks").unwrap();
    h.process_until(|h| h.saro().check(&convo, b"thanks"));

    // Raya's Welcome to Pax arrived second, unasked, and must not have moved
    // Pax off Saro's branch.
    h.process_until(|h| h.pax().check(&convo, b"welcome back"));
}

/// The replaced group's subscription and tick carry over to the new one.
#[test]
fn a_readd_keeps_one_tick() {
    const RAYA: usize = 1;
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo);
    assert_eq!(h.pending_wakeups(RAYA, &convo), 1);

    h.raya().group_request_readd(&convo).unwrap();
    // The repair is merged once finalized, before Saro sends.
    settle(&mut h);
    h.saro().send_content(&convo, b"welcome back").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"welcome back"));

    assert_eq!(h.pending_wakeups(RAYA, &convo), 1);
}

/// After the fork Mira joins Saro's branch and commits last. Raya never knew
/// her and would refuse her Welcome, so Raya names a member she does know.
#[test]
fn the_answerer_is_one_the_asker_knows() {
    const SARO: usize = 0;
    const RAYA: usize = 1;
    const MIRA: usize = 3;
    const NOOR: usize = 4;
    let mut h = TestHarness::<5>::new(|_, _| {});
    let raya = [h.client(RAYA).account()];
    let convo = h
        .client_mut(SARO)
        .create_group_convo_v3(&raya, "", "")
        .unwrap();
    h.process_until(|h| h.client(RAYA).convo_count() == 1);
    fork(&mut h, &convo);

    let mira = [h.client(MIRA).account()];
    h.client_mut(SARO)
        .group_add_participants(&convo, &mira)
        .unwrap();
    h.process_until(|h| h.client(MIRA).convo_count() == 1);
    let noor = [h.client(NOOR).account()];
    h.client_mut(MIRA)
        .group_add_participants(&convo, &noor)
        .unwrap();
    h.process_until(|h| h.client(NOOR).convo_count() == 1);
    h.process(Duration::from_secs(1));

    assert!(h.client_mut(RAYA).group_request_readd(&convo).unwrap() > 0);
    // The repair is merged once finalized, before Saro sends.
    settle(&mut h);
    h.client_mut(SARO)
        .send_content(&convo, b"welcome back")
        .unwrap();
    h.process_until(|h| h.client(RAYA).check(&convo, b"welcome back"));
}

#[test]
fn without_a_fork_there_is_no_branch_to_ask() {
    let (mut h, convo) = group_of_saro_and_raya();
    h.saro().send_content(&convo, b"hello").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"hello"));

    assert_eq!(h.raya().group_request_readd(&convo).unwrap(), 0);
}

/// Anyone who saw a beacon can seal to it, but only the named member can sign.
#[test]
fn an_unsigned_request_changes_nothing() {
    let (mut h, convo) = group_of_saro_and_raya();
    let mut wire = watch(&mut h, &convo);
    let pax = [h.pax().account()];
    h.saro().group_add_participants(&convo, &pax).unwrap();
    h.process_until(|h| h.pax().convo_count() == 1);
    h.process(Duration::from_secs(1));

    let saro = h.saro().signer_key();
    let beacon = drain(&mut wire)
        .into_iter()
        .find(|f| group_v3_wire::beacon_signed_by(f, &convo, &saro).is_some())
        .expect("Saro's beacon");
    let raya = h.raya().signer_key();
    let forged =
        group_v3_wire::unsigned_readd(&beacon, &convo, &raya, "00000000000000").expect("sealed");
    wire.publish(forged).unwrap();
    h.process(Duration::from_secs(2));

    assert_eq!(commits(&drain(&mut wire)), 0);
}

/// Saro repairs Raya, then Pax commits and so answers the next epoch. A copy of
/// Raya's old request, republished by anyone, must not remove her again.
#[test]
fn a_replayed_request_does_not_remove_a_repaired_member() {
    let mut h = TestHarness::<4>::new(|_, _| {});
    let raya = [h.raya().account()];
    let convo = h.saro().create_group_convo_v3(&raya, "", "").unwrap();
    h.process_until(|h| h.raya().convo_count() == 1);
    fork(&mut h, &convo);

    let mut wire = h.client_mut(0).ds().new_consumer();
    wire.subscribe(&group_v3_wire::delivery_address(&convo))
        .expect("subscribe");
    h.raya().group_request_readd(&convo).unwrap();
    h.process(Duration::from_secs(2));
    let request: Vec<_> = drain(&mut wire)
        .into_iter()
        .filter(|f| group_v3_wire::is_sealed(f))
        .collect();
    assert!(!request.is_empty());
    settle(&mut h);

    let mira = [h.mira().account()];
    h.pax().group_add_participants(&convo, &mira).unwrap();
    h.process_until(|h| h.mira().convo_count() == 1);
    h.process(Duration::from_secs(1));
    drain(&mut wire);

    for data in request {
        let delivery_address = group_v3_wire::delivery_address(&convo);
        wire.publish(libchat::AddressedEnvelope {
            delivery_address,
            data,
        })
        .unwrap();
    }
    h.process(Duration::from_secs(2));
    assert_eq!(commits(&drain(&mut wire)), 0, "the replay caused a repair");

    h.saro().send_content(&convo, b"still here").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"still here"));
}

/// Asking again before the first answer lands must reach the same answerer,
/// or two members repair the same epoch and fork the group again.
#[test]
fn asking_twice_before_an_answer_gets_one_repair() {
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo);

    let mut wire = watch(&mut h, &convo);
    assert_eq!(h.raya().group_request_readd(&convo).unwrap(), 1);
    assert_eq!(h.raya().group_request_readd(&convo).unwrap(), 1);
    h.process(Duration::from_secs(2));

    assert_eq!(commits(&drain(&mut wire)), 1, "exactly one repair");
}

/// Raya names Saro and Pax in key order. The first misses the request: asking
/// again changes nothing, and only a retry reaches the other, who repairs.
/// Pax repairs Raya unasked. The Welcome must not replace her group.
#[test]
fn an_unasked_welcome_does_not_replace_a_group() {
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo);
    let raya = h.raya().signer_key();
    h.pax().group_force_readd(&convo, &raya).unwrap();
    settle(&mut h);

    h.saro().send_content(&convo, b"unasked").unwrap();
    h.process(Duration::from_secs(2));
    assert!(
        !h.raya().check(&convo, b"unasked"),
        "Raya's group was replaced"
    );
}

/// Raya asks, but neither Saro nor Pax hears it. A Welcome that comes after
/// she stopped waiting must not replace her group.
#[test]
fn a_welcome_after_the_wait_is_refused() {
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo);
    assert_eq!(h.raya().group_request_readd(&convo).unwrap(), 1);
    h.saro().drop_pending_payloads();
    h.pax().drop_pending_payloads();
    for _ in 0..3 {
        settle(&mut h);
    }

    let raya = h.raya().signer_key();
    h.pax().group_force_readd(&convo, &raya).unwrap();
    settle(&mut h);
    h.saro().send_content(&convo, b"too late").unwrap();
    h.process(Duration::from_secs(2));
    assert!(
        !h.raya().check(&convo, b"too late"),
        "Raya's group was replaced"
    );
}

/// Saro removes and re-adds Raya, who is on his branch. She waits for the
/// commit to be finalized like any other, rather than leaving at once.
#[test]
fn a_commit_that_removes_us_waits_for_finality() {
    let (mut h, convo) = group_of_saro_and_raya();
    h.tolerate_inbound_errors();
    let raya = h.raya().signer_key();
    h.saro().group_force_readd(&convo, &raya).unwrap();
    // Delivered, with no time for any commit to be finalized.
    h.process(Duration::ZERO);

    assert!(h.raya().send_content(&convo, b"still here").is_ok());
}

#[test]
fn a_retry_reaches_the_next_member() {
    const SARO: usize = 0;
    const PAX: usize = 2;
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo);
    let first = if h.saro().signer_key().as_bytes() < h.pax().signer_key().as_bytes() {
        SARO
    } else {
        PAX
    };

    let mut wire = watch(&mut h, &convo);
    for _ in 0..2 {
        h.raya().group_request_readd(&convo).unwrap();
        h.client_mut(first).drop_pending_payloads();
        h.process(Duration::from_secs(2));
    }
    assert_eq!(commits(&drain(&mut wire)), 0, "only the first may answer");

    h.raya().group_retry_readd(&convo).unwrap();
    h.client_mut(first).drop_pending_payloads();
    h.process(Duration::from_secs(2));
    assert_eq!(commits(&drain(&mut wire)), 1, "the second repairs");

    // Saro hears Pax's repair, and merges it once it is finalized.
    settle(&mut h);
    h.saro().send_content(&convo, b"welcome back").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"welcome back"));
}
