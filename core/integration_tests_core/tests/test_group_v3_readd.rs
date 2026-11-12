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
    std::iter::from_fn(|| wire.poll()).collect()
}

fn commits(frames: &[Vec<u8>]) -> usize {
    frames
        .iter()
        .filter(|f| group_v3_wire::is_commit(f))
        .count()
}

/// Saro and Raya each add Pax in the same epoch, so each commits a different
/// next epoch and neither can read the other's. Pax joins Saro's branch first.
fn fork(h: &mut TestHarness<3>, convo: &str) {
    let pax = [h.pax().account()];
    h.saro().group_add_participants(convo, &pax).unwrap();
    h.raya().group_add_participants(convo, &pax).unwrap();
    h.tolerate_inbound_errors();
    h.process(Duration::from_secs(2));
    // Pax's beacon, sent once he joined, reaches Raya.
    h.process(Duration::from_secs(1));
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
    h.process(Duration::from_secs(1));
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
    h.process(Duration::from_secs(2));
    h.process(Duration::from_secs(1));
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
    const PAX: usize = 2;
    const MIRA: usize = 3;
    const NOOR: usize = 4;
    let mut h = TestHarness::<5>::new(|_, _| {});
    let raya = [h.client(RAYA).account()];
    let convo = h
        .client_mut(SARO)
        .create_group_convo_v3(&raya, "", "")
        .unwrap();
    h.process_until(|h| h.client(RAYA).convo_count() == 1);
    let pax = [h.client(PAX).account()];
    h.client_mut(SARO)
        .group_add_participants(&convo, &pax)
        .unwrap();
    h.client_mut(RAYA)
        .group_add_participants(&convo, &pax)
        .unwrap();
    h.tolerate_inbound_errors();
    h.process(Duration::from_secs(2));

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
    h.process(Duration::from_secs(2));
    h.process(Duration::from_secs(1));
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
    let pax = [h.pax().account()];
    h.saro().group_add_participants(&convo, &pax).unwrap();
    h.raya().group_add_participants(&convo, &pax).unwrap();
    h.tolerate_inbound_errors();
    h.process(Duration::from_secs(2));

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

    // Saro hears the repair on the next round.
    h.process(Duration::from_secs(1));
    h.saro().send_content(&convo, b"welcome back").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"welcome back"));
}
