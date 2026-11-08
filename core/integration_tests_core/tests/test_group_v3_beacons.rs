use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use components::LocalBroadcaster;
use integration_tests_core::TestHarness;
use libchat::DeliveryService as _;
use libchat::test_support::group_v3_wire;

/// A consumer of the shared wire that sees every frame published to `convo_id`
/// from now on, whoever sent it.
fn watch<const N: usize>(h: &mut TestHarness<N>, convo_id: &str) -> LocalBroadcaster {
    let mut wire = h.client_mut(0).ds().new_consumer();
    wire.subscribe(&group_v3_wire::delivery_address(convo_id))
        .expect("subscribe");
    wire
}

fn drain(wire: &mut LocalBroadcaster) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| wire.poll()).collect()
}

fn reject_beacons(envelope: &libchat::AddressedEnvelope) -> bool {
    group_v3_wire::is_beacon(&envelope.data)
}

/// Counts every beacon `ds` publishes, failing each one while `fail` is set.
fn count_beacons(ds: &mut LocalBroadcaster, fail: Rc<Cell<bool>>) -> Rc<Cell<u32>> {
    let attempts = Rc::new(Cell::new(0));
    let counted = attempts.clone();
    ds.reject_publishes(move |envelope| {
        if !reject_beacons(envelope) {
            return false;
        }
        counted.set(counted.get() + 1);
        fail.get()
    });
    attempts
}

/// Advances virtual time in small steps, so each retry is scheduled from the
/// moment the previous one fired.
fn advance<const N: usize>(h: &mut TestHarness<N>, total: Duration) {
    let step = Duration::from_millis(100);
    for _ in 0..total.as_millis() / step.as_millis() {
        h.process(step);
    }
}

#[test]
fn every_message_in_an_epoch_carries_the_beacon() {
    let mut h = TestHarness::<2>::new(|_, _| {});
    let raya = [h.raya().account()];
    let convo = h.saro().create_group_convo_v3(&raya, "", "").unwrap();
    h.process_until(|h| h.raya().convo_count() == 1);

    let mut wire = watch(&mut h, &convo);
    for text in [b"one", b"two", b"six"] {
        h.saro().send_content(&convo, text).unwrap();
    }

    let aad: Vec<_> = drain(&mut wire)
        .iter()
        .filter_map(|data| group_v3_wire::application_aad_beacon(data))
        .collect();
    assert_eq!(aad, vec![Some(1); 3]);
}

#[test]
fn a_member_publishes_a_beacon_after_a_peers_commit() {
    let mut h = TestHarness::<3>::new(|_, _| {});
    let raya = [h.raya().account()];
    let convo = h.saro().create_group_convo_v3(&raya, "", "").unwrap();
    h.process_until(|h| h.raya().convo_count() == 1);

    let mut wire = watch(&mut h, &convo);
    let pax = [h.pax().account()];
    h.saro().group_add_participants(&convo, &pax).unwrap();
    h.process_until(|h| h.pax().convo_count() == 1);
    h.process(std::time::Duration::from_secs(1));

    let raya_key = h.raya().signer_key();
    let raya_signed: Vec<_> = drain(&mut wire)
        .iter()
        .filter_map(|data| group_v3_wire::beacon_signed_by(data, &convo, &raya_key))
        .collect();
    assert_eq!(raya_signed, vec![2]);
}

#[test]
fn a_failed_beacon_does_not_stop_the_invitation() {
    let mut h = TestHarness::<2>::new(|_, _| {});
    h.saro().ds().reject_publishes(reject_beacons);

    let raya = [h.raya().account()];
    let convo = h.saro().create_group_convo_v3(&raya, "", "").unwrap();
    h.process_until(|h| h.raya().convo_count() == 1);

    h.saro().send_content(&convo, b"hello").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"hello"));
}

/// Nobody sends and nothing arrives: only a scheduled retry can deliver it.
#[test]
fn an_idle_member_delivers_its_beacon_once_the_transport_recovers() {
    let mut h = TestHarness::<2>::new(|_, _| {});
    h.saro().ds().reject_publishes(reject_beacons);
    let raya = [h.raya().account()];
    let convo = h.saro().create_group_convo_v3(&raya, "", "").unwrap();
    h.process_until(|h| h.raya().convo_count() == 1);

    let mut wire = watch(&mut h, &convo);
    h.saro().ds().accept_all_publishes();
    h.process(std::time::Duration::from_secs(120));

    let saro_key = h.saro().signer_key();
    let saro_signed: Vec<_> = drain(&mut wire)
        .iter()
        .filter_map(|data| group_v3_wire::beacon_signed_by(data, &convo, &saro_key))
        .collect();
    assert_eq!(saro_signed, vec![1]);
}

#[test]
fn a_failed_beacon_does_not_stop_a_join() {
    let mut h = TestHarness::<2>::new(|_, _| {});
    h.raya().ds().reject_publishes(reject_beacons);

    let raya = [h.raya().account()];
    let convo = h.saro().create_group_convo_v3(&raya, "", "").unwrap();
    h.process_until(|h| h.raya().convo_count() == 1);

    h.saro().send_content(&convo, b"hello").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"hello"));
}

/// Steps virtual time to each `(ms, attempts)` mark, checking the count there.
fn expect_attempts<const N: usize>(
    h: &mut TestHarness<N>,
    attempts: &Cell<u32>,
    marks: &[(u64, u32)],
) {
    let mut now = 0;
    for &(at, expected) in marks {
        advance(h, Duration::from_millis(at - now));
        now = at;
        assert_eq!(attempts.get(), expected, "beacon attempts by t = {at} ms");
    }
}

/// Each epoch's failure must share the one retry schedule, not start its own.
#[test]
fn retries_do_not_multiply_across_epochs() {
    let mut h = TestHarness::<4>::new(|_, _| {});
    let raya = [h.raya().account()];
    let convo = h.saro().create_group_convo_v3(&raya, "", "").unwrap();
    h.process_until(|h| h.raya().convo_count() == 1);

    let attempts = count_beacons(h.saro().ds(), Rc::new(Cell::new(true)));
    for joiner in [h.pax().account(), h.mira().account()] {
        h.saro().group_add_participants(&convo, &[joiner]).unwrap();
    }
    assert_eq!(attempts.get(), 2, "one first attempt per epoch");

    // One schedule: retries at t = 1, 3 and 7 s.
    let marks = [
        (500, 2),
        (1_500, 3),
        (2_500, 3),
        (3_500, 4),
        (6_500, 4),
        (7_500, 5),
    ];
    expect_attempts(&mut h, &attempts, &marks);
}

/// A delivery between two failing epochs must not start another schedule.
#[test]
fn a_delivery_between_epochs_does_not_start_another_chain() {
    let mut h = TestHarness::<4>::new(|_, _| {});
    let convo = h.saro().create_group_convo_v3(&[], "", "").unwrap();

    let fail = Rc::new(Cell::new(true));
    let attempts = count_beacons(h.saro().ds(), fail.clone());
    let joiners = [h.raya().account(), h.pax().account(), h.mira().account()];
    for (joiner, delivered) in joiners.into_iter().zip([false, true, false]) {
        fail.set(!delivered);
        h.saro().group_add_participants(&convo, &[joiner]).unwrap();
    }
    assert_eq!(attempts.get(), 3, "one first attempt per epoch");

    let marks = [(500, 3), (1_500, 4), (2_500, 4), (3_500, 5)];
    expect_attempts(&mut h, &attempts, &marks);
}
