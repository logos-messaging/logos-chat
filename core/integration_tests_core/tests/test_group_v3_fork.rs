use std::time::Duration;

use integration_tests_core::TestHarness;
use libchat::SyncState;
use libchat::test_support::group_v3_wire;

fn group_of_saro_and_raya() -> (TestHarness<4>, String) {
    let mut h = TestHarness::<4>::new(|_, _| {});
    let raya = [h.raya().account()];
    let convo = h.saro().create_group_convo_v3(&raya, "", "").unwrap();
    h.process_until(|h| h.raya().convo_count() == 1);
    (h, convo)
}

/// Steps virtual time past the commit finalization delay.
fn settle(h: &mut TestHarness<4>) {
    for _ in 0..125 {
        h.process(Duration::from_secs(1));
    }
}

/// Saro and Raya each add Pax in epoch 1 without hearing the other's commit,
/// so they hold different states at epoch 2. Pax joins Saro's branch.
/// `also_reject` holds back more of everyone's frames from then on.
fn fork(h: &mut TestHarness<4>, convo: &str, also_reject: fn(&[u8]) -> bool) {
    let pax = [h.pax().account()];
    for i in 0..4 {
        h.client_mut(i)
            .ds()
            .reject_publishes(move |e| also_reject(&e.data));
    }
    for i in 0..2 {
        h.client_mut(i)
            .ds()
            .reject_publishes(move |e| group_v3_wire::is_commit(&e.data) || also_reject(&e.data));
    }
    h.saro().group_add_participants(convo, &pax).unwrap();
    h.raya().group_add_participants(convo, &pax).unwrap();
    h.tolerate_inbound_errors();
    settle(h);
    for i in 0..2 {
        h.client_mut(i)
            .ds()
            .reject_publishes(move |e| also_reject(&e.data));
    }
    settle(h);
}

fn nothing(_: &[u8]) -> bool {
    false
}

#[test]
fn both_sides_of_a_fork_see_it() {
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo, nothing);

    let forked = SyncState::Forked { at_or_before: 2 };
    assert_eq!(h.saro().group_sync_state(&convo).unwrap(), forked);
    assert_eq!(h.raya().group_sync_state(&convo).unwrap(), forked);
}

/// Raya's branch, and Pax on it, sign epoch 2 while Saro is still in epoch 1.
/// Saro must still see the fork once its own commit lands.
#[test]
fn a_rival_heard_before_our_own_commit_lands_is_a_fork() {
    let (mut h, convo) = group_of_saro_and_raya();
    let pax = [h.pax().account()];
    for i in 0..2 {
        h.client_mut(i)
            .ds()
            .reject_publishes(|e| group_v3_wire::is_commit(&e.data));
    }
    h.raya().group_add_participants(&convo, &pax).unwrap();
    h.tolerate_inbound_errors();
    h.process_until(|h| h.pax().convo_count() == 1);
    h.process(Duration::from_secs(1));

    h.saro().group_add_participants(&convo, &pax).unwrap();
    settle(&mut h);

    let forked = SyncState::Forked { at_or_before: 2 };
    assert_eq!(h.saro().group_sync_state(&convo).unwrap(), forked);
}

/// Saro stays `Forked` through Pax's beacons, and clears only once Raya is
/// back on Saro's branch.
#[test]
fn the_side_that_stays_clears_once_the_other_is_readded() {
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo, nothing);

    assert_eq!(h.raya().group_request_readd(&convo).unwrap(), 1);
    settle(&mut h);
    h.saro().send_content(&convo, b"welcome back").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"welcome back"));
    settle(&mut h);

    assert_eq!(
        h.saro().group_sync_state(&convo).unwrap(),
        SyncState::Synced
    );
}

/// No beacons, so only Saro's next commit says something is wrong.
#[test]
fn a_commit_on_the_other_branch_is_only_a_suspicion() {
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo, group_v3_wire::is_beacon);
    assert_eq!(
        h.raya().group_sync_state(&convo).unwrap(),
        SyncState::Unknown
    );

    let mira = [h.mira().account()];
    h.saro().group_add_participants(&convo, &mira).unwrap();
    h.process(Duration::from_secs(1));

    assert_eq!(
        h.raya().group_sync_state(&convo).unwrap(),
        SyncState::Suspect { epoch: 2 }
    );
}

/// Each side of a fork reaches epoch 2 on its own commit, so the two share the
/// epoch but not its fingerprint.
#[test]
fn a_fork_shares_the_epoch_not_the_fingerprint() {
    let (mut h, convo) = group_of_saro_and_raya();
    let before = h.saro().debug_data(&convo).unwrap();
    assert!(before.contains_key("epoch_fingerprint"));
    assert_eq!(h.raya().debug_data(&convo).unwrap(), before);

    fork(&mut h, &convo, nothing);

    let saro = h.saro().debug_data(&convo).unwrap();
    let raya = h.raya().debug_data(&convo).unwrap();
    assert_eq!(saro["epoch"], 2);
    assert_eq!(raya["epoch"], 2);
    assert_ne!(saro["epoch_fingerprint"], raya["epoch_fingerprint"]);
    assert_eq!(h.pax().debug_data(&convo).unwrap(), saro);
}

#[test]
fn a_healthy_group_is_synced() {
    let (mut h, convo) = group_of_saro_and_raya();
    let pax = [h.pax().account()];
    h.saro().group_add_participants(&convo, &pax).unwrap();
    h.process_until(|h| h.pax().convo_count() == 1);
    settle(&mut h);

    assert_eq!(
        h.saro().group_sync_state(&convo).unwrap(),
        SyncState::Synced
    );
    assert_eq!(
        h.raya().group_sync_state(&convo).unwrap(),
        SyncState::Synced
    );
}
