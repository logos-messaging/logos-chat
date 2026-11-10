use std::time::Duration;

use integration_tests_core::TestHarness;
use libchat::DeliveryService as _;
use libchat::SyncState;
use libchat::test_support::group_v3_wire;

fn reject_beacons(envelope: &libchat::AddressedEnvelope) -> bool {
    group_v3_wire::is_beacon(&envelope.data)
}

/// Saro and Raya in a group, at epoch 1.
fn group(h: &mut TestHarness<4>) -> String {
    let raya = [h.raya().account()];
    let convo = h.saro().create_group_convo_v3(&raya, "", "").unwrap();
    h.process_until(|h| h.raya().convo_count() == 1);
    convo
}

/// Both add Pax without seeing each other's commit, so each merges its own and
/// they hold different states at epoch 2.
fn fork(h: &mut TestHarness<4>, convo: &str) {
    let pax = [h.pax().account()];
    h.saro().group_add_participants(convo, &pax).unwrap();
    h.raya().group_add_participants(convo, &pax).unwrap();
    // Pax gets two Welcomes for one conversation.
    h.tolerate_inbound_errors();
    h.process(Duration::from_secs(2));
}

fn forked(we_move: bool) -> SyncState {
    SyncState::Forked {
        at_or_before: 2,
        we_move,
    }
}

/// Saro hears Raya first, 1 signer to 1, a tie where neither moves. Repeat so
/// that whatever the ids, Pax's beacon must still re-rank it.
#[test]
fn only_the_outranked_side_of_a_fork_moves() {
    for _ in 0..8 {
        let mut h = TestHarness::<4>::new(|_, _| {});
        let convo = group(&mut h);
        fork(&mut h, &convo);
        // Pax's beacon, from its join.
        h.process(Duration::from_secs(2));

        // Pax took Saro's Welcome, so Saro's branch has two signers to Raya's
        // one. Saro stays and Raya moves.
        assert_eq!(h.saro().group_sync_state(&convo).unwrap(), forked(false));
        assert_eq!(h.raya().group_sync_state(&convo).unwrap(), forked(true));
    }
}

/// Saro stays `Forked` through Pax's beacons, and clears only once Raya is
/// back on Saro's branch.
#[test]
fn the_side_that_stays_clears_once_the_other_is_readded() {
    let mut h = TestHarness::<4>::new(|_, _| {});
    let convo = group(&mut h);
    fork(&mut h, &convo);
    h.process(Duration::from_secs(2));

    assert_eq!(h.raya().group_request_readd(&convo).unwrap(), 1);
    h.process(Duration::from_secs(2));
    h.saro().send_content(&convo, b"welcome back").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"welcome back"));
    h.process(Duration::from_secs(2));

    assert_eq!(
        h.saro().group_sync_state(&convo).unwrap(),
        SyncState::Synced
    );
}

#[test]
fn a_commit_on_the_other_branch_is_only_a_suspicion() {
    let mut h = TestHarness::<4>::new(|_, _| {});
    let convo = group(&mut h);
    for i in 0..4 {
        h.client_mut(i).ds().reject_publishes(reject_beacons);
    }
    fork(&mut h, &convo);
    assert_eq!(
        h.raya().group_sync_state(&convo).unwrap(),
        SyncState::Unknown
    );

    let mira = [h.mira().account()];
    h.saro().group_add_participants(&convo, &mira).unwrap();
    h.process(Duration::from_secs(2));

    assert_eq!(
        h.raya().group_sync_state(&convo).unwrap(),
        SyncState::Suspect { epoch: 2 }
    );
}

#[test]
fn a_junk_commit_at_our_epoch_is_only_a_suspicion() {
    let mut h = TestHarness::<4>::new(|_, _| {});
    let convo = group(&mut h);
    h.tolerate_inbound_errors();

    let junk = group_v3_wire::junk_commit(&convo, 1);
    h.saro().ds().publish(junk).unwrap();
    h.process(Duration::from_secs(2));

    assert_eq!(
        h.raya().group_sync_state(&convo).unwrap(),
        SyncState::Suspect { epoch: 1 }
    );
}

#[test]
fn a_healthy_group_is_synced() {
    let mut h = TestHarness::<4>::new(|_, _| {});
    let convo = group(&mut h);
    let pax = [h.pax().account()];
    h.saro().group_add_participants(&convo, &pax).unwrap();
    h.process_until(|h| h.pax().convo_count() == 1);
    h.raya().send_content(&convo, b"hello").unwrap();
    h.process(Duration::from_secs(2));

    assert_eq!(
        h.saro().group_sync_state(&convo).unwrap(),
        SyncState::Synced
    );
    assert_eq!(
        h.raya().group_sync_state(&convo).unwrap(),
        SyncState::Synced
    );
}

#[test]
fn a_beacon_no_member_signed_changes_nothing() {
    let mut h = TestHarness::<4>::new(|_, _| {});
    let convo = group(&mut h);
    h.process(Duration::from_secs(2));
    let before = h.raya().group_sync_state(&convo).unwrap();

    let forged = group_v3_wire::unsigned_beacon(&convo, 1, "00000000000000");
    h.saro().ds().publish(forged).unwrap();
    h.process(Duration::from_secs(2));

    assert_eq!(h.raya().group_sync_state(&convo).unwrap(), before);
}
