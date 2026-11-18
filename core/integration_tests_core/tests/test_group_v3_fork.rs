use std::time::Duration;

use integration_tests_core::TestHarness;
use libchat::test_support::group_v3_wire;
use libchat::{MemberSync, SyncState};

const SARO: usize = 0;
const RAYA: usize = 1;
const PAX: usize = 2;

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

/// How `viewer` sees `member`'s group state.
fn sync_of(h: &mut TestHarness<4>, viewer: usize, convo: &str, member: usize) -> MemberSync {
    let signer = h.client(member).signer_key();
    h.client(viewer)
        .group_member_states(convo)
        .unwrap()
        .into_iter()
        .find(|state| state.signer == signer)
        .expect("a member")
        .sync
}

#[test]
fn both_sides_of_a_fork_see_it() {
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo, nothing);

    let forked = SyncState::Forked { at_or_before: 2 };
    assert_eq!(h.saro().group_sync_state(&convo).unwrap(), forked);
    assert_eq!(h.raya().group_sync_state(&convo).unwrap(), forked);
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
    let before = h.saro().group_epoch(&convo).unwrap().unwrap();
    assert_eq!(h.raya().group_epoch(&convo).unwrap(), Some(before));

    fork(&mut h, &convo, nothing);

    let saro = h.saro().group_epoch(&convo).unwrap().unwrap();
    let raya = h.raya().group_epoch(&convo).unwrap().unwrap();
    assert_eq!((saro.epoch, raya.epoch), (2, 2));
    assert_ne!(saro.fingerprint, raya.fingerprint);
    assert_eq!(h.pax().group_epoch(&convo).unwrap(), Some(saro));
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

/// Raya's beacon on joining tells Saro her state. Saro's went out before Raya
/// joined, so Raya learns Saro's from the header of his first message.
#[test]
fn a_member_is_confirmed_by_a_beacon_or_a_message() {
    let (mut h, convo) = group_of_saro_and_raya();
    h.process_until(|h| sync_of(h, SARO, &convo, RAYA) == MemberSync::Synced);
    assert_eq!(sync_of(&mut h, RAYA, &convo, SARO), MemberSync::Unconfirmed);

    h.saro().send_content(&convo, b"hello raya").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"hello raya"));

    assert_eq!(sync_of(&mut h, RAYA, &convo, SARO), MemberSync::Synced);
    assert_eq!(sync_of(&mut h, RAYA, &convo, RAYA), MemberSync::Synced);
    let saro_signer = h.client(SARO).signer_key();
    let saro = h.saro().group_epoch(&convo).unwrap();
    let heard = h
        .raya()
        .group_member_states(&convo)
        .unwrap()
        .into_iter()
        .find(|state| state.signer == saro_signer)
        .and_then(|state| state.heard);
    assert_eq!(heard, saro);
}

#[test]
fn each_side_of_a_fork_sees_the_other_forked() {
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo, nothing);

    assert_eq!(sync_of(&mut h, SARO, &convo, RAYA), MemberSync::Forked);
    assert_eq!(sync_of(&mut h, SARO, &convo, PAX), MemberSync::Synced);
    assert_eq!(sync_of(&mut h, RAYA, &convo, SARO), MemberSync::Forked);
    assert_eq!(sync_of(&mut h, RAYA, &convo, PAX), MemberSync::Forked);
}

/// Saro's commit adding Pax never reaches Raya: he is a state ahead of her.
#[test]
fn a_member_who_missed_a_commit_is_behind() {
    let (mut h, convo) = group_of_saro_and_raya();
    h.saro().send_content(&convo, b"at one").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"at one"));

    h.client_mut(SARO)
        .ds()
        .reject_publishes(|e| group_v3_wire::is_commit(&e.data));
    let pax = [h.pax().account()];
    h.saro().group_add_participants(&convo, &pax).unwrap();
    settle(&mut h);

    assert_eq!(sync_of(&mut h, SARO, &convo, RAYA), MemberSync::Behind);
    assert_eq!(sync_of(&mut h, RAYA, &convo, SARO), MemberSync::Ahead);
}

/// With every beacon dropped, a message's header alone confirms its sender.
#[test]
fn a_header_alone_confirms_its_sender() {
    let mut h = TestHarness::<4>::new(|_, _| {});
    for i in 0..4 {
        h.client_mut(i)
            .ds()
            .reject_publishes(|e| group_v3_wire::is_beacon(&e.data));
    }
    let raya = [h.raya().account()];
    let convo = h.saro().create_group_convo_v3(&raya, "", "").unwrap();
    h.process_until(|h| h.raya().convo_count() == 1);
    assert_eq!(sync_of(&mut h, SARO, &convo, RAYA), MemberSync::Unconfirmed);

    h.saro().send_content(&convo, b"no beacons").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"no beacons"));

    assert_eq!(sync_of(&mut h, RAYA, &convo, SARO), MemberSync::Synced);
}
