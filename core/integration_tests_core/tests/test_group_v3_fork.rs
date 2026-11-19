use std::time::Duration;

use integration_tests_core::TestHarness;
use libchat::test_support::group_v3_wire;
use libchat::{DebugData, SyncState};

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

/// `member`'s entry in `viewer`'s debug data.
fn member_state(h: &mut TestHarness<4>, viewer: usize, convo: &str, member: usize) -> DebugData {
    let signer = h.client(member).signer_key().to_string();
    let data = h.client(viewer).debug_data(convo).unwrap();
    let members = data["members"].as_array().expect("a list of members");
    members
        .iter()
        .filter_map(|state| state.as_object())
        .find(|state| state["signer"] == signer.as_str())
        .expect("a member")
        .clone()
}

/// How `viewer` sees `member`'s group state.
fn sync_of(h: &mut TestHarness<4>, viewer: usize, convo: &str, member: usize) -> String {
    let state = member_state(h, viewer, convo, member);
    state["sync"].as_str().expect("a sync name").to_owned()
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
    let before = h.saro().debug_data(&convo).unwrap();
    assert!(before.contains_key("epoch_fingerprint"));
    let raya = h.raya().debug_data(&convo).unwrap();
    assert_eq!(raya["epoch_fingerprint"], before["epoch_fingerprint"]);

    fork(&mut h, &convo, nothing);

    let saro = h.saro().debug_data(&convo).unwrap();
    let raya = h.raya().debug_data(&convo).unwrap();
    assert_eq!(saro["epoch"], 2);
    assert_eq!(raya["epoch"], 2);
    assert_ne!(saro["epoch_fingerprint"], raya["epoch_fingerprint"]);
    let pax = h.pax().debug_data(&convo).unwrap();
    assert_eq!(pax["epoch_fingerprint"], saro["epoch_fingerprint"]);
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

/// Raya learns Saro's state from the header of Saro's first message.
#[test]
fn a_member_is_confirmed_by_a_message() {
    let (mut h, convo) = group_of_saro_and_raya();
    assert_eq!(sync_of(&mut h, RAYA, &convo, SARO), "unconfirmed");

    h.saro().send_content(&convo, b"hello raya").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"hello raya"));

    assert_eq!(sync_of(&mut h, RAYA, &convo, SARO), "synced");
    assert_eq!(sync_of(&mut h, RAYA, &convo, RAYA), "synced");
    let saro = h.saro().debug_data(&convo).unwrap();
    let heard = member_state(&mut h, RAYA, &convo, SARO);
    assert_eq!(heard["epoch"], saro["epoch"]);
    assert_eq!(heard["epoch_fingerprint"], saro["epoch_fingerprint"]);
}

#[test]
fn each_side_of_a_fork_sees_the_other_forked() {
    let (mut h, convo) = group_of_saro_and_raya();
    fork(&mut h, &convo, nothing);
    h.saro().send_content(&convo, b"from saro").unwrap();
    h.raya().send_content(&convo, b"from raya").unwrap();
    h.pax().send_content(&convo, b"from pax").unwrap();
    h.process_until(|h| h.saro().check(&convo, b"from pax") && h.pax().check(&convo, b"from saro"));

    assert_eq!(sync_of(&mut h, SARO, &convo, RAYA), "forked");
    assert_eq!(sync_of(&mut h, SARO, &convo, PAX), "synced");
    assert_eq!(sync_of(&mut h, RAYA, &convo, SARO), "forked");
    assert_eq!(sync_of(&mut h, RAYA, &convo, PAX), "forked");
}

/// Saro's commit adding Pax never reaches Raya, so Saro is a state ahead.
#[test]
fn a_member_who_missed_a_commit_is_behind() {
    let (mut h, convo) = group_of_saro_and_raya();
    h.saro().send_content(&convo, b"at one").unwrap();
    h.process_until(|h| h.raya().check(&convo, b"at one"));
    h.raya().send_content(&convo, b"raya at one").unwrap();
    h.process_until(|h| h.saro().check(&convo, b"raya at one"));

    h.client_mut(SARO)
        .ds()
        .reject_publishes(|e| group_v3_wire::is_commit(&e.data));
    let pax = [h.pax().account()];
    h.saro().group_add_participants(&convo, &pax).unwrap();
    settle(&mut h);
    h.saro().send_content(&convo, b"at two").unwrap();
    settle(&mut h);

    assert_eq!(sync_of(&mut h, SARO, &convo, RAYA), "behind");
    assert_eq!(sync_of(&mut h, RAYA, &convo, SARO), "ahead");
}

/// Raya has merged no commit since joining. Raya's first message still tells
/// Saro Raya's state.
#[test]
fn a_joiners_first_message_confirms_it() {
    let (mut h, convo) = group_of_saro_and_raya();
    h.raya().send_content(&convo, b"just joined").unwrap();
    h.process_until(|h| h.saro().check(&convo, b"just joined"));

    assert_eq!(sync_of(&mut h, SARO, &convo, RAYA), "synced");
}
