//! GroupV2 through the threaded client: three accounts on the in-process
//! transport, driven purely over the public `ChatClient` API and its event
//! channel. Group commits and welcomes are minted asynchronously by de-mls
//! (wakeup-driven), so assertions wait for events rather than expecting a
//! fixed sequence.

use std::time::Duration;

use components::EphemeralRegistry;
use crossbeam_channel::Receiver;
use libchat::SqliteStore;
use logos_account::TestLogosAccount;
use logos_generic_chat::{
    ChatClient, ChatClientBuilder, ConversationClass, DelegateSigner, Event, GroupMetadata,
    GroupV2Config, InProcessDelivery, MessageBus,
};

/// Metadata for a group these tests create without a name or description.
fn unnamed_group() -> GroupMetadata {
    GroupMetadata::new("", "")
}

/// Millisecond GroupV2 timers so the commit/consensus dance runs in test time.
///
/// Keep `voting_delay < consensus_timeout` (the library enforces it). The fork
/// this config once caused comes down to transport delay: `freeze_duration` is
/// the window two stewards have to exchange candidates for the same add, so if
/// the transport is slower than it, each finalizes on its own candidate and the
/// group forks — dropped messages under CI load.
fn fast_group_v2_config() -> GroupV2Config {
    GroupV2Config {
        voting_delay: Duration::from_millis(50),
        consensus_timeout: Duration::from_millis(250),
        commit_batch_window: Duration::from_millis(500),
        freeze_duration: Duration::from_millis(500),
        proposal_expiration: Duration::from_millis(4000),
        ..GroupV2Config::default()
    }
}

type TestClient = ChatClient<InProcessDelivery, EphemeralRegistry, SqliteStore>;

/// A client for a fresh account: mints the account and a delegate, publishes
/// the endorsing bundle, and builds the client on the shared bus/registry with
/// the fast GroupV2 timers. Returns the account address peers invite by.
fn create_test_client(
    message_bus: MessageBus,
    reg: EphemeralRegistry,
) -> (TestClient, Receiver<Event>, String) {
    create_test_client_with(message_bus, reg, fast_group_v2_config())
}

/// [`create_test_client`] with explicit GroupV2 timers, for a test that needs
/// to observe the group between two protocol steps.
fn create_test_client_with(
    message_bus: MessageBus,
    mut reg: EphemeralRegistry,
    config: GroupV2Config,
) -> (TestClient, Receiver<Event>, String) {
    let account = TestLogosAccount::new();
    let delegate = DelegateSigner::random();
    account
        .add_delegate_signer(&mut reg, delegate.public_key())
        .unwrap();
    let (client, events) = ChatClientBuilder::new(account.address())
        .ident(delegate)
        .transport(InProcessDelivery::new(message_bus))
        .registration(reg)
        .group_v2_config(config)
        .build()
        .expect("client create");
    let addr = client.addr().to_string();
    (client, events, addr)
}

/// Wait until an event matching `f` arrives, skipping unrelated events (group
/// protocol traffic can interleave observations); panic after `timeout`.
fn wait_for_event<F, T>(events: &Receiver<Event>, label: &str, timeout: Duration, mut f: F) -> T
where
    F: FnMut(&Event) -> Option<T>,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or_else(|| panic!("timed out waiting for {label}"));
        match events.recv_timeout(remaining) {
            Ok(event) => {
                if let Some(out) = f(&event) {
                    return out;
                }
            }
            Err(_) => panic!("timed out waiting for {label}"),
        }
    }
}

/// Wait for the group conversation to start on a joiner and return its id.
fn wait_for_group_started(events: &Receiver<Event>, label: &str) -> String {
    wait_for_event(events, label, Duration::from_secs(10), |e| match e {
        Event::ConversationStarted { convo_id, class } => {
            assert_eq!(*class, ConversationClass::Group);
            Some(convo_id.to_string())
        }
        _ => None,
    })
}

/// Poll a client's roster for `convo_id` until its verified *committed*
/// accounts equal `expected` (order-independent), or panic after a timeout. The
/// roster settles asynchronously as each member applies the add commit, so it is
/// polled rather than snapshotted; members still awaiting that commit are
/// skipped so an invite alone never reads as convergence.
fn wait_for_members(client: &mut TestClient, convo_id: &str, expected: &[&str]) {
    use std::collections::BTreeSet;
    let want: BTreeSet<&str> = expected.iter().copied().collect();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let roster = client.group_members(convo_id).expect("group_members");
        let got: BTreeSet<&str> = roster
            .iter()
            .filter(|m| !m.pending)
            .filter_map(|m| m.account.as_ref().map(|a| a.as_str()))
            .collect();
        if got == want {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("roster did not converge for {convo_id}: got {got:?}, want {want:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Wait for `content` to arrive and return the sender's verified account.
fn wait_for_message(events: &Receiver<Event>, content: &[u8]) -> Option<String> {
    let label = format!("MessageReceived({})", String::from_utf8_lossy(content));
    wait_for_event(events, &label, Duration::from_secs(10), |e| match e {
        Event::MessageReceived {
            content: got,
            sender,
            ..
        } if got == content => Some(sender.account.as_ref().map(|a| a.as_str().to_string())),
        _ => None,
    })
}

/// A three-account group: saro creates it with raya, raya (a non-creator)
/// adds pax, and a message from each member reaches both others with a
/// directory-verified sender account.
#[test]
fn group_v2_three_members() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    let (mut saro, saro_events, saro_addr) = create_test_client(bus.clone(), reg.clone());
    let (mut raya, raya_events, raya_addr) = create_test_client(bus.clone(), reg.clone());
    let (mut pax, pax_events, pax_addr) = create_test_client(bus.clone(), reg.clone());

    let convo_id = saro
        .create_group_conversation(&[&raya_addr], unnamed_group())
        .expect("saro create group");

    // The invite lands once saro's steward commit finalizes (wakeup-driven);
    // both sides then share the de-mls conversation id.
    let raya_convo_id = wait_for_group_started(&raya_events, "raya ConversationStarted");
    assert_eq!(raya_convo_id, convo_id);

    // Both sides see the two-account roster once the add commits.
    wait_for_members(&mut saro, &convo_id, &[&saro_addr, &raya_addr]);
    wait_for_members(&mut raya, &raya_convo_id, &[&saro_addr, &raya_addr]);

    saro.send_message(&convo_id, b"hello raya").unwrap();
    assert_eq!(
        wait_for_message(&raya_events, b"hello raya").as_deref(),
        Some(saro_addr.as_str())
    );

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();
    assert_eq!(
        wait_for_message(&saro_events, b"hi saro").as_deref(),
        Some(raya_addr.as_str())
    );

    // A non-creator grows the group: raya proposes pax, the steward commits,
    // and raya (who holds the pending invite) routes the welcome to pax.
    raya.add_group_members(&raya_convo_id, &[&pax_addr])
        .expect("raya add pax");
    let pax_convo_id = wait_for_group_started(&pax_events, "pax ConversationStarted");
    assert_eq!(pax_convo_id, convo_id);

    // Everyone is at the post-add epoch: a message from the creator reaches
    // both peers, and one from the newest member reaches both elders.
    saro.send_message(&convo_id, b"all three?").unwrap();
    assert_eq!(
        wait_for_message(&raya_events, b"all three?").as_deref(),
        Some(saro_addr.as_str())
    );
    assert_eq!(
        wait_for_message(&pax_events, b"all three?").as_deref(),
        Some(saro_addr.as_str())
    );

    pax.send_message(&pax_convo_id, b"pax is in").unwrap();
    assert_eq!(
        wait_for_message(&saro_events, b"pax is in").as_deref(),
        Some(pax_addr.as_str())
    );
    assert_eq!(
        wait_for_message(&raya_events, b"pax is in").as_deref(),
        Some(pax_addr.as_str())
    );

    // All three rosters converge on the same three accounts.
    let all = [saro_addr.as_str(), raya_addr.as_str(), pax_addr.as_str()];
    wait_for_members(&mut saro, &convo_id, &all);
    wait_for_members(&mut raya, &raya_convo_id, &all);
    wait_for_members(&mut pax, &pax_convo_id, &all);

    assert_eq!(saro.list_conversations().unwrap().len(), 1);
    assert_eq!(raya.list_conversations().unwrap().len(), 1);
    assert_eq!(pax.list_conversations().unwrap().len(), 1);
}

/// The same two peers are invited to several groups at once. Each installation
/// registers a single key package, so admitting it to more than one group only
/// works if that key package survives a join — a regression guard for the
/// multi-group "welcome not addressed to this member" flake.
#[test]
fn peers_invited_to_many_groups() {
    const GROUPS: usize = 3;

    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    let (mut saro, _saro_events, saro_addr) = create_test_client(bus.clone(), reg.clone());
    let (_raya, raya_events, raya_addr) = create_test_client(bus.clone(), reg.clone());
    let (_pax, pax_events, pax_addr) = create_test_client(bus.clone(), reg.clone());

    // Saro opens several groups, each inviting both Raya and Pax; every group
    // reuses Raya's and Pax's one key package.
    let mut convo_ids = Vec::new();
    for _ in 0..GROUPS {
        convo_ids.push(
            saro.create_group_conversation(&[&raya_addr, &pax_addr], unnamed_group())
                .expect("saro create group"),
        );
    }

    // Both peers must join all of them.
    for _ in 0..GROUPS {
        wait_for_group_started(&raya_events, "raya joins a group");
        wait_for_group_started(&pax_events, "pax joins a group");
    }

    // Every group is live: a distinct message in each reaches both peers with
    // the creator's verified account.
    for (i, convo_id) in convo_ids.iter().enumerate() {
        let msg = format!("hello group {i}").into_bytes();
        saro.send_message(convo_id, &msg).unwrap();
        assert_eq!(
            wait_for_message(&raya_events, &msg).as_deref(),
            Some(saro_addr.as_str())
        );
        assert_eq!(
            wait_for_message(&pax_events, &msg).as_deref(),
            Some(saro_addr.as_str())
        );
    }

    assert_eq!(saro.list_conversations().unwrap().len(), GROUPS);
}

/// The creator is in its own roster from the start, with no other members: the
/// roster always includes self.
#[test]
fn group_creator_is_in_own_roster() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    let (mut saro, _saro_events, saro_addr) = create_test_client(bus.clone(), reg.clone());

    let convo_id = saro
        .create_group_conversation(&[], unnamed_group())
        .expect("empty group");
    let roster = saro.group_members(&convo_id).expect("group_members");
    let accounts: Vec<Option<&str>> = roster
        .iter()
        .map(|m| m.account.as_ref().map(|a| a.as_str()))
        .collect();
    assert_eq!(accounts, vec![Some(saro_addr.as_str())]);
}

/// An invited member joins the roster immediately, flagged pending: the add is
/// staged as a proposal, so the invitee is not a member until the group commits.
#[test]
fn invited_member_is_pending_until_the_group_commits() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    // A commit window far longer than the assertions below, so the add provably
    // cannot merge while they run.
    let deferred_commit = GroupV2Config {
        commit_batch_window: Duration::from_secs(30),
        ..fast_group_v2_config()
    };
    let (mut saro, _saro_events, saro_addr) =
        create_test_client_with(bus.clone(), reg.clone(), deferred_commit);
    let (_raya, _raya_events, raya_addr) = create_test_client(bus.clone(), reg.clone());

    let convo_id = saro
        .create_group_conversation(&[], unnamed_group())
        .expect("empty group");
    saro.add_group_members(&convo_id, &[&raya_addr])
        .expect("saro invites raya");

    let roster = saro.group_members(&convo_id).expect("group_members");
    let accounts = |pending: bool| -> Vec<&str> {
        roster
            .iter()
            .filter(|m| m.pending == pending)
            .filter_map(|m| m.account.as_ref().map(|a| a.as_str()))
            .collect()
    };
    assert_eq!(accounts(false), vec![saro_addr.as_str()]);
    assert_eq!(accounts(true), vec![raya_addr.as_str()]);
}

/// The pending flag is transient: once the group commits the add, the invitee
/// is an ordinary roster member and nothing is left pending. The joiner, which
/// invited nobody, never reports a pending member at all: the flag is local to
/// the client that sent the invite.
#[test]
fn pending_clears_once_the_add_commits() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    let (mut saro, _saro_events, saro_addr) = create_test_client(bus.clone(), reg.clone());
    let (mut raya, raya_events, raya_addr) = create_test_client(bus.clone(), reg.clone());

    let convo_id = saro
        .create_group_conversation(&[], unnamed_group())
        .expect("empty group");
    saro.add_group_members(&convo_id, &[&raya_addr])
        .expect("saro invites raya");

    let raya_convo_id = wait_for_group_started(&raya_events, "raya ConversationStarted");
    wait_for_members(&mut saro, &convo_id, &[&saro_addr, &raya_addr]);

    let roster = saro.group_members(&convo_id).expect("group_members");
    assert!(
        roster.iter().all(|m| !m.pending),
        "committed roster still reports a pending member: {roster:?}"
    );

    let joiner_roster = raya
        .group_members(&raya_convo_id)
        .expect("joiner group_members");
    assert!(
        joiner_roster.iter().all(|m| !m.pending),
        "joiner reports a pending member it never invited: {joiner_roster:?}"
    );
}

/// A batch add is validated before any member is proposed: a member whose
/// account is endorsed in the directory but whose device registered no key
/// package fails the whole call, the resolvable member in the same batch is
/// not invited, and the group keeps working.
#[test]
fn add_batch_with_missing_key_package_invites_no_one() {
    let bus = MessageBus::default();
    let mut reg = EphemeralRegistry::new();

    let (mut saro, _saro_events, _saro_addr) = create_test_client(bus.clone(), reg.clone());
    let (_raya, raya_events, raya_addr) = create_test_client(bus.clone(), reg.clone());
    let (_pax, pax_events, pax_addr) = create_test_client(bus.clone(), reg.clone());

    // Ghost: its account endorses a device in the directory, but that device
    // never registered a key package (no client was built for it).
    let ghost_account = TestLogosAccount::new();
    let ghost_delegate = DelegateSigner::random();
    ghost_account
        .add_delegate_signer(&mut reg, ghost_delegate.public_key())
        .unwrap();

    let convo_id = saro
        .create_group_conversation(&[&raya_addr], unnamed_group())
        .expect("saro create group");
    wait_for_group_started(&raya_events, "raya ConversationStarted");

    saro.add_group_members(&convo_id, &[&ghost_account.address(), &pax_addr])
        .expect_err("ghost has no key package");

    // Pax was in the failed batch and must not have been invited.
    assert!(
        pax_events.recv_timeout(Duration::from_secs(1)).is_err(),
        "pax must not join from a failed batch"
    );

    // The failed add left the group functional.
    saro.send_message(&convo_id, b"still alive").unwrap();
    wait_for_message(&raya_events, b"still alive");
}

/// Group membership is resolved through the account directory, so inviting an
/// address whose account never published a bundle fails at resolution — on
/// create and on add alike.
#[test]
fn group_invite_of_unpublished_account_is_an_error() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    let (mut saro, _saro_events, _saro_addr) = create_test_client(bus.clone(), reg.clone());
    let unpublished = TestLogosAccount::new();

    let err = saro
        .create_group_conversation(&[&unpublished.address()], unnamed_group())
        .expect_err("no bundle published for the account");
    assert!(matches!(
        err,
        logos_generic_chat::ClientError::AccountResolution(_)
    ));

    let convo_id = saro
        .create_group_conversation(&[], unnamed_group())
        .expect("empty group");
    let err = saro
        .add_group_members(&convo_id, &[&unpublished.address()])
        .expect_err("no bundle published for the account");
    assert!(matches!(
        err,
        logos_generic_chat::ClientError::AccountResolution(_)
    ));
}

/// A group's name and description are set at creation and reach every joiner in
/// the welcome: the creator reads them back, and a joiner reads the same values
/// once its conversation starts.
#[test]
fn group_metadata_reaches_joiners() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    let (mut saro, _saro_events, _saro_addr) = create_test_client(bus.clone(), reg.clone());
    let (raya, raya_events, raya_addr) = create_test_client(bus.clone(), reg.clone());

    let convo_id = saro
        .create_group_conversation(
            &[&raya_addr],
            GroupMetadata::new("Book Club", "Weekly reads"),
        )
        .expect("saro create group");

    let meta = saro.group_metadata(&convo_id).expect("creator metadata");
    assert_eq!(meta.name, "Book Club");
    assert_eq!(meta.desc, "Weekly reads");

    let raya_convo_id = wait_for_group_started(&raya_events, "raya ConversationStarted");
    let meta = raya
        .group_metadata(&raya_convo_id)
        .expect("joiner metadata");
    assert_eq!(meta.name, "Book Club");
    assert_eq!(meta.desc, "Weekly reads");
}

/// A group created without a name or description reports empty metadata rather
/// than failing: both fields are optional.
#[test]
fn group_metadata_defaults_to_empty() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    let (mut saro, _saro_events, _saro_addr) = create_test_client(bus.clone(), reg.clone());

    let convo_id = saro
        .create_group_conversation(&[], unnamed_group())
        .expect("empty group");
    let meta = saro.group_metadata(&convo_id).expect("creator metadata");
    assert_eq!(meta.name, "");
    assert_eq!(meta.desc, "");
}

/// The peers that hold a sent message surface as `MessageAcked` events keyed by
/// the id the send returned — what an application needs to list the peers that
/// hold a message. The acknowledgement is passive: Raya and Pax only send
/// ordinary replies, never a receipt.
#[test]
fn a_sent_message_is_acknowledged_by_the_peers_that_reply() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    let (mut saro, saro_events, saro_addr) = create_test_client(bus.clone(), reg.clone());
    let (mut raya, raya_events, raya_addr) = create_test_client(bus.clone(), reg.clone());
    let (mut pax, pax_events, pax_addr) = create_test_client(bus.clone(), reg.clone());

    let convo_id = saro
        .create_group_conversation(&[&raya_addr, &pax_addr], unnamed_group())
        .expect("saro create group");
    wait_for_group_started(&raya_events, "raya ConversationStarted");
    wait_for_group_started(&pax_events, "pax ConversationStarted");
    wait_for_members(&mut saro, &convo_id, &[&saro_addr, &raya_addr, &pax_addr]);

    let message_id = saro
        .send_message(&convo_id, b"anyone there?")
        .expect("saro send");
    wait_for_message(&raya_events, b"anyone there?");
    wait_for_message(&pax_events, b"anyone there?");

    // Ordinary replies; their causal history carries the acknowledgement.
    raya.send_message(&convo_id, b"raya here")
        .expect("raya reply");
    pax.send_message(&convo_id, b"pax here").expect("pax reply");

    let mut holders = Vec::new();
    while holders.len() < 2 {
        let peer = wait_for_event(
            &saro_events,
            "saro MessageAcked",
            Duration::from_secs(10),
            |e| match e {
                Event::MessageAcked {
                    convo_id: id,
                    message_id: acked,
                    acked_by,
                } if **id == *convo_id && *acked == message_id => Some(
                    acked_by
                        .as_ref()
                        .and_then(|a| a.account.as_ref())
                        .map(|a| a.as_str().to_string()),
                ),
                _ => None,
            },
        );
        holders.push(peer.expect("the acknowledging peer's account should be directory-verified"));
    }
    holders.sort();

    let mut expected = vec![raya_addr.clone(), pax_addr.clone()];
    expected.sort();
    assert_eq!(holders, expected, "both replying peers should be listed");
}
