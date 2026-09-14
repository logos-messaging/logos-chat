use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use arboard::Clipboard;
use crossbeam_channel::Receiver;
use logos_chat::{
    AccountDirectory, ChatClient, ConversationClass, ConversationStore, Event, GroupMetadata,
    RegistrationService, Transport,
};
use serde::{Deserialize, Serialize};

use crate::utils::now;

/// Render a decoded content body for display. Markdown is tagged so it's visibly
/// distinct; unknown types show a placeholder.
fn render_content(content: &message_types::MessageContent) -> String {
    use message_types::MessageContent::{Markdown, Text, Unsupported};
    match content {
        Text(s) => s.clone(),
        Markdown(s) => format!("[md] {s}"),
        Unsupported { content_type } => format!("[unsupported: {content_type}]"),
    }
}

/// A short one-line snippet of a stored message body, for "replying to …" previews.
fn snippet_of(body: &str) -> String {
    let line = body.lines().next().unwrap_or("");
    let short: String = line.chars().take(24).collect();
    if line.chars().count() > 24 {
        format!("{short}…")
    } else {
        short
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayMessage {
    pub from_self: bool,
    pub content: String,
    pub timestamp: u64,
    pub message_id: Option<String>,
    #[serde(default)]
    pub delivered_to: Vec<String>,
    /// Who this message is attributed to: our own account vs. a peer (by account
    /// address). The display name is resolved from the account at render time.
    pub origin: MessageOrigin,
}

impl DisplayMessage {
    fn new(from_self: bool, content: String, origin: MessageOrigin) -> Self {
        Self {
            from_self,
            content,
            timestamp: now(),
            message_id: None,
            delivered_to: Vec::new(),
            origin,
        }
    }
}

/// Attribution of a displayed message. `Own` is our own account (any of our
/// devices); `Foreign` carries the sender's resolved account address, which the
/// app maps to a display name. (Client resolves credential → account; the app
/// resolves account → name.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageOrigin {
    Own,
    Foreign(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSession {
    pub chat_id: String,
    pub nickname: Option<String>,
    pub kind: ConversationClass,
    pub messages: Vec<DisplayMessage>,
}

impl ChatSession {
    /// Human-readable label: nickname if set, otherwise the first 8 chars of the chat ID.
    pub fn display_name(&self) -> &str {
        self.nickname
            .as_deref()
            .unwrap_or_else(|| &self.chat_id[..8.min(self.chat_id.len())])
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AppState {
    /// Keyed by chat_id (conversation ID).
    pub chats: HashMap<String, ChatSession>,
    /// Holds the active chat_id.
    pub active_chat: Option<String>,
}

pub struct ChatApp<T, R, S>
where
    T: Transport,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    pub client: ChatClient<T, R, S>,
    events: Receiver<Event>,
    pub state: AppState,
    /// Whether the active chat can accept outbound content this session. Mirrors
    /// [`ChatClient::can_send`] for the active chat; `false` for a chat
    /// restored from a previous session that the MLS client can't reload yet.
    is_active: bool,
    /// Ephemeral command output — not persisted, cleared on chat switch.
    command_output: Vec<DisplayMessage>,
    pub input: String,
    pub status: String,
    pub user_name: String,
    state_path: PathBuf,
}

impl<T, R, S> ChatApp<T, R, S>
where
    T: Transport,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: ConversationStore + Send,
{
    pub fn new(
        client: ChatClient<T, R, S>,
        events: Receiver<Event>,
        user_name: &str,
        data_dir: &Path,
    ) -> Result<Self> {
        fs::create_dir_all(data_dir)?;

        let state_path = data_dir.join(format!("{user_name}_state.json"));
        let state = Self::load_state(&state_path);

        let chat_count = state.chats.len();
        let status = if chat_count == 0 {
            format!("Welcome, {user_name}! Type /help for commands.")
        } else {
            format!(
                "Welcome back, {user_name}! {chat_count} chat(s) loaded — read-only from a previous \
                 session; start a new /dm or /new to chat. Type /help."
            )
        };

        let mut app = Self {
            client,
            events,
            state,
            is_active: false,
            command_output: Vec::new(),
            input: String::new(),
            status,
            user_name: user_name.to_string(),
            state_path,
        };
        // Restored chats can't be reloaded into the MLS client yet, so open on the
        // roster (with read-only flags) rather than a dead active chat.
        app.state.active_chat = None;
        app.show_chats_list();
        Ok(app)
    }

    fn load_state(path: &Path) -> AppState {
        if path.exists()
            && let Ok(contents) = fs::read_to_string(path)
            && let Ok(state) = serde_json::from_str(&contents)
        {
            return state;
        }
        AppState::default()
    }

    fn save_state(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.state)?;
        fs::write(&self.state_path, json)?;
        Ok(())
    }

    pub fn current_session(&self) -> Option<&ChatSession> {
        self.state
            .active_chat
            .as_ref()
            .and_then(|name| self.state.chats.get(name))
    }

    pub fn messages(&self) -> Vec<&DisplayMessage> {
        let chat = self
            .current_session()
            .map(|s| s.messages.as_slice())
            .unwrap_or(&[]);
        chat.iter().chain(self.command_output.iter()).collect()
    }

    fn set_active_chat(&mut self, chat_id: Option<String>) {
        self.is_active = chat_id
            .as_deref()
            .map(|id| self.client.can_send(id))
            .unwrap_or(false);
        self.state.active_chat = chat_id;
        self.command_output.clear();
    }

    /// Whether the active chat can accept outbound content this session.
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    /// Render the chat list; chats restored from a previous session that the MLS
    /// client can't reload are flagged read-only.
    fn show_chats_list(&mut self) {
        self.command_output.clear();
        let sessions: Vec<_> = self.state.chats.values().cloned().collect();
        if sessions.is_empty() {
            self.add_system_message("No chats yet. Use /dm or /new to start one.");
            return;
        }
        self.add_system_message(&format!("── Your Chats ({}) ──", sessions.len()));
        for s in &sessions {
            let active = self.state.active_chat.as_deref() == Some(&s.chat_id);
            let read_only = !self.client.can_send(&s.chat_id);
            let mut tags = String::new();
            if active {
                tags.push_str(" (active)");
            }
            if read_only {
                tags.push_str(" (read-only)");
            }
            let label = format!(
                "  • [{:?}] {} ({}){tags}",
                s.kind,
                s.display_name(),
                &s.chat_id[..8.min(s.chat_id.len())]
            );
            self.add_system_message(&label);
        }
    }

    /// Insert a freshly created conversation and make it active.
    fn start_session(
        &mut self,
        chat_id: String,
        kind: ConversationClass,
        nickname: Option<String>,
    ) {
        self.state.chats.insert(
            chat_id.clone(),
            ChatSession {
                chat_id: chat_id.clone(),
                nickname,
                kind,
                messages: Vec::new(),
            },
        );
        self.set_active_chat(Some(chat_id));
    }

    /// Find a chat_id by nickname (exact) or chat_id prefix.
    fn resolve_chat_id(&self, query: &str) -> Option<&str> {
        // Exact nickname match first.
        if let Some((id, _)) = self
            .state
            .chats
            .iter()
            .find(|(_, s)| s.nickname.as_deref() == Some(query))
        {
            return Some(id.as_str());
        }
        // Fall back to chat_id prefix.
        self.state
            .chats
            .keys()
            .find(|id| id.starts_with(query))
            .map(String::as_str)
    }

    pub fn process_incoming(&mut self) -> Result<()> {
        let mut received = false;
        while let Ok(event) = self.events.try_recv() {
            self.handle_event(event);
            received = true;
        }
        if received {
            self.save_state()?;
        }
        Ok(())
    }

    fn handle_event(&mut self, event: Event) {
        match event {
            Event::ConversationStarted { convo_id, class } => {
                let chat_id = convo_id.to_string();
                if self.state.chats.contains_key(&chat_id) {
                    return;
                }
                let label = chat_id[..8.min(chat_id.len())].to_string();
                self.status = format!("New {class:?} ({label})! Use /nickname to name it.");
                self.start_session(chat_id, class, None);
            }
            Event::MessageReceived {
                convo_id,
                content,
                sender,
                message_id,
            } => {
                let chat_id = convo_id.to_string();
                // The client resolved the credential to an account; classify by it.
                let origin = match sender.account.as_ref().map(|a| a.as_str()) {
                    Some(account) if account == self.client.addr() => MessageOrigin::Own,
                    Some(account) => MessageOrigin::Foreign(account.to_string()),
                    // Unassociated device — no account claim; fall back to its signer id.
                    None => MessageOrigin::Foreign(sender.local_identity.as_str().to_string()),
                };
                // Decode the content-type body; if it's a reply, prefix a short
                // preview of the referenced message (resolved via its stored id).
                let (mut body, in_reply_to) = match message_types::decode(&content) {
                    Ok(msg) => (render_content(&msg.content), msg.in_reply_to),
                    Err(_) => (String::from_utf8_lossy(&content).into_owned(), None),
                };
                let Some(session) = self.state.chats.get_mut(&chat_id) else {
                    return;
                };
                if let Some(target) = in_reply_to {
                    let preview = session
                        .messages
                        .iter()
                        .find(|m| m.message_id.as_deref() == Some(&target))
                        .map(|m| snippet_of(&m.content))
                        .unwrap_or_else(|| format!("re: {}", &target[..8.min(target.len())]));
                    body = format!("↩ {preview}\n{body}");
                }
                let mut message = DisplayMessage::new(false, body, origin);
                message.message_id = Some(message_id);
                session.messages.push(message);
            }
            Event::MessageAcked {
                convo_id,
                message_id,
                acked_by,
            } => {
                let Some(session) = self.state.chats.get_mut(convo_id.as_ref()) else {
                    return;
                };
                let Some(message) = session
                    .messages
                    .iter_mut()
                    .find(|m| m.message_id.as_deref() == Some(message_id.as_str()))
                else {
                    return; // sent before this session, or not ours
                };
                let peer = acked_by.map_or_else(
                    || "a member".to_string(),
                    |s| {
                        let id = s.account.unwrap_or(s.local_identity);
                        format!("{}…", &id.as_str()[..8.min(id.as_str().len())])
                    },
                );
                if !message.delivered_to.contains(&peer) {
                    message.delivered_to.push(peer);
                }
            }
            Event::MessageMissing {
                convo_id,
                sender_hint,
                ..
            } => {
                let Some(session) = self.state.chats.get(convo_id.as_ref()) else {
                    return;
                };
                // The hint is not authenticated (see `Event::MessageMissing`),
                // so name the author loosely rather than as an established fact.
                let author = sender_hint.map_or_else(
                    || "a member".to_string(),
                    |s| {
                        let id = s.account.unwrap_or(s.local_identity);
                        format!("{}…", &id.as_str()[..8.min(id.as_str().len())])
                    },
                );
                self.status = format!(
                    "A message from {author} never arrived in '{}'.",
                    session.display_name()
                );
            }
            Event::ConversationMembersChanged { convo_id } => {
                let chat_id = convo_id.to_string();
                if let Some(session) = self.state.chats.get(&chat_id) {
                    self.status = format!("Membership changed in {}.", session.display_name());
                }
            }
            Event::InboundError { message } => {
                self.status = format!("Could not process incoming message: {message}");
            }
            _ => {}
        }
    }

    /// Send a plain-text (`text/plain`) message.
    pub fn send_message(&mut self, content: &str) -> Result<()> {
        let encoded = message_types::encode_text(content).map_err(|e| anyhow::anyhow!("{e}"))?;
        self.send_encoded(encoded, content.to_string())
    }

    /// Send a Markdown (`text/markdown`) message.
    fn send_markdown(&mut self, content: &str) -> Result<()> {
        let encoded =
            message_types::encode_markdown(content).map_err(|e| anyhow::anyhow!("{e}"))?;
        self.send_encoded(encoded, format!("[md] {content}"))
    }

    /// Send already-encoded content bytes and echo a local copy in our view.
    fn send_encoded(&mut self, encoded: Vec<u8>, echo: String) -> Result<()> {
        let chat_id = self
            .state
            .active_chat
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No active chat. Use /dm or /new first."))?;

        if !self.is_active {
            anyhow::bail!(
                "This conversation is from a previous session and can't receive messages yet \
                 — chats don't persist across restart. Start a new one with /dm or /new."
            );
        }

        let message_id = self
            .client
            .send_message(&chat_id, &encoded)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;

        if let Some(session) = self.state.chats.get_mut(&chat_id) {
            let mut message = DisplayMessage::new(true, echo, MessageOrigin::Own);
            // Kept so `MessageAcked` can find this message again.
            message.message_id = Some(message_id);
            session.messages.push(message);
        }
        self.save_state()?;

        Ok(())
    }

    fn add_system_message(&mut self, content: &str) {
        self.command_output.push(DisplayMessage::new(
            true,
            content.to_string(),
            MessageOrigin::Own,
        ));
    }

    pub fn handle_command(&mut self, cmd: &str) -> Result<Option<String>> {
        let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
        let command = parts[0];
        let args = parts.get(1).copied().unwrap_or("");

        match command {
            "/help" => {
                self.add_system_message("── Commands ──");
                self.add_system_message("/account - Show your account address");
                self.add_system_message("/dm <address> - Start a direct (1:1) chat");
                self.add_system_message("/new <name> [address...] - Create a group chat");
                self.add_system_message("/add <address> - Add someone to the active group");
                self.add_system_message("/members - List members of the active conversation");
                self.add_system_message("/md <text> - Send a Markdown message");
                self.add_system_message("/reply <text> - Reply to the latest message");
                self.add_system_message("/nickname <name> - Name the active chat");
                self.add_system_message("/chats - List all chats");
                self.add_system_message("/switch <name|id> - Switch active chat");
                self.add_system_message("/delete <name|id> - Delete a chat");
                self.add_system_message("/status - Show connection status");
                self.add_system_message("/clear - Clear current chat messages");
                self.add_system_message("/quit or Esc or Ctrl+C - Exit");
                Ok(Some("Help displayed".to_string()))
            }
            "/account" => {
                let address = self.client.addr().to_string();
                self.add_system_message("── Your Account Address ──");
                self.add_system_message(&address);
                let clipboard_msg = match Clipboard::new().and_then(|mut cb| cb.set_text(&address))
                {
                    Ok(()) => "Address copied to clipboard. Share it so others can reach you.",
                    Err(_) => "Share this address so others can reach you.",
                };
                self.add_system_message(clipboard_msg);
                Ok(Some("Account address shown".to_string()))
            }
            "/dm" => {
                let address = args.trim();
                if address.is_empty() {
                    return Ok(Some("Usage: /dm <address>".to_string()));
                }
                let chat_id = self
                    .client
                    .create_direct_conversation(address)
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                let label = chat_id[..8.min(chat_id.len())].to_string();
                self.start_session(chat_id, ConversationClass::Dm, None);
                self.save_state()?;
                self.status = format!("Direct chat started ({label}). Say hello!");
                Ok(Some(format!("DM started ({label})")))
            }
            "/new" => {
                // First token is the group name (required); any remaining tokens
                // are addresses to invite at creation.
                let mut tokens = args.split_whitespace();
                let Some(name) = tokens.next().map(str::to_string) else {
                    return Ok(Some("Usage: /new <name> [address...]".to_string()));
                };
                // The creator is already a member; drop self and any repeats so we
                // don't propose a duplicate signature key (which MLS rejects).
                let my_addr = self.client.addr().to_string();
                let mut members: Vec<&str> = tokens.filter(|a| *a != my_addr).collect();
                members.sort_unstable();
                members.dedup();
                let chat_id = self
                    .client
                    .create_group_conversation(&members, GroupMetadata::new(name.clone(), ""))
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                let label = chat_id[..8.min(chat_id.len())].to_string();
                self.start_session(chat_id, ConversationClass::Group, Some(name));
                self.save_state()?;
                let msg = if members.is_empty() {
                    format!("Group created ({label}).")
                } else {
                    format!(
                        "Group created ({label}); {} invite(s) pending.",
                        members.len()
                    )
                };
                self.status = msg.clone();
                Ok(Some(msg))
            }
            "/add" => {
                let address = args.trim();
                if address.is_empty() {
                    return Ok(Some("Usage: /add <address>".to_string()));
                }
                let chat_id = self.state.active_chat.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("No active conversation. Use /new to create a group.")
                })?;
                // DMs are 1:1 and reject adds at the protocol level; refuse early
                // with a friendly hint rather than surfacing UnsupportedFunction.
                if self.state.chats.get(chat_id).map(|s| s.kind) == Some(ConversationClass::Dm) {
                    return Ok(Some(
                        "DMs are 1:1 — start a group with /new to add people.".to_string(),
                    ));
                }
                // Adding a signature key already in the group (yourself, or a
                // member/pending invite) makes MLS reject the commit with
                // DuplicateSignatureKey. Catch it here as a friendly no-op.
                if address == self.client.addr() {
                    return Ok(Some(
                        "That's your own address — you're already in the group.".to_string(),
                    ));
                }
                let already_present = self
                    .client
                    .group_members(chat_id)
                    .map(|members| {
                        members
                            .iter()
                            .any(|m| m.account.as_ref().map(|a| a.as_str()) == Some(address))
                    })
                    .unwrap_or(false);
                if already_present {
                    return Ok(Some(
                        "That account is already in the group (or its invite is pending)."
                            .to_string(),
                    ));
                }
                self.client
                    .add_group_members(chat_id, &[address])
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                self.status = "Invite pending — the group will commit it shortly.".to_string();
                Ok(Some("Invite pending".to_string()))
            }
            "/members" => {
                let chat_id = self
                    .state
                    .active_chat
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("No active conversation."))?;
                let members = self
                    .client
                    .group_members(&chat_id)
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                let my_addr = self.client.addr().to_string();
                self.add_system_message(&format!("── Members ({}) ──", members.len()));
                for m in &members {
                    let id = m
                        .account
                        .as_ref()
                        .map(|a| a.as_str())
                        .unwrap_or_else(|| m.local_identity.as_str());
                    let short = &id[..16.min(id.len())];
                    let mut tags = String::new();
                    if m.account.as_ref().map(|a| a.as_str()) == Some(my_addr.as_str()) {
                        tags.push_str(" (you)");
                    }
                    if m.pending {
                        tags.push_str(" (pending)");
                    }
                    self.add_system_message(&format!("  • {short}…{tags}"));
                }
                Ok(Some(format!("{} member(s)", members.len())))
            }
            "/md" => {
                if args.is_empty() {
                    return Ok(Some("Usage: /md <markdown text>".to_string()));
                }
                self.send_markdown(args)?;
                Ok(Some("Sent (markdown)".to_string()))
            }
            "/reply" => {
                let text = args.trim();
                if text.is_empty() {
                    return Ok(Some("Usage: /reply <text>".to_string()));
                }
                let chat_id = self
                    .state
                    .active_chat
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("No active chat. Use /dm or /new first."))?;
                // Reply to the most recent message in this chat that has an id.
                let target = self
                    .state
                    .chats
                    .get(&chat_id)
                    .and_then(|s| s.messages.iter().rev().find_map(|m| m.message_id.clone()));
                let Some(target) = target else {
                    return Ok(Some("Nothing to reply to yet.".to_string()));
                };
                let preview = self
                    .state
                    .chats
                    .get(&chat_id)
                    .and_then(|s| {
                        s.messages
                            .iter()
                            .find(|m| m.message_id.as_deref() == Some(&target))
                    })
                    .map(|m| snippet_of(&m.content))
                    .unwrap_or_default();
                let encoded = message_types::encode_reply(&target, text)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                self.send_encoded(encoded, format!("↩ {preview}\n{text}"))?;
                Ok(Some("Reply sent".to_string()))
            }
            "/nickname" => {
                if args.is_empty() {
                    return Ok(Some("Usage: /nickname <name>".to_string()));
                }
                let chat_id = self
                    .state
                    .active_chat
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("No active chat."))?;
                let session = self
                    .state
                    .chats
                    .get_mut(&chat_id)
                    .ok_or_else(|| anyhow::anyhow!("Chat session not found."))?;
                session.nickname = Some(args.to_string());
                self.save_state()?;
                self.status = format!("Chat named '{args}'.");
                Ok(Some(format!("Nickname set to '{args}'")))
            }
            "/chats" => {
                self.show_chats_list();
                let n = self.state.chats.len();
                Ok(Some(if n == 0 {
                    "No chats yet".to_string()
                } else {
                    format!("{n} chat(s)")
                }))
            }
            "/switch" => {
                if args.is_empty() {
                    return Ok(Some("Usage: /switch <nickname|id-prefix>".to_string()));
                }
                let chat_id = self
                    .resolve_chat_id(args)
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("No chat matching '{args}'."))?;
                let label = self.state.chats[&chat_id].display_name().to_string();
                self.set_active_chat(Some(chat_id));
                self.save_state()?;
                self.status = format!("Switched to '{label}'.");
                Ok(Some(format!("Switched to '{label}'")))
            }
            "/delete" => {
                if args.is_empty() {
                    return Ok(Some("Usage: /delete <nickname|id-prefix>".to_string()));
                }
                let chat_id = self
                    .resolve_chat_id(args)
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("No chat matching '{args}'."))?;
                let label = self.state.chats[&chat_id].display_name().to_string();
                self.state.chats.remove(&chat_id);
                if self.state.active_chat.as_deref() == Some(&chat_id) {
                    self.state.active_chat = self.state.chats.keys().next().cloned();
                }
                self.save_state()?;
                self.status = format!("Deleted '{label}'.");
                Ok(Some(format!("Deleted '{label}'")))
            }
            "/status" => {
                let active_label = self
                    .state
                    .active_chat
                    .as_ref()
                    .and_then(|id| self.state.chats.get(id))
                    .map(|s| {
                        format!(
                            "{} ({})",
                            s.display_name(),
                            &s.chat_id[..8.min(s.chat_id.len())]
                        )
                    })
                    .unwrap_or_else(|| "none".to_string());
                let status = format!(
                    "User: {}\nIdentity: {}\nChats: {}\nActive: {}",
                    self.user_name,
                    self.client.installation_name(),
                    self.state.chats.len(),
                    active_label,
                );
                Ok(Some(status))
            }
            "/clear" => {
                if let Some(active) = &self.state.active_chat.clone()
                    && let Some(session) = self.state.chats.get_mut(active)
                {
                    session.messages.clear();
                    self.save_state()?;
                }
                Ok(Some("Messages cleared".to_string()))
            }
            "/quit" => Ok(None),
            _ => Ok(Some(format!(
                "Unknown command: {command}. Type /help for commands."
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{render_content, snippet_of};
    use message_types::{decode, encode_markdown, encode_text};

    fn body_of(bytes: &[u8]) -> String {
        render_content(&decode(bytes).unwrap().content)
    }

    #[test]
    fn renders_text() {
        assert_eq!(body_of(&encode_text("hi there").unwrap()), "hi there");
    }

    #[test]
    fn tags_markdown() {
        assert_eq!(body_of(&encode_markdown("# H").unwrap()), "[md] # H");
    }

    #[test]
    fn snippet_truncates_long_lines() {
        assert_eq!(snippet_of("short"), "short");
        assert_eq!(snippet_of(&"x".repeat(30)), format!("{}…", "x".repeat(24)));
    }
}
