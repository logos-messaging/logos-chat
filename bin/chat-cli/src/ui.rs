//! Terminal UI using ratatui.

use std::io::{self, Stdout};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

use logos_chat::{AccountDirectory, ConversationStore, KvStore, RegistrationService, Transport};

use crate::app::ChatApp;

pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Initialize the terminal.
pub fn init() -> io::Result<Tui> {
    execute!(io::stdout(), EnterAlternateScreen)?;
    enable_raw_mode()?;
    let backend = CrosstermBackend::new(io::stdout());
    Terminal::new(backend)
}

/// Restore the terminal to its original state.
pub fn restore() -> io::Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

/// Draw the UI.
pub fn draw<D, R, S>(frame: &mut Frame, app: &ChatApp<D, R, S>)
where
    D: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: KvStore + ConversationStore + Send + 'static,
{
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Messages
            Constraint::Length(3), // Input
            Constraint::Length(3), // Status
        ])
        .split(frame.area());

    draw_header(frame, app, chunks[0]);
    draw_messages(frame, app, chunks[1]);
    draw_input(frame, app, chunks[2]);
    draw_status(frame, app, chunks[3]);
}

fn draw_header<D, R, S>(frame: &mut Frame, app: &ChatApp<D, R, S>, area: Rect)
where
    D: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: KvStore + ConversationStore + Send + 'static,
{
    let title = match app.current_session() {
        Some(session) => {
            let id = &session.chat_id[..8.min(session.chat_id.len())];
            match &session.nickname {
                Some(name) => format!(" 💬 Chat: {} ↔ {name} ({id}) ", app.user_name),
                None => format!(" 💬 Chat: {} ↔ ({id}) ", app.user_name),
            }
        }
        None => format!(" 💬 {} — no active chat ", app.user_name),
    };

    let header = Paragraph::new(title)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));

    frame.render_widget(header, area);
}

fn draw_messages<D, R, S>(frame: &mut Frame, app: &ChatApp<D, R, S>, area: Rect)
where
    D: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: KvStore + ConversationStore + Send + 'static,
{
    let remote_name = app
        .current_session()
        .map(|s| s.display_name())
        .unwrap_or("Them");
    // In a group every incoming message is attributed to its own sender; in a
    // DM the single peer's label is enough.
    let is_group = matches!(
        app.current_session().map(|s| s.kind),
        Some(logos_chat::ConversationClass::Group)
    );

    // Inner width: area minus borders (2) for wrapping long content.
    let inner_width = area.width.saturating_sub(2) as usize;

    let messages: Vec<ListItem> = app
        .messages()
        .iter()
        .flat_map(|msg| {
            let (prefix, style) = if msg.from_self {
                ("You".to_string(), Style::default().fg(Color::Green))
            } else if is_group {
                // App resolves a display name from the sender's account address —
                // a truncation for now; a contacts/accounts lookup slots in here.
                let label = match &msg.origin {
                    crate::app::MessageOrigin::Own => "you",
                    crate::app::MessageOrigin::Foreign(account) => &account[..8.min(account.len())],
                };
                (label.to_string(), Style::default().fg(Color::Yellow))
            } else {
                (remote_name.to_string(), Style::default().fg(Color::Yellow))
            };

            let prefix_str = format!("{}: ", prefix);
            let prefix_len = prefix_str.len();

            // Split content into lines that fit within inner_width.
            let content = &msg.content;
            if content.is_empty() {
                return vec![ListItem::new(Line::from(vec![Span::styled(
                    prefix_str,
                    style.add_modifier(Modifier::BOLD),
                )]))];
            }

            let mut items = Vec::new();
            let first_line_width = inner_width.saturating_sub(prefix_len).max(1);

            // First line includes the prefix.
            let (first_chunk, rest): (&str, &str) = if content.len() <= first_line_width {
                (content.as_str(), "")
            } else {
                content.split_at(first_line_width)
            };

            items.push(ListItem::new(Line::from(vec![
                Span::styled(prefix_str, style.add_modifier(Modifier::BOLD)),
                Span::raw(first_chunk),
            ])));

            // Continuation lines are indented to align with content.
            let indent = " ".repeat(prefix_len);
            let mut remaining: &str = rest;
            while !remaining.is_empty() {
                let chunk_width = inner_width.saturating_sub(prefix_len).max(1);
                let (chunk, tail) = if remaining.len() <= chunk_width {
                    (remaining, "")
                } else {
                    remaining.split_at(chunk_width)
                };
                items.push(ListItem::new(Line::from(vec![
                    Span::raw(indent.clone()),
                    Span::raw(chunk),
                ])));
                remaining = tail;
            }

            // Delivery receipts for our own sends: the peers whose later
            // messages showed they hold this one.
            if !msg.delivered_to.is_empty() {
                items.push(ListItem::new(Line::from(vec![
                    Span::raw(indent.clone()),
                    Span::styled(
                        format!("↳ delivered to {}", msg.delivered_to.join(", ")),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])));
            }

            items
        })
        .collect();

    let title = match app.current_session() {
        Some(s) => match &s.nickname {
            Some(name) => format!(" Messages with {name} "),
            None => format!(" Messages ({}) ", &s.chat_id[..8.min(s.chat_id.len())]),
        },
        None => " Command output ".to_string(),
    };

    let item_count = messages.len();
    let messages_widget =
        List::new(messages).block(Block::default().title(title).borders(Borders::ALL));

    // Scroll so the last line is always visible (area height minus two borders).
    let visible = area.height.saturating_sub(2) as usize;
    let offset = item_count.saturating_sub(visible);
    let mut list_state = ratatui::widgets::ListState::default().with_offset(offset);
    frame.render_stateful_widget(messages_widget, area, &mut list_state);
}

fn draw_input<D, R, S>(frame: &mut Frame, app: &ChatApp<D, R, S>, area: Rect)
where
    D: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: KvStore + ConversationStore + Send + 'static,
{
    // Inner width: area minus borders (2).
    let inner_width = area.width.saturating_sub(2) as usize;
    let input_len = app.input.len();

    // Scroll the view so the cursor (end of input) is always visible.
    let scroll_offset = if input_len >= inner_width {
        input_len - inner_width + 1
    } else {
        0
    };

    let visible_input = &app.input[scroll_offset..];

    let input = Paragraph::new(visible_input).style(Style::default()).block(
        Block::default()
            .title(" Input (Enter to send) ")
            .borders(Borders::ALL),
    );

    frame.render_widget(input, area);

    // Place cursor at the visible end of the input.
    let cursor_x = area.x + (input_len - scroll_offset) as u16 + 1;
    frame.set_cursor_position((cursor_x, area.y + 1));
}

fn draw_status<D, R, S>(frame: &mut Frame, app: &ChatApp<D, R, S>, area: Rect)
where
    D: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: KvStore + ConversationStore + Send + 'static,
{
    let status = Paragraph::new(app.status.as_str())
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().title(" Status ").borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    frame.render_widget(status, area);
}

/// Handle keyboard events.
pub fn handle_events<D, R, S>(app: &mut ChatApp<D, R, S>) -> io::Result<bool>
where
    D: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: KvStore + ConversationStore + Send + 'static,
{
    // Poll for events with a short timeout to allow checking incoming messages
    if event::poll(std::time::Duration::from_millis(100))?
        && let Event::Key(key) = event::read()?
    {
        if key.kind != KeyEventKind::Press {
            return Ok(true);
        }

        match key.code {
            KeyCode::Esc => return Ok(false),
            // Handle Ctrl+C
            KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                return Ok(false);
            }
            KeyCode::Enter if !app.input.is_empty() => {
                let input = std::mem::take(&mut app.input);

                if input.starts_with('/') {
                    match app.handle_command(&input) {
                        Ok(Some(response)) => {
                            app.status = response;
                        }
                        Ok(None) => {
                            // Quit signal
                            return Ok(false);
                        }
                        Err(e) => {
                            app.status = format!("Error: {}", e);
                        }
                    }
                } else if app.current_session().is_some() {
                    if let Err(e) = app.send_message(&input) {
                        app.status = format!("Send error: {}", e);
                    }
                } else {
                    app.status = "No active chat. Use /dm or /new first.".to_string();
                }
            }
            KeyCode::Char(c) => {
                app.input.push(c);
            }
            KeyCode::Backspace => {
                app.input.pop();
            }
            _ => {}
        }
    }

    Ok(true)
}
