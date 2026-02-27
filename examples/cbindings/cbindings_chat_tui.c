/**
 * Simple Terminal UI for liblogoschat.c
 * Commands:
 *   /join <intro_bundle_json>  - Join a conversation
 *   /bundle                    - Show your intro bundle
 *   /quit                      - Exit
 *   <message>                  - Send message to current conversation
 */

#include <ncurses.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "liblogoschat.h"

// Constants
static const int LOG_PANEL_HEIGHT = 6;
static const int MSG_PANEL_HEIGHT = 12;
static const int MAX_MESSAGES = 100;
static const int MAX_LOGS = 50;
static const size_t MAX_LINE_LEN = 2048;
static const size_t MAX_INPUT_LEN = 2048;

// Application state structures
typedef struct {
    char current_convo[128];
    char my_name[64];
    void *ctx;
} ChatState;

typedef struct {
    char (*lines)[2048];  
    int count;
    int max;
    pthread_mutex_t mutex;
} TextBuffer;

typedef struct {
    WINDOW *log_win, *msg_win, *input_win;
    WINDOW *log_border, *msg_border;
    SCREEN *screen;
    FILE *tty_out, *tty_in;
} UI;

typedef struct {
    char buffer[2048];
    int len;
    int pos;
} InputState;

typedef struct {
    ChatState chat;
    TextBuffer messages;
    TextBuffer logs;
    UI ui;
    InputState input;
    FILE *log_file;
    char log_filename[256];
    atomic_int running;
    atomic_int needs_refresh;
    atomic_int resize_pending;
} App;

static App g_app;

// Forward declarations
static void refresh_ui(void);
static void add_text(TextBuffer *buf, const char *text, const char *prefix);
static void handle_input(const char *input);

//////////////////////////////////////////////////////////////////////////////
// Utility functions
//////////////////////////////////////////////////////////////////////////////

static const char *get_timestamp(void) {
    static char buf[16];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
    return buf;
}

// Simple JSON string value extractor
static int json_extract(const char *json, const char **keys, char **values, 
                        size_t *sizes, int n) {
    int found = 0;
    for (int i = 0; i < n; i++) {
        values[i][0] = '\0';
        // Build search pattern: "key":
        char pattern[128];
        snprintf(pattern, sizeof(pattern), "\"%s\":", keys[i]);
        const char *pos = strstr(json, pattern);
        if (!pos) continue;
        
        pos += strlen(pattern);
        while (*pos == ' ') pos++;  // skip whitespace
        if (*pos != '"') continue;  // only handle string values
        pos++;  // skip opening quote
        
        const char *end = strchr(pos, '"');
        if (!end) continue;
        
        size_t len = end - pos;
        if (len >= sizes[i]) len = sizes[i] - 1;
        strncpy(values[i], pos, len);
        values[i][len] = '\0';
        found++;
    }
    return found;
}

static void string_to_hex(const char *str, char *hex, size_t hex_size) {
    size_t len = strlen(str);
    if (len * 2 + 1 > hex_size)
        len = (hex_size - 1) / 2;
    for (size_t i = 0; i < len; i++) {
        snprintf(hex + i * 2, 3, "%02x", (unsigned char)str[i]);
    }
    hex[len * 2] = '\0';
}

static void hex_to_string(const char *hex, char *str, size_t str_size) {
    size_t hex_len = strlen(hex);
    size_t len = hex_len / 2;
    if (len >= str_size)
        len = str_size - 1;
    for (size_t i = 0; i < len; i++) {
        char byte[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        char *end;
        unsigned long val = strtoul(byte, &end, 16);
        if (end != byte + 2) {
            str[i] = '?';  // Invalid hex
        } else {
            str[i] = (char)val;
        }
    }
    str[len] = '\0';
}

static int copy_to_clipboard(const char *data, size_t len) {
    const char *cmd = NULL;
#ifdef __APPLE__
    cmd = "pbcopy";
#else
    if (system("which wl-copy >/dev/null 2>&1") == 0)
        cmd = "wl-copy";
    else if (system("which xclip >/dev/null 2>&1") == 0)
        cmd = "xclip -selection clipboard";
    else if (system("which xsel >/dev/null 2>&1") == 0)
        cmd = "xsel --clipboard --input";
#endif
    if (!cmd) return 0;
    FILE *pipe = popen(cmd, "w");
    if (!pipe) return 0;
    fwrite(data, 1, len, pipe);
    pclose(pipe);
    return 1;
}

//////////////////////////////////////////////////////////////////////////////
// Text buffer operations
//////////////////////////////////////////////////////////////////////////////

static int textbuf_init(TextBuffer *buf, int max_lines) {
    buf->lines = calloc(max_lines, MAX_LINE_LEN);
    if (!buf->lines) return -1;
    buf->count = 0;
    buf->max = max_lines;
    pthread_mutex_init(&buf->mutex, NULL);
    return 0;
}

static void textbuf_destroy(TextBuffer *buf) {
    free(buf->lines);
    buf->lines = NULL;
    pthread_mutex_destroy(&buf->mutex);
}

static void add_text(TextBuffer *buf, const char *text, const char *prefix) {
    pthread_mutex_lock(&buf->mutex);
    if (buf->count >= buf->max) {
        memmove(buf->lines[0], buf->lines[1], (buf->max - 1) * MAX_LINE_LEN);
        buf->count = buf->max - 1;
    }
    if (prefix) {
        snprintf(buf->lines[buf->count], MAX_LINE_LEN, "[%s] %s", prefix, text);
    } else {
        snprintf(buf->lines[buf->count], MAX_LINE_LEN, "%s", text);
    }
    buf->count++;
    pthread_mutex_unlock(&buf->mutex);
    atomic_store(&g_app.needs_refresh, 1);
}

static inline void add_message(const char *msg) {
    add_text(&g_app.messages, msg, NULL);
}

static inline void add_log(const char *log) {
    add_text(&g_app.logs, log, get_timestamp());
}

//////////////////////////////////////////////////////////////////////////////
// ncurses UI
//////////////////////////////////////////////////////////////////////////////

static void create_windows(void) {
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    int log_height = LOG_PANEL_HEIGHT + 2;
    int msg_height = MSG_PANEL_HEIGHT + 2;
    int input_height = 3;
    int available = max_y - input_height;

    if (log_height + msg_height > available) {
        log_height = available / 3;
        msg_height = available - log_height;
    }

    UI *ui = &g_app.ui;
    ui->log_border = newwin(log_height, max_x, 0, 0);
    ui->msg_border = newwin(msg_height, max_x, log_height, 0);
    ui->log_win = derwin(ui->log_border, log_height - 2, max_x - 2, 1, 1);
    ui->msg_win = derwin(ui->msg_border, msg_height - 2, max_x - 2, 1, 1);
    ui->input_win = newwin(input_height, max_x, log_height + msg_height, 0);

    scrollok(ui->log_win, TRUE);
    scrollok(ui->msg_win, TRUE);
    keypad(ui->input_win, TRUE);
    nodelay(ui->input_win, TRUE);

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_CYAN, -1);
        init_pair(2, COLOR_GREEN, -1);
        init_pair(3, COLOR_YELLOW, -1);
        init_pair(4, COLOR_RED, -1);
        init_pair(5, COLOR_MAGENTA, -1);
    }
}

static void destroy_windows(void) {
    UI *ui = &g_app.ui;
    if (ui->log_win) delwin(ui->log_win);
    if (ui->msg_win) delwin(ui->msg_win);
    if (ui->input_win) delwin(ui->input_win);
    if (ui->log_border) delwin(ui->log_border);
    if (ui->msg_border) delwin(ui->msg_border);
    memset(ui, 0, sizeof(*ui) - sizeof(ui->screen) - sizeof(ui->tty_out) - sizeof(ui->tty_in));
}

static void draw_borders(void) {
    UI *ui = &g_app.ui;
    ChatState *chat = &g_app.chat;

    wattron(ui->log_border, COLOR_PAIR(3) | A_DIM);
    box(ui->log_border, 0, 0);
    mvwprintw(ui->log_border, 0, 2, " Logs ");
    wattroff(ui->log_border, COLOR_PAIR(3) | A_DIM);

    wattron(ui->msg_border, COLOR_PAIR(1) | A_BOLD);
    box(ui->msg_border, 0, 0);
    if (chat->current_convo[0]) {
        mvwprintw(ui->msg_border, 0, 2, " Messages [%s] [%s] ", chat->my_name, chat->current_convo);
    } else {
        mvwprintw(ui->msg_border, 0, 2, " Messages [%s] [no conversation] ", chat->my_name);
    }
    wattroff(ui->msg_border, COLOR_PAIR(1) | A_BOLD);

    wattron(ui->input_win, COLOR_PAIR(2) | A_BOLD);
    box(ui->input_win, 0, 0);
    mvwprintw(ui->input_win, 0, 2, " Input ");
    wattroff(ui->input_win, COLOR_PAIR(2) | A_BOLD);

    wnoutrefresh(ui->log_border);
    wnoutrefresh(ui->msg_border);
}

static void draw_textbuf(WINDOW *win, TextBuffer *buf) {
    werase(win);
    pthread_mutex_lock(&buf->mutex);

    int max_y = getmaxy(win);
    int max_x = getmaxx(win);
    int total_lines = 0;
    int *lines_per = alloca(buf->count * sizeof(int));

    for (int i = 0; i < buf->count; i++) {
        int len = (int)strlen(buf->lines[i]);
        lines_per[i] = len == 0 ? 1 : (len + max_x - 1) / max_x;
        total_lines += lines_per[i];
    }

    int skip = total_lines > max_y ? total_lines - max_y : 0;
    int start = 0, skipped = 0;
    while (start < buf->count && skipped + lines_per[start] <= skip) {
        skipped += lines_per[start++];
    }

    int row = 0;
    for (int i = start; i < buf->count && row < max_y; i++) {
        wmove(win, row, 0);
        if (buf == &g_app.logs) wattron(win, A_DIM);
        wprintw(win, "%s", buf->lines[i]);
        if (buf == &g_app.logs) wattroff(win, A_DIM);
        row += lines_per[i];
    }

    pthread_mutex_unlock(&buf->mutex);
    wnoutrefresh(win);
}

static void draw_input(void) {
    UI *ui = &g_app.ui;
    InputState *inp = &g_app.input;
    int max_x = getmaxx(ui->input_win);

    mvwhline(ui->input_win, 1, 1, ' ', max_x - 2);
    wattron(ui->input_win, COLOR_PAIR(2) | A_BOLD);
    mvwprintw(ui->input_win, 1, 1, "> ");
    wattroff(ui->input_win, COLOR_PAIR(2) | A_BOLD);

    int available = max_x - 5;
    int display_start = inp->pos > available - 1 ? inp->pos - available + 1 : 0;
    mvwprintw(ui->input_win, 1, 3, "%.*s", available, inp->buffer + display_start);
    wmove(ui->input_win, 1, 3 + inp->pos - display_start);
    wnoutrefresh(ui->input_win);
}

static void refresh_ui(void) {
    if (!atomic_exchange(&g_app.needs_refresh, 0)) return;

    if (atomic_exchange(&g_app.resize_pending, 0)) {
        endwin();
        refresh();
        destroy_windows();
        create_windows();
    }

    draw_borders();
    draw_textbuf(g_app.ui.log_win, &g_app.logs);
    draw_textbuf(g_app.ui.msg_win, &g_app.messages);
    draw_input();
    doupdate();
}

//////////////////////////////////////////////////////////////////////////////
// Signal handling (async-signal-safe)
//////////////////////////////////////////////////////////////////////////////

static void handle_sigint(int sig) {
    (void)sig;
    atomic_store(&g_app.running, 0);
}

static void handle_sigwinch(int sig) {
    (void)sig;
    atomic_store(&g_app.resize_pending, 1);
    atomic_store(&g_app.needs_refresh, 1);
}

//////////////////////////////////////////////////////////////////////////////
// FFI Callbacks
//////////////////////////////////////////////////////////////////////////////

static void general_callback(int ret, const char *msg, size_t len, void *userData) {
    (void)userData;
    char buf[256];
    if (ret == RET_OK) {
        snprintf(buf, sizeof(buf), "OK%s%.*s", len > 0 ? ": " : "", (int)(len > 60 ? 60 : len), msg);
    } else {
        snprintf(buf, sizeof(buf), "ERR: %.*s", (int)(len > 60 ? 60 : len), msg);
    }
    add_log(buf);
}

static void event_callback(int ret, const char *msg, size_t len, void *userData) {
    (void)userData;
    (void)ret;
    (void)len;

    char event_type[32] = {0};
    char convo_id[128] = {0};
    char content[2048] = {0};
    
    const char *keys[] = {"eventType", "conversationId", "content"};
    char *values[] = {event_type, convo_id, content};
    size_t sizes[] = {sizeof(event_type), sizeof(convo_id), sizeof(content)};
    json_extract(msg, keys, values, sizes, 3);

    if (strcmp(event_type, "new_message") == 0) {
        char decoded[2048], buf[2048];
        hex_to_string(content, decoded, sizeof(decoded));
        snprintf(buf, sizeof(buf), "<- %s", decoded);
        add_message(buf);
    } else if (strcmp(event_type, "new_conversation") == 0) {
        strncpy(g_app.chat.current_convo, convo_id, sizeof(g_app.chat.current_convo) - 1);
        char buf[256];
        snprintf(buf, sizeof(buf), "* New conversation: %.32s...", g_app.chat.current_convo);
        add_message(buf);
    } else if (strcmp(event_type, "delivery_ack") == 0) {
        add_log("Delivery acknowledged");
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "EVT: %.70s%s", msg, len > 70 ? "..." : "");
    add_log(buf);
}

static void bundle_callback(int ret, const char *msg, size_t len, void *userData) {
    (void)userData;
    if (ret == RET_OK && len > 0) {
        char buf[2048];
        snprintf(buf, sizeof(buf), "%.*s", (int)(len < sizeof(buf) - 1 ? len : sizeof(buf) - 1), msg);

        if (copy_to_clipboard(msg, len)) {
            add_message("Your IntroBundle (copied to clipboard):");
            add_log("Bundle copied to clipboard");
        } else {
            add_message("Your IntroBundle:");
        }
        add_message("");
        add_message(buf);
        add_message("");
    } else {
        char buf[256];
        snprintf(buf, sizeof(buf), "Failed to get bundle: %.*s", (int)len, msg);
        add_message(buf);
    }
}

static void identity_callback(int ret, const char *msg, size_t len, void *userData) {
    (void)userData; (void)len;
    if (ret == RET_OK) {
        const char *keys[] = {"name"};
        char *values[] = {g_app.chat.my_name};
        size_t sizes[] = {sizeof(g_app.chat.my_name)};
        json_extract(msg, keys, values, sizes, 1);

        char buf[256];
        snprintf(buf, sizeof(buf), "Identity: %s", g_app.chat.my_name);
        add_log(buf);
    }
}

//////////////////////////////////////////////////////////////////////////////
// Command handling
//////////////////////////////////////////////////////////////////////////////

static void cmd_join(const char *args) {
    if (!args || !*args) {
        add_message("Usage: /join <intro_bundle_json>");
        return;
    }
    char hex_msg[256];
    string_to_hex("Hello!", hex_msg, sizeof(hex_msg));
    chat_new_private_conversation(g_app.chat.ctx, general_callback, NULL, args, hex_msg);
    add_message("* Creating conversation...");
}

static void cmd_send(const char *message) {
    if (!g_app.chat.current_convo[0]) {
        add_message("No active conversation. Use /join or receive an invite.");
        return;
    }
    char hex_msg[4096];
    string_to_hex(message, hex_msg, sizeof(hex_msg));
    chat_send_message(g_app.chat.ctx, general_callback, NULL, g_app.chat.current_convo, hex_msg);

    char buf[2048];
    snprintf(buf, sizeof(buf), "-> You: %s", message);
    add_message(buf);
}

static void handle_input(const char *input) {
    if (!input || !*input) return;

    if (input[0] != '/') {
        cmd_send(input);
        return;
    }

    if (strncmp(input, "/quit", 5) == 0 || strncmp(input, "/q", 2) == 0) {
        atomic_store(&g_app.running, 0);
    } else if (strncmp(input, "/join ", 6) == 0) {
        cmd_join(input + 6);
    } else if (strncmp(input, "/bundle", 7) == 0) {
        chat_create_intro_bundle(g_app.chat.ctx, bundle_callback, NULL);
    } else if (strncmp(input, "/help", 5) == 0) {
        add_message("Commands:");
        add_message("  /join <bundle>  - Join conversation with IntroBundle");
        add_message("  /bundle         - Show your IntroBundle");
        add_message("  /quit           - Exit");
        add_message("  <message>       - Send message");
    } else {
        char buf[256];
        snprintf(buf, sizeof(buf), "Unknown command: %s", input);
        add_message(buf);
    }
}

//////////////////////////////////////////////////////////////////////////////
// Input processing
//////////////////////////////////////////////////////////////////////////////

static void process_input_char(int ch) {
    InputState *inp = &g_app.input;

    switch (ch) {
    case '\n':
    case KEY_ENTER:
        if (inp->len > 0) {
            inp->buffer[inp->len] = '\0';
            handle_input(inp->buffer);
            inp->len = inp->pos = 0;
            inp->buffer[0] = '\0';
        }
        break;
    case KEY_BACKSPACE:
    case 127: // DEL
    case 8: // BS
        if (inp->pos > 0) {
            memmove(inp->buffer + inp->pos - 1, inp->buffer + inp->pos, inp->len - inp->pos + 1);
            inp->pos--;
            inp->len--;
        }
        break;
    case KEY_DC:
        if (inp->pos < inp->len) {
            memmove(inp->buffer + inp->pos, inp->buffer + inp->pos + 1, inp->len - inp->pos);
            inp->len--;
        }
        break;
    case KEY_LEFT:
        if (inp->pos > 0) inp->pos--;
        break;
    case KEY_RIGHT:
        if (inp->pos < inp->len) inp->pos++;
        break;
    default:
        if (ch >= 32 && ch < 127 && inp->len < (int)MAX_INPUT_LEN - 1) {
            memmove(inp->buffer + inp->pos + 1, inp->buffer + inp->pos, inp->len - inp->pos + 1);
            inp->buffer[inp->pos++] = ch;
            inp->len++;
        }
        break;
    }
    atomic_store(&g_app.needs_refresh, 1);
}

//////////////////////////////////////////////////////////////////////////////
// Initialization and cleanup
//////////////////////////////////////////////////////////////////////////////

static int init_logging(const char *name) {
    time_t now = time(NULL);
    snprintf(g_app.log_filename, sizeof(g_app.log_filename), "chat_tui_%s_%ld.log", name, (long)now);

    g_app.log_file = fopen(g_app.log_filename, "w");
    if (!g_app.log_file) {
        g_app.log_file = fopen("/dev/null", "w");
    }

    g_app.ui.tty_out = fopen("/dev/tty", "w");
    g_app.ui.tty_in = fopen("/dev/tty", "r");
    if (!g_app.ui.tty_out || !g_app.ui.tty_in) {
        fprintf(stderr, "Error: Could not open /dev/tty\n");
        return -1;
    }

    fflush(stdout);
    fflush(stderr);
    dup2(fileno(g_app.log_file), STDOUT_FILENO);
    dup2(fileno(g_app.log_file), STDERR_FILENO);
    return 0;
}

static int init_ui(void) {
    g_app.ui.screen = newterm(NULL, g_app.ui.tty_out, g_app.ui.tty_in);
    if (!g_app.ui.screen) return -1;

    set_term(g_app.ui.screen);
    cbreak();
    noecho();
    curs_set(1);
    if (has_colors()) {
        start_color();
        use_default_colors();
    }
    create_windows();
    return 0;
}

static void cleanup(void) {
    if (g_app.chat.ctx) {
        chat_stop(g_app.chat.ctx, general_callback, NULL);
        chat_destroy(g_app.chat.ctx, general_callback, NULL);
    }

    destroy_windows();
    if (g_app.ui.screen) {
        endwin();
        delscreen(g_app.ui.screen);
    }

    if (g_app.ui.tty_out) fclose(g_app.ui.tty_out);
    if (g_app.ui.tty_in) fclose(g_app.ui.tty_in);
    if (g_app.log_file) fclose(g_app.log_file);

    textbuf_destroy(&g_app.messages);
    textbuf_destroy(&g_app.logs);

    FILE *tty = fopen("/dev/tty", "w");
    if (tty) {
        fprintf(tty, "Goodbye! (Library logs saved to %s)\n", g_app.log_filename);
        fclose(tty);
    }
}

//////////////////////////////////////////////////////////////////////////////
// Main
//////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[]) {
    const char *name = "user";
    int port = 0, cluster_id = 2, shard_id = 1;
    const char *peer = NULL;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--name=", 7) == 0) name = argv[i] + 7;
        else if (strncmp(argv[i], "--port=", 7) == 0) port = atoi(argv[i] + 7);
        else if (strncmp(argv[i], "--cluster=", 10) == 0) cluster_id = atoi(argv[i] + 10);
        else if (strncmp(argv[i], "--shard=", 8) == 0) shard_id = atoi(argv[i] + 8);
        else if (strncmp(argv[i], "--peer=", 7) == 0) peer = argv[i] + 7;
        else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("  --name=<name>      Your display name\n");
            printf("  --port=<port>      Listen port (0 for random)\n");
            printf("  --cluster=<id>     Cluster ID (default: 2)\n");
            printf("  --shard=<id>       Shard ID (default: 1)\n");
            printf("  --peer=<addr>      Static peer multiaddr\n");
            return 0;
        }
    }

    // Initialize application state
    memset(&g_app, 0, sizeof(g_app));
    strncpy(g_app.chat.my_name, name, sizeof(g_app.chat.my_name) - 1);
    atomic_store(&g_app.running, 1);

    if (textbuf_init(&g_app.messages, MAX_MESSAGES) < 0 ||
        textbuf_init(&g_app.logs, MAX_LOGS) < 0) {
        fprintf(stderr, "Failed to allocate buffers\n");
        return 1;
    }

    if (init_logging(name) < 0) {
        textbuf_destroy(&g_app.messages);
        textbuf_destroy(&g_app.logs);
        return 1;
    }

    // Build config and create chat context
    char config[2048];
    if (peer) {
        snprintf(config, sizeof(config),
                 "{\"name\":\"%s\",\"port\":%d,\"clusterId\":%d,\"shardId\":%d,\"staticPeers\":[\"%s\"]}",
                 name, port, cluster_id, shard_id, peer);
    } else {
        snprintf(config, sizeof(config),
                 "{\"name\":\"%s\",\"port\":%d,\"clusterId\":%d,\"shardId\":%d}",
                 name, port, cluster_id, shard_id);
    }

    g_app.chat.ctx = chat_new(config, general_callback, NULL);
    if (!g_app.chat.ctx) {
        fprintf(g_app.log_file, "Failed to create chat context\n");
        cleanup();
        return 1;
    }

    set_event_callback(g_app.chat.ctx, event_callback, NULL);

    if (init_ui() < 0) {
        fprintf(g_app.log_file, "Failed to initialize ncurses\n");
        cleanup();
        return 1;
    }

    signal(SIGINT, handle_sigint);
    signal(SIGWINCH, handle_sigwinch);

    add_log("Starting client...");
    chat_start(g_app.chat.ctx, general_callback, NULL);
    chat_get_identity(g_app.chat.ctx, identity_callback, NULL);

    add_message("Welcome to Chat TUI!");
    add_message("Type /help for commands, /quit to exit");
    add_message("");

    atomic_store(&g_app.needs_refresh, 1);
    refresh_ui();

    // Main loop
    while (atomic_load(&g_app.running)) {
        int ch;
        while ((ch = wgetch(g_app.ui.input_win)) != ERR) {
            process_input_char(ch);
        }
        refresh_ui();
        usleep(10000);
    }

    add_log("Shutting down...");
    cleanup();
    return 0;
}