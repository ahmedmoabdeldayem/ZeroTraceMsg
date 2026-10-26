#include "store.hpp"
#include <chrono>
#include <sqlite3.h>
#include <stdexcept>
#include <string>

// ── helpers ──────────────────────────────────────────────────────────────────

void Store::check(int rc) const
{
    if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW)
        throw std::runtime_error(std::string("SQLite error: ") + sqlite3_errmsg(db_));
}

void Store::exec(const char* sql)
{
    char* errmsg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::string msg = errmsg ? errmsg : "unknown SQLite error";
        sqlite3_free(errmsg);
        throw std::runtime_error("SQLite exec failed: " + msg);
    }
}

// RAII wrapper for a prepared statement
struct Stmt {
    sqlite3_stmt* s{nullptr};
    ~Stmt() { sqlite3_finalize(s); }
    explicit operator sqlite3_stmt*() { return s; }
};

// ── construction / schema ─────────────────────────────────────────────────────

Store::Store(const std::string& path)
{
    const char* dbpath = path.empty() ? ":memory:" : path.c_str();
    int rc = sqlite3_open(dbpath, &db_);
    if (rc != SQLITE_OK)
        throw std::runtime_error(std::string("Cannot open database: ") + sqlite3_errmsg(db_));

    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA foreign_keys=ON");
    exec("CREATE TABLE IF NOT EXISTS users ("
         "  user_id TEXT PRIMARY KEY,"
         "  pubkey  BLOB NOT NULL"
         ")");
    exec("CREATE TABLE IF NOT EXISTS sessions ("
         "  user_id    TEXT PRIMARY KEY,"
         "  token      TEXT NOT NULL,"
         "  created_at INTEGER NOT NULL"
         ")");
    exec("CREATE TABLE IF NOT EXISTS messages ("
         "  id           TEXT PRIMARY KEY,"
         "  recipient_id TEXT NOT NULL,"
         "  sender_id    TEXT NOT NULL,"
         "  blob         BLOB NOT NULL,"
         "  timestamp    INTEGER NOT NULL,"
         "  in_flight_at INTEGER DEFAULT NULL"
         ")");
    exec("CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id)");
    // Schema migrations: add columns that didn't exist in earlier schema versions.
    try {
        exec("ALTER TABLE messages ADD COLUMN in_flight_at INTEGER DEFAULT NULL");
    } catch (...) {
    }
    try {
        exec("ALTER TABLE messages ADD COLUMN prekey_id TEXT NOT NULL DEFAULT '_'");
    } catch (...) {
    }
    exec("CREATE TABLE IF NOT EXISTS rate_buckets ("
         "  user_id      TEXT PRIMARY KEY,"
         "  count        INTEGER NOT NULL,"
         "  window_start INTEGER NOT NULL,"
         "  last_used    INTEGER NOT NULL"
         ")");
    exec("CREATE TABLE IF NOT EXISTS delivery_acks ("
         "  user_id TEXT PRIMARY KEY,"
         "  count   INTEGER NOT NULL DEFAULT 0"
         ")");
    exec("CREATE TABLE IF NOT EXISTS prekeys ("
         "  prekey_id   TEXT PRIMARY KEY,"
         "  user_id     TEXT NOT NULL,"
         "  pubkey      BLOB NOT NULL,"
         "  uploaded_at INTEGER NOT NULL"
         ")");
    exec("CREATE INDEX IF NOT EXISTS idx_prekeys_user ON prekeys(user_id)");
    exec("CREATE TABLE IF NOT EXISTS groups ("
         "  group_id   TEXT PRIMARY KEY,"
         "  owner_id   TEXT NOT NULL,"
         "  name       TEXT NOT NULL,"
         "  created_at INTEGER NOT NULL"
         ")");
    exec("CREATE TABLE IF NOT EXISTS group_members ("
         "  group_id  TEXT NOT NULL,"
         "  user_id   TEXT NOT NULL,"
         "  joined_at INTEGER NOT NULL,"
         "  PRIMARY KEY (group_id, user_id)"
         ")");
    exec("CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id)");
    exec("CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id)");
    exec("CREATE TABLE IF NOT EXISTS linked_devices ("
         "  primary_id TEXT NOT NULL,"
         "  device_id  TEXT NOT NULL,"
         "  linked_at  INTEGER NOT NULL,"
         "  PRIMARY KEY (primary_id, device_id)"
         ")");
    exec("CREATE INDEX IF NOT EXISTS idx_linked_primary ON linked_devices(primary_id)");
    exec("CREATE INDEX IF NOT EXISTS idx_linked_device ON linked_devices(device_id)");
}

Store::~Store() { sqlite3_close(db_); }

// ── users ─────────────────────────────────────────────────────────────────────

void Store::put_user(const std::string& user_id, const std::vector<uint8_t>& pubkey)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "INSERT OR REPLACE INTO users(user_id, pubkey) VALUES(?,?)", -1,
                             &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    check(
        sqlite3_bind_blob(st.s, 2, pubkey.data(), static_cast<int>(pubkey.size()), SQLITE_STATIC));
    check(sqlite3_step(st.s));
}

std::optional<std::vector<uint8_t>> Store::get_pubkey(const std::string& user_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT pubkey FROM users WHERE user_id=?", -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    int rc = sqlite3_step(st.s);
    if (rc == SQLITE_DONE)
        return std::nullopt;
    check(rc);
    const void* raw = sqlite3_column_blob(st.s, 0);
    int len = sqlite3_column_bytes(st.s, 0);
    return std::vector<uint8_t>(static_cast<const uint8_t*>(raw),
                                static_cast<const uint8_t*>(raw) + len);
}

bool Store::user_exists(const std::string& user_id) { return get_pubkey(user_id).has_value(); }

int Store::user_count()
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM users", -1, &st.s, nullptr));
    check(sqlite3_step(st.s));
    return sqlite3_column_int(st.s, 0);
}

std::vector<std::string> Store::list_users()
{
    Stmt st;
    check(
        sqlite3_prepare_v2(db_, "SELECT user_id FROM users ORDER BY user_id", -1, &st.s, nullptr));
    std::vector<std::string> ids;
    while (sqlite3_step(st.s) == SQLITE_ROW)
        ids.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0)));
    return ids;
}

void Store::remove_user(const std::string& user_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "DELETE FROM users WHERE user_id=?", -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
}

// ── sessions ──────────────────────────────────────────────────────────────────

void Store::put_session(const std::string& user_id, const std::string& token, int64_t created_at)
{
    Stmt st;
    check(sqlite3_prepare_v2(
        db_, "INSERT OR REPLACE INTO sessions(user_id, token, created_at) VALUES(?,?,?)", -1, &st.s,
        nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 2, token.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_int64(st.s, 3, created_at));
    check(sqlite3_step(st.s));
}

std::optional<Store::SessionRow> Store::get_session(const std::string& user_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT token, created_at FROM sessions WHERE user_id=?", -1,
                             &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    int rc = sqlite3_step(st.s);
    if (rc == SQLITE_DONE)
        return std::nullopt;
    check(rc);
    SessionRow row;
    row.token = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
    row.created_at = sqlite3_column_int64(st.s, 1);
    return row;
}

void Store::remove_session(const std::string& user_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "DELETE FROM sessions WHERE user_id=?", -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
}

int Store::session_count()
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM sessions", -1, &st.s, nullptr));
    check(sqlite3_step(st.s));
    return sqlite3_column_int(st.s, 0);
}

void Store::prune_sessions(int64_t min_created_at)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "DELETE FROM sessions WHERE created_at < ?", -1, &st.s, nullptr));
    check(sqlite3_bind_int64(st.s, 1, min_created_at));
    check(sqlite3_step(st.s));
}

// ── messages ──────────────────────────────────────────────────────────────────

void Store::enqueue(const std::string& msg_id, const std::string& recipient_id,
                    const std::string& sender_id, const std::vector<uint8_t>& blob,
                    const std::string& prekey_id, int64_t ts)
{
    Stmt st;
    check(sqlite3_prepare_v2(
        db_,
        "INSERT INTO messages(id, recipient_id, sender_id, blob, prekey_id, timestamp)"
        " VALUES(?,?,?,?,?,?)",
        -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, msg_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 2, recipient_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 3, sender_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_blob(st.s, 4, blob.data(), static_cast<int>(blob.size()), SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 5, prekey_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_int64(st.s, 6, ts));
    check(sqlite3_step(st.s));
}

int Store::inbox_size(const std::string& recipient_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM messages WHERE recipient_id=?", -1, &st.s,
                             nullptr));
    check(sqlite3_bind_text(st.s, 1, recipient_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
    return sqlite3_column_int(st.s, 0);
}

std::vector<Store::MessageRow> Store::drain_inbox(const std::string& recipient_id)
{
    exec("BEGIN");
    std::vector<MessageRow> rows;

    {
        Stmt st;
        check(sqlite3_prepare_v2(db_,
                                 "SELECT id, sender_id, prekey_id, blob FROM messages"
                                 " WHERE recipient_id=? ORDER BY timestamp ASC",
                                 -1, &st.s, nullptr));
        check(sqlite3_bind_text(st.s, 1, recipient_id.c_str(), -1, SQLITE_STATIC));
        while (sqlite3_step(st.s) == SQLITE_ROW) {
            MessageRow row;
            row.id = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
            row.sender_id = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 1));
            row.prekey_id = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 2));
            const void* raw = sqlite3_column_blob(st.s, 3);
            int len = sqlite3_column_bytes(st.s, 3);
            row.blob.assign(static_cast<const uint8_t*>(raw),
                            static_cast<const uint8_t*>(raw) + len);
            rows.push_back(std::move(row));
        }
    }

    {
        Stmt st;
        check(sqlite3_prepare_v2(db_, "DELETE FROM messages WHERE recipient_id=?", -1, &st.s,
                                 nullptr));
        check(sqlite3_bind_text(st.s, 1, recipient_id.c_str(), -1, SQLITE_STATIC));
        check(sqlite3_step(st.s));
    }

    exec("COMMIT");
    return rows;
}

std::vector<Store::MessageRow> Store::peek_inbox(const std::string& recipient_id, int64_t now)
{
    exec("BEGIN");
    std::vector<MessageRow> rows;

    {
        Stmt st;
        check(sqlite3_prepare_v2(
            db_,
            "SELECT id, sender_id, prekey_id, blob FROM messages"
            " WHERE recipient_id=? AND in_flight_at IS NULL ORDER BY timestamp ASC",
            -1, &st.s, nullptr));
        check(sqlite3_bind_text(st.s, 1, recipient_id.c_str(), -1, SQLITE_STATIC));
        while (sqlite3_step(st.s) == SQLITE_ROW) {
            MessageRow row;
            row.id = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
            row.sender_id = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 1));
            row.prekey_id = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 2));
            const void* raw = sqlite3_column_blob(st.s, 3);
            int len = sqlite3_column_bytes(st.s, 3);
            row.blob.assign(static_cast<const uint8_t*>(raw),
                            static_cast<const uint8_t*>(raw) + len);
            rows.push_back(std::move(row));
        }
    }

    if (!rows.empty()) {
        Stmt st;
        check(sqlite3_prepare_v2(
            db_, "UPDATE messages SET in_flight_at=? WHERE recipient_id=? AND in_flight_at IS NULL",
            -1, &st.s, nullptr));
        check(sqlite3_bind_int64(st.s, 1, now));
        check(sqlite3_bind_text(st.s, 2, recipient_id.c_str(), -1, SQLITE_STATIC));
        check(sqlite3_step(st.s));
    }

    exec("COMMIT");
    return rows;
}

std::vector<std::string> Store::sender_ids_for(const std::string& recipient_id,
                                               const std::vector<std::string>& ids)
{
    std::vector<std::string> senders;
    for (const auto& id : ids) {
        Stmt st;
        check(sqlite3_prepare_v2(db_,
                                 "SELECT sender_id FROM messages WHERE id=? AND recipient_id=?", -1,
                                 &st.s, nullptr));
        check(sqlite3_bind_text(st.s, 1, id.c_str(), -1, SQLITE_STATIC));
        check(sqlite3_bind_text(st.s, 2, recipient_id.c_str(), -1, SQLITE_STATIC));
        if (sqlite3_step(st.s) == SQLITE_ROW)
            senders.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0)));
    }
    return senders;
}

void Store::ack_messages(const std::string& recipient_id, const std::vector<std::string>& ids)
{
    for (const auto& id : ids) {
        Stmt st;
        check(sqlite3_prepare_v2(db_, "DELETE FROM messages WHERE id=? AND recipient_id=?", -1,
                                 &st.s, nullptr));
        check(sqlite3_bind_text(st.s, 1, id.c_str(), -1, SQLITE_STATIC));
        check(sqlite3_bind_text(st.s, 2, recipient_id.c_str(), -1, SQLITE_STATIC));
        check(sqlite3_step(st.s));
    }
}

void Store::requeue_stale(int64_t cutoff)
{
    Stmt st;
    check(sqlite3_prepare_v2(
        db_, "UPDATE messages SET in_flight_at=NULL WHERE in_flight_at>0 AND in_flight_at<?", -1,
        &st.s, nullptr));
    check(sqlite3_bind_int64(st.s, 1, cutoff));
    check(sqlite3_step(st.s));
}

int Store::total_messages()
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM messages", -1, &st.s, nullptr));
    check(sqlite3_step(st.s));
    return sqlite3_column_int(st.s, 0);
}

void Store::migrate_inbox(const std::string& old_recipient_id, const std::string& new_recipient_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "UPDATE messages SET recipient_id=? WHERE recipient_id=?", -1,
                             &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, new_recipient_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 2, old_recipient_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
}

void Store::prune_messages(int64_t min_ts)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "DELETE FROM messages WHERE timestamp < ?", -1, &st.s, nullptr));
    check(sqlite3_bind_int64(st.s, 1, min_ts));
    check(sqlite3_step(st.s));
}

// ── rate buckets ──────────────────────────────────────────────────────────────

std::optional<Store::RateRow> Store::get_rate_bucket(const std::string& user_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(
        db_, "SELECT count, window_start, last_used FROM rate_buckets WHERE user_id=?", -1, &st.s,
        nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    int rc = sqlite3_step(st.s);
    if (rc == SQLITE_DONE)
        return std::nullopt;
    check(rc);
    RateRow row;
    row.count = sqlite3_column_int(st.s, 0);
    row.window_start = sqlite3_column_int64(st.s, 1);
    row.last_used = sqlite3_column_int64(st.s, 2);
    return row;
}

void Store::put_rate_bucket(const std::string& user_id, int count, int64_t window_start,
                            int64_t last_used)
{
    Stmt st;
    check(sqlite3_prepare_v2(
        db_,
        "INSERT OR REPLACE INTO rate_buckets(user_id, count, window_start, last_used)"
        " VALUES(?,?,?,?)",
        -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_int(st.s, 2, count));
    check(sqlite3_bind_int64(st.s, 3, window_start));
    check(sqlite3_bind_int64(st.s, 4, last_used));
    check(sqlite3_step(st.s));
}

void Store::remove_rate_bucket(const std::string& user_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "DELETE FROM rate_buckets WHERE user_id=?", -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
}

void Store::prune_rate_buckets(int64_t min_last_used)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "DELETE FROM rate_buckets WHERE last_used > 0 AND last_used < ?",
                             -1, &st.s, nullptr));
    check(sqlite3_bind_int64(st.s, 1, min_last_used));
    check(sqlite3_step(st.s));
}

// ── delivery acks ─────────────────────────────────────────────────────────────

void Store::increment_ack(const std::string& user_id, int n)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_,
                             "INSERT INTO delivery_acks(user_id, count) VALUES(?,?)"
                             " ON CONFLICT(user_id) DO UPDATE SET count = count + excluded.count",
                             -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_int(st.s, 2, n));
    check(sqlite3_step(st.s));
}

int Store::drain_ack(const std::string& user_id)
{
    int count = 0;
    {
        Stmt st;
        check(sqlite3_prepare_v2(db_, "SELECT count FROM delivery_acks WHERE user_id=?", -1, &st.s,
                                 nullptr));
        check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
        if (sqlite3_step(st.s) == SQLITE_ROW)
            count = sqlite3_column_int(st.s, 0);
    }
    if (count > 0) {
        Stmt st;
        check(sqlite3_prepare_v2(db_, "UPDATE delivery_acks SET count=0 WHERE user_id=?", -1, &st.s,
                                 nullptr));
        check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
        check(sqlite3_step(st.s));
    }
    return count;
}

// ── prekeys ───────────────────────────────────────────────────────────────────

void Store::put_prekeys(const std::string& user_id, const std::vector<PrekeyRow>& prekeys)
{
    int64_t now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                           std::chrono::system_clock::now().time_since_epoch())
                                           .count());
    for (const auto& pk : prekeys) {
        Stmt st;
        check(sqlite3_prepare_v2(
            db_,
            "INSERT OR IGNORE INTO prekeys(prekey_id, user_id, pubkey, uploaded_at)"
            " VALUES(?,?,?,?)",
            -1, &st.s, nullptr));
        check(sqlite3_bind_text(st.s, 1, pk.prekey_id.c_str(), -1, SQLITE_STATIC));
        check(sqlite3_bind_text(st.s, 2, user_id.c_str(), -1, SQLITE_STATIC));
        check(sqlite3_bind_blob(st.s, 3, pk.pubkey.data(), static_cast<int>(pk.pubkey.size()),
                                SQLITE_STATIC));
        check(sqlite3_bind_int64(st.s, 4, now));
        check(sqlite3_step(st.s));
    }
}

std::optional<Store::PrekeyRow> Store::pop_prekey(const std::string& user_id)
{
    exec("BEGIN");
    std::optional<PrekeyRow> result;

    {
        Stmt st;
        check(sqlite3_prepare_v2(db_,
                                 "SELECT prekey_id, pubkey FROM prekeys WHERE user_id=? ORDER BY "
                                 "uploaded_at ASC LIMIT 1",
                                 -1, &st.s, nullptr));
        check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
        if (sqlite3_step(st.s) == SQLITE_ROW) {
            PrekeyRow row;
            row.prekey_id = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
            const void* raw = sqlite3_column_blob(st.s, 1);
            int len = sqlite3_column_bytes(st.s, 1);
            row.pubkey.assign(static_cast<const uint8_t*>(raw),
                              static_cast<const uint8_t*>(raw) + len);
            result = std::move(row);
        }
    }

    if (result.has_value()) {
        Stmt st;
        check(sqlite3_prepare_v2(db_, "DELETE FROM prekeys WHERE prekey_id=?", -1, &st.s, nullptr));
        check(sqlite3_bind_text(st.s, 1, result->prekey_id.c_str(), -1, SQLITE_STATIC));
        check(sqlite3_step(st.s));
    }

    exec("COMMIT");
    return result;
}

int Store::prekey_count(const std::string& user_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM prekeys WHERE user_id=?", -1, &st.s,
                             nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
    return sqlite3_column_int(st.s, 0);
}

// ── groups ────────────────────────────────────────────────────────────────────

static int64_t now_ts()
{
    return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count());
}

void Store::create_group(const std::string& group_id, const std::string& owner_id,
                         const std::string& name)
{
    Stmt st;
    check(sqlite3_prepare_v2(
        db_, "INSERT OR IGNORE INTO groups(group_id, owner_id, name, created_at) VALUES(?,?,?,?)",
        -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, group_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 2, owner_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 3, name.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_int64(st.s, 4, now_ts()));
    check(sqlite3_step(st.s));
}

bool Store::group_exists(const std::string& group_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT 1 FROM groups WHERE group_id=?", -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, group_id.c_str(), -1, SQLITE_STATIC));
    return sqlite3_step(st.s) == SQLITE_ROW;
}

std::string Store::group_owner(const std::string& group_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT owner_id FROM groups WHERE group_id=?", -1, &st.s,
                             nullptr));
    check(sqlite3_bind_text(st.s, 1, group_id.c_str(), -1, SQLITE_STATIC));
    if (sqlite3_step(st.s) != SQLITE_ROW)
        return "";
    return reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
}

std::string Store::group_name(const std::string& group_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT name FROM groups WHERE group_id=?", -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, group_id.c_str(), -1, SQLITE_STATIC));
    if (sqlite3_step(st.s) != SQLITE_ROW)
        return "";
    return reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
}

void Store::delete_group(const std::string& group_id)
{
    {
        Stmt st;
        check(sqlite3_prepare_v2(db_, "DELETE FROM group_members WHERE group_id=?", -1, &st.s,
                                 nullptr));
        check(sqlite3_bind_text(st.s, 1, group_id.c_str(), -1, SQLITE_STATIC));
        check(sqlite3_step(st.s));
    }
    Stmt st;
    check(sqlite3_prepare_v2(db_, "DELETE FROM groups WHERE group_id=?", -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, group_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
}

void Store::add_member(const std::string& group_id, const std::string& user_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(
        db_, "INSERT OR IGNORE INTO group_members(group_id, user_id, joined_at) VALUES(?,?,?)", -1,
        &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, group_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 2, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_int64(st.s, 3, now_ts()));
    check(sqlite3_step(st.s));
}

void Store::remove_member(const std::string& group_id, const std::string& user_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "DELETE FROM group_members WHERE group_id=? AND user_id=?", -1,
                             &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, group_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 2, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
}

bool Store::is_member(const std::string& group_id, const std::string& user_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT 1 FROM group_members WHERE group_id=? AND user_id=?", -1,
                             &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, group_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 2, user_id.c_str(), -1, SQLITE_STATIC));
    return sqlite3_step(st.s) == SQLITE_ROW;
}

std::vector<std::string> Store::list_members(const std::string& group_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(
        db_, "SELECT user_id FROM group_members WHERE group_id=? ORDER BY joined_at ASC", -1, &st.s,
        nullptr));
    check(sqlite3_bind_text(st.s, 1, group_id.c_str(), -1, SQLITE_STATIC));
    std::vector<std::string> members;
    while (sqlite3_step(st.s) == SQLITE_ROW)
        members.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0)));
    return members;
}

int Store::member_count(const std::string& group_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM group_members WHERE group_id=?", -1, &st.s,
                             nullptr));
    check(sqlite3_bind_text(st.s, 1, group_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
    return sqlite3_column_int(st.s, 0);
}

void Store::remove_user_from_all_groups(const std::string& user_id)
{
    // Delete groups owned by this user
    {
        Stmt st;
        check(sqlite3_prepare_v2(db_, "SELECT group_id FROM groups WHERE owner_id=?", -1, &st.s,
                                 nullptr));
        check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
        std::vector<std::string> owned;
        while (sqlite3_step(st.s) == SQLITE_ROW)
            owned.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0)));
        for (const auto& gid : owned)
            delete_group(gid);
    }
    // Remove membership from all other groups
    Stmt st;
    check(sqlite3_prepare_v2(db_, "DELETE FROM group_members WHERE user_id=?", -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
}

// ── linked devices ────────────────────────────────────────────────────────────

void Store::link_device(const std::string& primary_id, const std::string& device_id)
{
    int64_t now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                           std::chrono::system_clock::now().time_since_epoch())
                                           .count());
    Stmt st;
    check(sqlite3_prepare_v2(
        db_, "INSERT OR IGNORE INTO linked_devices(primary_id, device_id, linked_at) VALUES(?,?,?)",
        -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, primary_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 2, device_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_int64(st.s, 3, now));
    check(sqlite3_step(st.s));
}

void Store::unlink_device(const std::string& primary_id, const std::string& device_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "DELETE FROM linked_devices WHERE primary_id=? AND device_id=?",
                             -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, primary_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 2, device_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
}

std::vector<std::string> Store::get_linked_devices(const std::string& primary_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(
        db_, "SELECT device_id FROM linked_devices WHERE primary_id=? ORDER BY linked_at ASC", -1,
        &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, primary_id.c_str(), -1, SQLITE_STATIC));
    std::vector<std::string> devices;
    while (sqlite3_step(st.s) == SQLITE_ROW)
        devices.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0)));
    return devices;
}

int Store::device_count(const std::string& primary_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM linked_devices WHERE primary_id=?", -1,
                             &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, primary_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
    return sqlite3_column_int(st.s, 0);
}

void Store::remove_all_links(const std::string& user_id)
{
    Stmt st;
    check(sqlite3_prepare_v2(db_, "DELETE FROM linked_devices WHERE primary_id=? OR device_id=?",
                             -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 2, user_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_step(st.s));
}

// ── bulk ─────────────────────────────────────────────────────────────────────

void Store::clear_all()
{
    exec("DELETE FROM users");
    exec("DELETE FROM sessions");
    exec("DELETE FROM messages");
    exec("DELETE FROM rate_buckets");
    exec("DELETE FROM delivery_acks");
    exec("DELETE FROM prekeys");
    exec("DELETE FROM linked_devices");
    exec("DELETE FROM groups");
    exec("DELETE FROM group_members");
}
