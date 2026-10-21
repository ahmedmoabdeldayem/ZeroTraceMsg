#include "store.hpp"
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
    // Schema migration: add in_flight_at to databases created before this column existed.
    try {
        exec("ALTER TABLE messages ADD COLUMN in_flight_at INTEGER DEFAULT NULL");
    } catch (...) {
        // Column already present — ignore.
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
                    const std::string& sender_id, const std::vector<uint8_t>& blob, int64_t ts)
{
    Stmt st;
    check(sqlite3_prepare_v2(
        db_, "INSERT INTO messages(id, recipient_id, sender_id, blob, timestamp) VALUES(?,?,?,?,?)",
        -1, &st.s, nullptr));
    check(sqlite3_bind_text(st.s, 1, msg_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 2, recipient_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_text(st.s, 3, sender_id.c_str(), -1, SQLITE_STATIC));
    check(sqlite3_bind_blob(st.s, 4, blob.data(), static_cast<int>(blob.size()), SQLITE_STATIC));
    check(sqlite3_bind_int64(st.s, 5, ts));
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
        check(sqlite3_prepare_v2(
            db_,
            "SELECT id, sender_id, blob FROM messages WHERE recipient_id=? ORDER BY timestamp ASC",
            -1, &st.s, nullptr));
        check(sqlite3_bind_text(st.s, 1, recipient_id.c_str(), -1, SQLITE_STATIC));
        while (sqlite3_step(st.s) == SQLITE_ROW) {
            MessageRow row;
            row.id = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
            row.sender_id = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 1));
            const void* raw = sqlite3_column_blob(st.s, 2);
            int len = sqlite3_column_bytes(st.s, 2);
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
            "SELECT id, sender_id, blob FROM messages"
            " WHERE recipient_id=? AND in_flight_at IS NULL ORDER BY timestamp ASC",
            -1, &st.s, nullptr));
        check(sqlite3_bind_text(st.s, 1, recipient_id.c_str(), -1, SQLITE_STATIC));
        while (sqlite3_step(st.s) == SQLITE_ROW) {
            MessageRow row;
            row.id = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
            row.sender_id = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 1));
            const void* raw = sqlite3_column_blob(st.s, 2);
            int len = sqlite3_column_bytes(st.s, 2);
            row.blob.assign(static_cast<const uint8_t*>(raw),
                            static_cast<const uint8_t*>(raw) + len);
            rows.push_back(std::move(row));
        }
    }

    if (!rows.empty()) {
        Stmt st;
        check(sqlite3_prepare_v2(
            db_,
            "UPDATE messages SET in_flight_at=? WHERE recipient_id=? AND in_flight_at IS NULL",
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
        check(sqlite3_prepare_v2(
            db_, "SELECT sender_id FROM messages WHERE id=? AND recipient_id=?", -1, &st.s,
            nullptr));
        check(sqlite3_bind_text(st.s, 1, id.c_str(), -1, SQLITE_STATIC));
        check(sqlite3_bind_text(st.s, 2, recipient_id.c_str(), -1, SQLITE_STATIC));
        if (sqlite3_step(st.s) == SQLITE_ROW)
            senders.emplace_back(
                reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0)));
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

// ── bulk ─────────────────────────────────────────────────────────────────────

void Store::clear_all()
{
    exec("DELETE FROM users");
    exec("DELETE FROM sessions");
    exec("DELETE FROM messages");
    exec("DELETE FROM rate_buckets");
    exec("DELETE FROM delivery_acks");
}
