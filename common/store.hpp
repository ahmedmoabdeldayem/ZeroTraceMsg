#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct sqlite3; // avoid pulling in sqlite3.h in every translation unit

// ─────────────────────────────────────────────────────────────────────────────
// Store — persistent server state backed by SQLite.
//
// All methods assume the caller holds store_mutex (defined in server.cpp).
// Pass path="" for an in-memory database (used by tests via reset_server_state).
// ─────────────────────────────────────────────────────────────────────────────
class Store
{
  public:
    explicit Store(const std::string& path);
    ~Store();

    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;

    // ── users ─────────────────────────────────────────────────────────────────
    void put_user(const std::string& user_id, const std::vector<uint8_t>& pubkey);
    std::optional<std::vector<uint8_t>> get_pubkey(const std::string& user_id);
    bool user_exists(const std::string& user_id);
    int user_count();
    std::vector<std::string> list_users();
    void remove_user(const std::string& user_id);

    // ── sessions ──────────────────────────────────────────────────────────────
    struct SessionRow {
        std::string token;
        int64_t created_at;
    };
    void put_session(const std::string& user_id, const std::string& token, int64_t created_at);
    std::optional<SessionRow> get_session(const std::string& user_id);
    void remove_session(const std::string& user_id);
    int session_count();
    void prune_sessions(int64_t min_created_at);

    // ── prekeys ───────────────────────────────────────────────────────────────
    struct PrekeyRow {
        std::string prekey_id; // hex(SHA-256(pubkey)[0:8])
        std::vector<uint8_t> pubkey;
    };
    // Store a batch of one-time prekeys for a user (server-side public keys only).
    void put_prekeys(const std::string& user_id, const std::vector<PrekeyRow>& prekeys);
    // Atomically pop (return + delete) one prekey for user; returns nullopt if none available.
    std::optional<PrekeyRow> pop_prekey(const std::string& user_id);
    int prekey_count(const std::string& user_id);

    // ── messages ──────────────────────────────────────────────────────────────
    struct MessageRow {
        std::string id;
        std::string sender_id;
        std::string prekey_id; // "_" when encrypted to identity key
        std::vector<uint8_t> blob;
    };
    void enqueue(const std::string& msg_id, const std::string& recipient_id,
                 const std::string& sender_id, const std::vector<uint8_t>& blob,
                 const std::string& prekey_id, int64_t ts);
    int inbox_size(const std::string& recipient_id);
    // Phase 1: return pending messages and mark them in-flight (not yet deleted).
    std::vector<MessageRow> peek_inbox(const std::string& recipient_id, int64_t now);
    // Returns the sender_id for each of the given message IDs that belong to recipient.
    // Used to credit delivery acks before deletion.
    std::vector<std::string> sender_ids_for(const std::string& recipient_id,
                                            const std::vector<std::string>& ids);
    // Phase 2: delete specific messages by ID after the client confirms receipt.
    // Only deletes messages whose recipient_id matches (prevents spoofed ACKs).
    void ack_messages(const std::string& recipient_id, const std::vector<std::string>& ids);
    // Reset in-flight messages older than cutoff back to pending for re-delivery.
    void requeue_stale(int64_t cutoff);
    // Returns all messages for recipient and deletes them atomically (used by DEREGISTER/tests).
    std::vector<MessageRow> drain_inbox(const std::string& recipient_id);
    // Reassign all messages from old_recipient to new_recipient (used by REKEY).
    void migrate_inbox(const std::string& old_recipient_id, const std::string& new_recipient_id);
    int total_messages();
    void prune_messages(int64_t min_ts);

    // ── rate buckets ──────────────────────────────────────────────────────────
    struct RateRow {
        int count;
        int64_t window_start;
        int64_t last_used;
    };
    std::optional<RateRow> get_rate_bucket(const std::string& user_id);
    void put_rate_bucket(const std::string& user_id, int count, int64_t window_start,
                         int64_t last_used);
    void remove_rate_bucket(const std::string& user_id);
    void prune_rate_buckets(int64_t min_last_used);

    // ── delivery acks ─────────────────────────────────────────────────────────
    void increment_ack(const std::string& user_id, int n = 1);
    // Returns current pending ACK count and resets it to zero.
    int drain_ack(const std::string& user_id);

    // ── groups ────────────────────────────────────────────────────────────────
    // Create a group owned by owner_id; group_id must be unique.
    void create_group(const std::string& group_id, const std::string& owner_id,
                      const std::string& name);
    bool group_exists(const std::string& group_id);
    std::string group_owner(const std::string& group_id); // "" if not found
    std::string group_name(const std::string& group_id);
    void delete_group(const std::string& group_id);
    // Membership
    void add_member(const std::string& group_id, const std::string& user_id);
    void remove_member(const std::string& group_id, const std::string& user_id);
    bool is_member(const std::string& group_id, const std::string& user_id);
    std::vector<std::string> list_members(const std::string& group_id);
    int member_count(const std::string& group_id);
    // Remove all groups owned by user_id and memberships where user_id is a member.
    void remove_user_from_all_groups(const std::string& user_id);

    // ── linked devices ────────────────────────────────────────────────────────
    // Link device_id to primary_id so messages reach both inboxes.
    void link_device(const std::string& primary_id, const std::string& device_id);
    void unlink_device(const std::string& primary_id, const std::string& device_id);
    // Returns all device_ids linked to primary_id (does not include primary_id itself).
    std::vector<std::string> get_linked_devices(const std::string& primary_id);
    int device_count(const std::string& primary_id);
    // Remove all links where user_id is primary or device (called on DEREGISTER/REKEY).
    void remove_all_links(const std::string& user_id);

    // ── bulk ──────────────────────────────────────────────────────────────────
    void clear_all();

  private:
    sqlite3* db_{nullptr};
    void exec(const char* sql);
    void check(int rc) const;
};
