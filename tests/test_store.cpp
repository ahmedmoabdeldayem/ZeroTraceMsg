// Tests for common/store — SQLite persistence layer

#include "../common/store.hpp"
#include "test_runner.hpp"
#include <iostream>

int main()
{
    SUITE_INIT("test_store");
    std::cout << "=== store tests ===\n\n";

    // -------------------------------------------------------
    // Users
    // -------------------------------------------------------
    TEST("put_user / get_pubkey round-trip");
    {
        Store s("");
        std::vector<uint8_t> key = {1, 2, 3, 4};
        s.put_user("aabbccdd11223344", key);
        auto got = s.get_pubkey("aabbccdd11223344");
        ASSERT_TRUE(got.has_value());
        ASSERT_EQ(*got, key);
    }

    TEST("get_pubkey returns nullopt for unknown user");
    {
        Store s("");
        ASSERT_TRUE(!s.get_pubkey("deadbeefdeadbeef").has_value());
    }

    TEST("user_exists reflects registration state");
    {
        Store s("");
        ASSERT_TRUE(!s.user_exists("aabb112233445566"));
        s.put_user("aabb112233445566", {0xAB});
        ASSERT_TRUE(s.user_exists("aabb112233445566"));
    }

    TEST("user_count tracks insertions");
    {
        Store s("");
        ASSERT_EQ(s.user_count(), 0);
        s.put_user("1111111111111111", {1});
        s.put_user("2222222222222222", {2});
        ASSERT_EQ(s.user_count(), 2);
    }

    TEST("remove_user deletes user and key");
    {
        Store s("");
        s.put_user("aabbccdd11223344", {1, 2});
        s.remove_user("aabbccdd11223344");
        ASSERT_TRUE(!s.user_exists("aabbccdd11223344"));
        ASSERT_EQ(s.user_count(), 0);
    }

    TEST("put_user with same id replaces pubkey");
    {
        Store s("");
        s.put_user("aabbccdd11223344", {1, 2});
        s.put_user("aabbccdd11223344", {3, 4});
        auto got = s.get_pubkey("aabbccdd11223344");
        ASSERT_TRUE(got.has_value());
        std::vector<uint8_t> expected = {3, 4};
        ASSERT_EQ(*got, expected);
        ASSERT_EQ(s.user_count(), 1); // still only one user
    }

    // -------------------------------------------------------
    // Sessions
    // -------------------------------------------------------
    TEST("put_session / get_session round-trip");
    {
        Store s("");
        s.put_session("aabbccdd11223344", "tok123", 1000);
        auto got = s.get_session("aabbccdd11223344");
        ASSERT_TRUE(got.has_value());
        ASSERT_EQ(got->token, "tok123");
        ASSERT_EQ(got->created_at, (int64_t)1000);
    }

    TEST("get_session returns nullopt for unknown user");
    {
        Store s("");
        ASSERT_TRUE(!s.get_session("deadbeefdeadbeef").has_value());
    }

    TEST("remove_session clears session");
    {
        Store s("");
        s.put_session("aabbccdd11223344", "tok", 0);
        s.remove_session("aabbccdd11223344");
        ASSERT_TRUE(!s.get_session("aabbccdd11223344").has_value());
    }

    TEST("session_count tracks insertions and deletions");
    {
        Store s("");
        s.put_session("1111111111111111", "t1", 0);
        s.put_session("2222222222222222", "t2", 0);
        ASSERT_EQ(s.session_count(), 2);
        s.remove_session("1111111111111111");
        ASSERT_EQ(s.session_count(), 1);
    }

    TEST("prune_sessions removes only expired sessions");
    {
        Store s("");
        s.put_session("1111111111111111", "t1", 100);
        s.put_session("2222222222222222", "t2", 500);
        s.prune_sessions(300); // removes created_at < 300
        ASSERT_TRUE(!s.get_session("1111111111111111").has_value());
        ASSERT_TRUE(s.get_session("2222222222222222").has_value());
    }

    // -------------------------------------------------------
    // Messages
    // -------------------------------------------------------
    TEST("enqueue / inbox_size / drain_inbox round-trip");
    {
        Store s("");
        std::vector<uint8_t> blob = {0xAA, 0xBB};
        s.enqueue("msgid01", "recip0000000001", "sender000000001", blob, 1000);
        ASSERT_EQ(s.inbox_size("recip0000000001"), 1);
        auto msgs = s.drain_inbox("recip0000000001");
        ASSERT_EQ(msgs.size(), (size_t)1);
        ASSERT_EQ(msgs[0].id, "msgid01");
        ASSERT_EQ(msgs[0].sender_id, "sender000000001");
        ASSERT_EQ(msgs[0].blob, blob);
        // inbox must be empty after drain
        ASSERT_EQ(s.inbox_size("recip0000000001"), 0);
    }

    TEST("drain_inbox returns messages ordered by timestamp");
    {
        Store s("");
        s.enqueue("id3", "recip0000000001", "s", {0x03}, 300);
        s.enqueue("id1", "recip0000000001", "s", {0x01}, 100);
        s.enqueue("id2", "recip0000000001", "s", {0x02}, 200);
        auto msgs = s.drain_inbox("recip0000000001");
        ASSERT_EQ(msgs.size(), (size_t)3);
        ASSERT_EQ(msgs[0].id, "id1");
        ASSERT_EQ(msgs[1].id, "id2");
        ASSERT_EQ(msgs[2].id, "id3");
    }

    TEST("drain_inbox on empty inbox returns empty vector");
    {
        Store s("");
        auto msgs = s.drain_inbox("nobody000000001");
        ASSERT_EQ(msgs.size(), (size_t)0);
    }

    TEST("total_messages counts across recipients");
    {
        Store s("");
        s.enqueue("m1", "r1000000000001", "s", {0x01}, 0);
        s.enqueue("m2", "r1000000000001", "s", {0x02}, 0);
        s.enqueue("m3", "r2000000000002", "s", {0x03}, 0);
        ASSERT_EQ(s.total_messages(), 3);
    }

    TEST("prune_messages removes messages older than cutoff");
    {
        Store s("");
        s.enqueue("old", "recip0000000001", "s", {0x01}, 100);
        s.enqueue("new", "recip0000000001", "s", {0x02}, 500);
        s.prune_messages(300); // removes timestamp < 300
        ASSERT_EQ(s.inbox_size("recip0000000001"), 1);
        auto msgs = s.drain_inbox("recip0000000001");
        ASSERT_EQ(msgs[0].id, "new");
    }

    // -------------------------------------------------------
    // Rate buckets
    // -------------------------------------------------------
    TEST("put_rate_bucket / get_rate_bucket round-trip");
    {
        Store s("");
        s.put_rate_bucket("user0000000001", 5, 1000, 1050);
        auto got = s.get_rate_bucket("user0000000001");
        ASSERT_TRUE(got.has_value());
        ASSERT_EQ(got->count, 5);
        ASSERT_EQ(got->window_start, (int64_t)1000);
        ASSERT_EQ(got->last_used, (int64_t)1050);
    }

    TEST("get_rate_bucket returns nullopt for unknown user");
    {
        Store s("");
        ASSERT_TRUE(!s.get_rate_bucket("nobody000000001").has_value());
    }

    TEST("prune_rate_buckets removes stale entries");
    {
        Store s("");
        s.put_rate_bucket("user0000000001", 1, 0, 100);
        s.put_rate_bucket("user0000000002", 1, 0, 500);
        s.prune_rate_buckets(300); // removes last_used > 0 && last_used < 300
        ASSERT_TRUE(!s.get_rate_bucket("user0000000001").has_value());
        ASSERT_TRUE(s.get_rate_bucket("user0000000002").has_value());
    }

    // -------------------------------------------------------
    // Delivery acks
    // -------------------------------------------------------
    TEST("increment_ack / drain_ack round-trip");
    {
        Store s("");
        s.increment_ack("user0000000001", 3);
        ASSERT_EQ(s.drain_ack("user0000000001"), 3);
        ASSERT_EQ(s.drain_ack("user0000000001"), 0); // drained — reset to zero
    }

    TEST("increment_ack accumulates");
    {
        Store s("");
        s.increment_ack("user0000000001");
        s.increment_ack("user0000000001");
        s.increment_ack("user0000000001");
        ASSERT_EQ(s.drain_ack("user0000000001"), 3);
    }

    TEST("drain_ack on unknown user returns 0");
    {
        Store s("");
        ASSERT_EQ(s.drain_ack("nobody000000001"), 0);
    }

    // -------------------------------------------------------
    // Bulk clear
    // -------------------------------------------------------
    TEST("clear_all wipes every table");
    {
        Store s("");
        s.put_user("aabbccdd11223344", {1});
        s.put_session("aabbccdd11223344", "tok", 0);
        s.enqueue("m1", "aabbccdd11223344", "s", {0xAB}, 0);
        s.put_rate_bucket("aabbccdd11223344", 1, 0, 0);
        s.increment_ack("aabbccdd11223344");
        s.clear_all();
        ASSERT_EQ(s.user_count(), 0);
        ASSERT_EQ(s.session_count(), 0);
        ASSERT_EQ(s.total_messages(), 0);
        ASSERT_TRUE(!s.get_rate_bucket("aabbccdd11223344").has_value());
        ASSERT_EQ(s.drain_ack("aabbccdd11223344"), 0);
    }

    SUITE_RESULTS();
}
