#pragma once
#include <botan/tls.h>
#include <string>
#include <sys/socket.h>

// Callback base for blocking BSD socket TLS:
//   tls_emit_data  → writes ciphertext to fd
//   tls_record_received → appends plain text to recv_buf
class SocketTlsCallbacks : public Botan::TLS::Callbacks
{
  public:
    int fd;
    std::string recv_buf;
    bool closed = false;

    explicit SocketTlsCallbacks(int fd) : fd(fd) {}

    void tls_emit_data(std::span<const uint8_t> data) override
    {
        size_t sent = 0;
        while (sent < data.size()) {
            ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
            if (n <= 0) {
                closed = true;
                return;
            }
            sent += static_cast<size_t>(n);
        }
    }

    void tls_record_received(uint64_t, std::span<const uint8_t> data) override
    {
        recv_buf.append(reinterpret_cast<const char*>(data.data()), data.size());
    }

    void tls_alert(Botan::TLS::Alert alert) override
    {
        if (alert.is_fatal())
            closed = true;
    }
};

// Read one newline-delimited line from a TLS channel.
// Drives the handshake transparently — the loop feeds raw bytes from the socket
// into the TLS state machine; once the handshake completes, plain-text records
// start filling recv_buf and we return them line by line.
inline std::string tls_read_line(int fd, Botan::TLS::Channel& tls, SocketTlsCallbacks& cb)
{
    while (true) {
        auto pos = cb.recv_buf.find('\n');
        if (pos != std::string::npos) {
            std::string line = cb.recv_buf.substr(0, pos);
            cb.recv_buf.erase(0, pos + 1);
            return line;
        }
        if (cb.closed)
            return {};
        uint8_t buf[4096];
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
            return {};
        try {
            tls.received_data({buf, static_cast<size_t>(n)});
        } catch (...) {
            return {};
        }
    }
}

// Send one newline-terminated line via TLS.
inline void tls_send_line(Botan::TLS::Channel& tls, const std::string& line)
{
    tls.send(line + "\n");
}
