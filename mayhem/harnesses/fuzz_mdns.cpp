// Fuzz the vendored mDNS packet parser (core/backends/lan/mdns.h) the way KDE Connect's LAN
// discovery uses it (core/backends/lan/mdnsh_wrapper.cpp): a datagram from the network is read by
// mdns_query_recv / mdns_socket_listen / mdns_discovery_recv, and each record is handed to a
// callback that extracts names and parses PTR/SRV/A/AAAA/TXT records.
// The datagram travels through a local SOCK_DGRAM socketpair, so the library's own recvfrom()
// path is exercised. Input: byte 0 selects the receive entry point, the rest is the datagram.
#include <netinet/in.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include "core/backends/lan/mdns.h"

static int g_socks[2] = {-1, -1};

static int record_cb(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                     uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                     size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                     size_t record_length, void *user_data)
{
    (void)sock; (void)from; (void)addrlen; (void)entry; (void)query_id; (void)rclass; (void)ttl;
    (void)name_length; (void)user_data;
    char namebuf[256];
    char recbuf[256];
    size_t off = name_offset;
    mdns_string_extract(data, size, &off, namebuf, sizeof(namebuf));
    mdns_get_next_substring(data, size, record_offset);
    switch (rtype) {
    case MDNS_RECORDTYPE_PTR:
        mdns_record_parse_ptr(data, size, record_offset, record_length, recbuf, sizeof(recbuf));
        break;
    case MDNS_RECORDTYPE_SRV:
        mdns_record_parse_srv(data, size, record_offset, record_length, recbuf, sizeof(recbuf));
        break;
    case MDNS_RECORDTYPE_A: {
        struct sockaddr_in a;
        mdns_record_parse_a(data, size, record_offset, record_length, &a);
        break;
    }
    case MDNS_RECORDTYPE_AAAA: {
        struct sockaddr_in6 a6;
        mdns_record_parse_aaaa(data, size, record_offset, record_length, &a6);
        break;
    }
    case MDNS_RECORDTYPE_TXT: {
        mdns_record_txt_t txt[24];
        mdns_record_parse_txt(data, size, record_offset, record_length, txt, sizeof(txt) / sizeof(txt[0]));
        break;
    }
    default:
        break;
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;
    if (g_socks[0] < 0) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_socks) != 0)
            return 0;
        int sz = 1 << 20;
        setsockopt(g_socks[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
        setsockopt(g_socks[1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
        fcntl(g_socks[1], F_SETFL, fcntl(g_socks[1], F_GETFL) | O_NONBLOCK);
    }
    uint8_t mode = data[0];
    if (send(g_socks[0], data + 1, size - 1, 0) < 0)
        return 0;
    // Same receive buffer size mdnsh_wrapper.cpp uses.
    static char buffer[2048];
    switch (mode % 3) {
    case 0:
        mdns_query_recv(g_socks[1], buffer, sizeof(buffer), record_cb, nullptr, 0);
        break;
    case 1:
        mdns_socket_listen(g_socks[1], buffer, sizeof(buffer), record_cb, nullptr);
        break;
    default:
        mdns_discovery_recv(g_socks[1], buffer, sizeof(buffer), record_cb, nullptr);
        break;
    }
    // Drain anything left so each input starts from an empty socket.
    while (recv(g_socks[1], buffer, sizeof(buffer), MSG_DONTWAIT) > 0) {
    }
    return 0;
}
