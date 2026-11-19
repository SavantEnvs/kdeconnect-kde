// Known-answer tests for the code the fuzz targets exercise, built with the project's normal
// flags: NetworkPacket::unserialize/serialize, the DeviceInfo identity validators, and the mdns.h
// record parser. Prints "PASS <name>" / "FAIL <name>" per case; mayhem/test.sh counts them.
#include <QCoreApplication>
#include <QLoggingCategory>
#include <QSslCertificate>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

#include "core/backends/lan/mdns.h"
#include "core/deviceinfo.h"
#include "core/networkpacket.h"

static int failures = 0;
static void check(const char *name, bool ok)
{
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static const char *ID = "abcdefghijklmnopqrstuvwxyz012345";

static void networkpacket_tests()
{
    QByteArray json = QByteArrayLiteral(
        "{\"id\":1,\"type\":\"kdeconnect.identity\",\"body\":{\"deviceId\":\"abcdefghijklmnopqrstuvwxyz012345\","
        "\"deviceName\":\"My (Phone)!\",\"deviceType\":\"smartphone\",\"protocolVersion\":8,\"tcpPort\":1716,"
        "\"incomingCapabilities\":[\"kdeconnect.ping\"],\"outgoingCapabilities\":[\"kdeconnect.ping\",\"kdeconnect.battery\"]},"
        "\"payloadSize\":42,\"payloadTransferInfo\":{\"port\":1739}}\n");
    NetworkPacket np(QString{});
    check("unserialize_identity", NetworkPacket::unserialize(json, &np));
    check("identity_type", np.type() == QStringLiteral("kdeconnect.identity"));
    check("identity_tcpPort", np.get<int>(QStringLiteral("tcpPort")) == 1716);
    check("identity_payloadSize", np.payloadSize() == 42);
    check("identity_transferInfo", np.payloadTransferInfo().value(QStringLiteral("port")).toInt() == 1739);
    check("valid_identity", DeviceInfo::isValidIdentityPacket(&np));
    check("valid_udp_discovery", DeviceInfo::isValidUdpDiscoveryPacket(&np));
    check("not_connection_packet", !DeviceInfo::isValidConnectionPacket(&np));

    DeviceInfo info = DeviceInfo::FromIdentityPacketAndCert(np, QSslCertificate());
    check("deviceinfo_id", info.id == QLatin1String(ID));
    check("deviceinfo_name_filtered", info.name == QStringLiteral("My Phone"));
    check("deviceinfo_type", info.type == DeviceType::Phone && info.type.toString() == QStringLiteral("phone"));
    check("deviceinfo_protocol", info.protocolVersion == 8);
    check("deviceinfo_caps", info.incomingCapabilities.size() == 1 && info.outgoingCapabilities.size() == 2
                                 && info.outgoingCapabilities.contains(QStringLiteral("kdeconnect.battery")));

    NetworkPacket np2(QString{});
    check("roundtrip_unserialize", NetworkPacket::unserialize(np.serialize(), &np2));
    check("roundtrip_equal", np2.type() == np.type() && np2.body() == np.body());

    NetworkPacket bad(QString{});
    check("reject_invalid_json", !NetworkPacket::unserialize(QByteArrayLiteral("{\"type\":"), &bad));
    check("reject_missing_type", !NetworkPacket::unserialize(QByteArrayLiteral("{\"body\":{}}"), &bad));

    NetworkPacket dirty(QString{});
    NetworkPacket::unserialize(QByteArrayLiteral("{\"type\":\"kdeconnect.ping\",\"body\":{\"deviceId\":\"ab/c-d.e\"}}"), &dirty);
    check("deviceid_dbus_filtered", dirty.get<QString>(QStringLiteral("deviceId")) == QStringLiteral("ab_c_d_e"));
    check("short_deviceid_invalid", !DeviceInfo::isValidUdpDiscoveryPacket(&dirty));
    check("filtername_truncates", DeviceInfo::filterName(QString(40, QLatin1Char('x'))).size() == 32);
}

static int g_ptr_seen = 0;
static char g_ptr_name[256];
static int cb(int, const struct sockaddr *, size_t, mdns_entry_type_t, uint16_t, uint16_t rtype, uint16_t, uint32_t ttl,
              const void *data, size_t size, size_t, size_t, size_t record_offset, size_t record_length, void *)
{
    if (rtype == MDNS_RECORDTYPE_PTR && ttl == 120) {
        mdns_string_t s = mdns_record_parse_ptr(data, size, record_offset, record_length, g_ptr_name, sizeof(g_ptr_name));
        g_ptr_name[s.length] = 0;
        g_ptr_seen++;
    }
    return 0;
}

static void mdns_tests()
{
    // Response: 1 answer, _kdeconnect._udp.local PTR -> abc._kdeconnect._udp.local, TTL 120.
    const unsigned char pkt[] = {
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        11, '_', 'k', 'd', 'e', 'c', 'o', 'n', 'n', 'e', 'c', 't', 4, '_', 'u', 'd', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0,
        0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x06,
        3, 'a', 'b', 'c', 0xc0, 0x0c};
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
        check("mdns_socketpair", false);
        return;
    }
    send(sv[0], pkt, sizeof(pkt), 0);
    char buf[2048];
    size_t n = mdns_query_recv(sv[1], buf, sizeof(buf), cb, nullptr, 0);
    check("mdns_query_recv_count", n == 1 && g_ptr_seen == 1);
    check("mdns_ptr_name", std::strcmp(g_ptr_name, "abc._kdeconnect._udp.local.") == 0);
    close(sv[0]);
    close(sv[1]);
}

int main(int argc, char **argv)
{
    QLoggingCategory::setFilterRules(QStringLiteral("*.debug=false"));
    QCoreApplication app(argc, argv);
    networkpacket_tests();
    mdns_tests();
    return failures ? 1 : 0;
}
