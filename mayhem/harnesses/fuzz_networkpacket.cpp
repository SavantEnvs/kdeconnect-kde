// Fuzz KDE Connect's wire-packet parser: every backend (LAN TCP/UDP, Bluetooth, loopback) turns
// newline-delimited JSON from the peer into a NetworkPacket with NetworkPacket::unserialize, then
// pre-pairing code checks it with the DeviceInfo validators and builds a DeviceInfo from it
// (core/backends/lan/lanlinkprovider.cpp udpBroadcastReceived / tcpPacketReceived). This harness
// drives that same public path on the fuzz input and re-serializes the result.
#include <QCoreApplication>
#include <QByteArray>
#include <QSslCertificate>
#include <QStringList>
#include <QLoggingCategory>

#include "core/deviceinfo.h"
#include "core/networkpacket.h"

static QCoreApplication *g_app;

static void ensureApp()
{
    if (g_app)
        return;
    static int qargc = 1;
    static char name[] = "fuzz_networkpacket";
    static char *qargv[] = {name, nullptr};
    QLoggingCategory::setFilterRules(QStringLiteral("*.debug=false\n*.warning=false"));
    g_app = new QCoreApplication(qargc, qargv);
}

// The standalone reproducer driver does not call LLVMFuzzerInitialize, so the app is also
// created lazily on the first input.
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    ensureApp();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // LanLinkProvider reads one line (readLine) per packet and caps identity packets at
    // MAX_IDENTITY_PACKET_SIZE (8192) before unserializing; larger inputs are not reachable.
    if (size > 8192)
        return -1;
    ensureApp();
    QByteArray bytes(reinterpret_cast<const char *>(data), static_cast<qsizetype>(size));

    NetworkPacket np(QString{});
    if (!NetworkPacket::unserialize(bytes, &np))
        return 0;

    bool udp = DeviceInfo::isValidUdpDiscoveryPacket(&np);
    bool ident = DeviceInfo::isValidIdentityPacket(&np);
    bool conn = DeviceInfo::isValidConnectionPacket(&np);
    if (udp || ident || conn) {
        DeviceInfo info = DeviceInfo::FromIdentityPacketAndCert(np, QSslCertificate());
        NetworkPacket back = info.toIdentityPacket();
        (void)back.serialize();
        (void)info.toUdpDiscoveryPacket(np.get<int>(QStringLiteral("tcpPort"), 0)).serialize();
    }
    (void)np.get<QString>(QStringLiteral("deviceId"));
    (void)np.get<QStringList>(QStringLiteral("incomingCapabilities"));
    (void)np.get<qint64>(QStringLiteral("payloadSize"));
    (void)np.payloadTransferInfo();

    QByteArray out = np.serialize();
    NetworkPacket np2(QString{});
    NetworkPacket::unserialize(out, &np2);
    return 0;
}
