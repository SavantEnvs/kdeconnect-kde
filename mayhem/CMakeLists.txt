# Harness-side build of upstream's kdeconnectcore library (core/) for fuzzing.
# Upstream's top-level CMakeLists.txt requires Qt >= 6.9 and the whole GUI stack (Kirigami,
# Wayland, PulseAudio, ...); the org base (Debian trixie) ships Qt 6.8.2 / KF6 6.13. The core
# library itself only needs QtNetwork/QtDBus + KF6 CoreAddons/KIO/I18n/Config + OpenSSL, so
# this file compiles core/'s own source list (minus Bluetooth and the Avahi D-Bus discovery,
# both runtime-optional upstream) as a static library and links the harnesses against it.
cmake_minimum_required(VERSION 3.16)
project(kdeconnect_fuzz VERSION 27.03.70 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_AUTOMOC ON)

find_package(ECM 6.3 REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
include(ECMQtDeclareLoggingCategory)
include(ECMSetupVersion)
include(GenerateExportHeader)

find_package(Qt6 6.8 REQUIRED COMPONENTS Core Network DBus)
find_package(KF6 6.3 REQUIRED COMPONENTS CoreAddons KIO I18n Config)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

get_filename_component(KDC ${CMAKE_CURRENT_SOURCE_DIR}/.. ABSOLUTE)

# Avahi D-Bus proxies the LAN backend includes on Linux (upstream generates them in dbusinterfaces/).
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated/systeminterfaces)
set(avahi_SRCS)
foreach(pair "EntryGroup;avahientrygroup" "Server;avahiserver" "ServiceBrowser;avahiservicerbrowser")
    list(GET pair 0 iface)
    list(GET pair 1 base)
    set(xml ${KDC}/dbusinterfaces/systeminterfaces/org.freedesktop.Avahi.${iface}.xml)
    set_source_files_properties(${xml} PROPERTIES NO_NAMESPACE true)
    qt_add_dbus_interface(avahi_SRCS ${xml} generated/systeminterfaces/${base})
endforeach()
ecm_setup_version(${PROJECT_VERSION} VARIABLE_PREFIX KDECONNECT
    VERSION_HEADER ${CMAKE_CURRENT_BINARY_DIR}/kdeconnect-version.h)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
add_library(kdeconnectcore STATIC
    ${KDC}/core/backends/lan/server.cpp
    ${KDC}/core/backends/lan/lanlinkprovider.cpp
    ${KDC}/core/backends/lan/landevicelink.cpp
    ${KDC}/core/backends/lan/compositeuploadjob.cpp
    ${KDC}/core/backends/lan/uploadjob.cpp
    ${KDC}/core/backends/lan/mdnshdiscovery.cpp
    ${KDC}/core/backends/lan/mdnsh_wrapper.cpp
    ${KDC}/core/backends/lan/avahidiscovery.cpp
    ${avahi_SRCS}
    ${KDC}/core/backends/loopback/loopbacklinkprovider.cpp
    ${KDC}/core/backends/loopback/loopbackdevicelink.cpp
    ${KDC}/core/backends/linkprovider.cpp
    ${KDC}/core/backends/devicelink.cpp
    ${KDC}/core/backends/pairinghandler.cpp
    ${KDC}/core/kdeconnectplugin.cpp
    ${KDC}/core/kdeconnectpluginconfig.cpp
    ${KDC}/core/pluginloader.cpp
    ${KDC}/core/kdeconnectconfig.cpp
    ${KDC}/core/dbushelper.cpp
    ${KDC}/core/networkpacket.cpp
    ${KDC}/core/filetransferjob.cpp
    ${KDC}/core/compositefiletransferjob.cpp
    ${KDC}/core/daemon.cpp
    ${KDC}/core/device.cpp
    ${KDC}/core/sslhelper.cpp
    ${KDC}/core/core_debug.cpp
    ${KDC}/core/notificationserverinfo.cpp
    ${KDC}/core/openconfig.cpp
)
ecm_qt_declare_logging_category(kdeconnectcore
    HEADER kdeconnect_debug.h
    IDENTIFIER KDECONNECT_CORE CATEGORY_NAME kdeconnect.core)
generate_export_header(kdeconnectcore EXPORT_FILE_NAME kdeconnectcore_export.h BASE_NAME KDEConnectCore)
target_compile_definitions(kdeconnectcore PUBLIC KDECONNECTCORE_STATIC_DEFINE
    PRIVATE TRANSLATION_DOMAIN="kdeconnect-core")
target_include_directories(kdeconnectcore PUBLIC ${KDC} ${KDC}/core ${KDC}/dbusinterfaces ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(kdeconnectcore
    PUBLIC Qt::Network Qt::DBus KF6::CoreAddons KF6::KIOCore KF6::KIOGui KF6::I18n KF6::ConfigCore OpenSSL::Crypto)

option(KDC_FUZZ "build the fuzz harnesses" ON)
if(KDC_FUZZ)
    foreach(h fuzz_networkpacket)
        add_executable(${h} harnesses/${h}.cpp lsan_off.cc)
        target_link_libraries(${h} PRIVATE kdeconnectcore)
        target_link_options(${h} PRIVATE ${KDC_FUZZ_LINK})
        add_executable(${h}-standalone harnesses/${h}.cpp lsan_off.cc)
        target_link_libraries(${h}-standalone PRIVATE kdeconnectcore ${KDC_STANDALONE_OBJ})
    endforeach()
else()
    add_executable(kdc_selftest selftest/kdc_selftest.cpp)
    target_link_libraries(kdc_selftest PRIVATE kdeconnectcore)
endif()
