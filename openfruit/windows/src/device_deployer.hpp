#pragma once

#include <string>
#include <vector>

namespace OpenFruit {

struct ConnectedDevice {
    std::string udid;
    std::string name;
    std::string connection_type; // e.g. "USB", "WiFi"
};

class DeviceDeployer {
public:
    static std::vector<ConnectedDevice> ListDevices(const std::wstring& repo_root);

    static bool Deploy(
        const std::wstring& repo_root,
        const std::wstring& signed_ipa_path,
        const std::wstring& udid = L""
    );
};

} // namespace OpenFruit

