#pragma once

#include <string>

namespace openib {
inline std::string version_string() {
    return std::to_string(OPENIB_VERSION_MAJOR) + "." +
           std::to_string(OPENIB_VERSION_MINOR) + "." +
           std::to_string(OPENIB_VERSION_PATCH);
}
} // namespace openib
