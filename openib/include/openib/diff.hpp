#pragma once

#include "openib/nib.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace openib {

struct DiffItem {
    std::string category;
    std::string message;
};

struct DiffResult {
    bool equivalent{true};
    std::vector<DiffItem> differences;
};

DiffResult diff_archives(const nib::Archive& left, const nib::Archive& right);
DiffResult diff_nib_files(const std::filesystem::path& left, const std::filesystem::path& right);
std::string format_diff(const DiffResult& result);

} // namespace openib
