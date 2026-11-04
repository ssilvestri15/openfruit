#include "sdk_runtime_abi.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>

namespace OpenFruit {
namespace {
bool Version(const std::string& text, std::array<unsigned, 3>& out) {
    out = {};
    if (!std::regex_match(text, std::regex(R"([0-9]+(?:\.[0-9]+){0,2})"))) return false;
    std::istringstream stream(text);
    std::string part;
    unsigned i = 0;
    while (std::getline(stream, part, '.')) {
        try { auto n = std::stoul(part); if (n > 65535) return false; out[i++] = static_cast<unsigned>(n); }
        catch (...) { return false; }
    }
    return true;
}
std::string Trim(std::string text) {
    const auto a = text.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    return text.substr(a, text.find_last_not_of(" \t\r\n") - a + 1);
}
}

IosRuntimeArchiveInspection InspectIosRuntimeArchive(
    const std::filesystem::path& archive, const std::filesystem::path& llvm_bin,
    const std::string& deployment_target, const ProcessRunOptions& supplied_options) {
    IosRuntimeArchiveInspection result;
    result.evidence.Set("schema", JsonValue::String("openfruit.ios-runtime-archive-abi.v1"));
    result.evidence.Set("archive", JsonValue::String(archive.generic_string()));
    result.evidence.Set("deployment_target", JsonValue::String(deployment_target));
    result.evidence.Set("selected_architecture", JsonValue::String("arm64"));
    auto fail = [&](std::string message) { result.error = std::move(message); result.evidence.Set("error", JsonValue::String(result.error)); return result; };
    std::array<unsigned, 3> deployment;
    if (!Version(deployment_target, deployment)) return fail("Invalid iOS deployment target");
    std::error_code ec;
    if (!std::filesystem::is_regular_file(archive, ec)) return fail("Runtime archive is not a regular file");
    // Only check the container signature. LLVM remains the archive/Mach-O parser.
    std::ifstream input(archive, std::ios::binary);
    char signature[8]{};
    input.read(signature, sizeof(signature));
    const std::string magic(signature, static_cast<std::size_t>(input.gcount()));
    const bool ar = magic == "!<arch>\n";
    const bool fat = magic.size() >= 4 &&
        (magic.substr(0, 4) == std::string("\xca\xfe\xba\xbe", 4) ||
         magic.substr(0, 4) == std::string("\xbe\xba\xfe\xca", 4) ||
         magic.substr(0, 4) == std::string("\xca\xfe\xba\xbf", 4) ||
         magic.substr(0, 4) == std::string("\xbf\xba\xfe\xca", 4));
    if (!ar && !fat) return fail("Runtime input is not an archive or universal archive");
    const auto tool = llvm_bin / "llvm-objdump.exe";
    if (!std::filesystem::is_regular_file(tool, ec)) return fail("Selected LLVM llvm-objdump.exe is unavailable");
    const auto readobj = llvm_bin / "llvm-readobj.exe";
    if (!std::filesystem::is_regular_file(readobj, ec)) return fail("Selected LLVM llvm-readobj.exe is unavailable");
    auto options = supplied_options;
    if (options.deadline == std::chrono::steady_clock::time_point::max())
        options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    const auto inventory = Win32Process::Run(readobj.wstring(),
        {readobj.wstring(), L"--file-headers", archive.wstring()}, L"", {}, nullptr, nullptr, options);
    result.evidence.Set("inventory_tool", JsonValue::String(readobj.generic_string()));
    if (!inventory.success || inventory.cancelled || inventory.timed_out || inventory.output_truncated ||
        inventory.callback_failed || !Trim(inventory.std_err).empty())
        return fail("LLVM archive member inventory failed or is incomplete: " + inventory.std_err);
    // objdump --macho can silently skip ELF/COFF members. Require the independent
    // LLVM member inventory to account for each selected Mach-O member.
    unsigned inventory_files = 0, formats = 0, subtypes = 0, selected_members = 0, relocatable = 0;
    std::istringstream inventory_lines(inventory.std_out);
    std::string inventory_line;
    while (std::getline(inventory_lines, inventory_line)) {
        inventory_line = Trim(inventory_line);
        if (inventory_line.rfind("File: ", 0) == 0) ++inventory_files;
        if (inventory_line.rfind("Format: ", 0) == 0) {
            ++formats;
            if (inventory_line != "Format: Mach-O arm64") return fail("Archive contains a non-ARM64 Mach-O member: " + inventory_line);
        }
        if (inventory_line.rfind("CpuSubType: ", 0) == 0) {
            ++subtypes;
            if (inventory_line == "CpuSubType: CPU_SUBTYPE_ARM64_ALL (0x0)") ++selected_members;
            else if (inventory_line != "CpuSubType: CPU_SUBTYPE_ARM64E (0x2)") return fail("Archive contains an unsupported ARM64 subtype");
        }
        if (inventory_line == "FileType: Relocatable (0x1)") ++relocatable;
    }
    if (!selected_members || inventory_files != formats || formats != subtypes || subtypes != relocatable)
        return fail("Archive member inventory is incomplete or contains non-relocatable members");
    const auto process = Win32Process::Run(tool.wstring(),
        {tool.wstring(), L"--macho", L"--arch=arm64", L"--private-headers", archive.wstring()},
        L"", {}, nullptr, nullptr, options);
    result.evidence.Set("tool", JsonValue::String(tool.generic_string()));
    result.evidence.Set("exit_code", JsonValue::Number(std::to_string(process.exit_code)));
    if (!process.success || process.cancelled || process.timed_out || process.output_truncated || process.callback_failed)
        return fail("LLVM archive inspection failed, was interrupted, or produced incomplete output: " + process.std_err);
    if (!Trim(process.std_err).empty()) return fail("LLVM reported archive inspection diagnostics: " + process.std_err);

    const std::regex member_header(R"(^.*\([^\r\n]+\)(?: \(architecture [^\r\n]+\))?:$)");
    const std::regex cpu_header(R"(^MH_MAGIC_64\s+ARM64\s+ALL\s+0x[0-9a-fA-F]+\s+OBJECT\s+.*$)");
    const std::regex size_line(R"(^size\s+0x([0-9a-fA-F]+)$)");
    std::istringstream lines(process.std_out);
    std::string line, member, pending_command, minimum, platform;
    bool cpu_ok = false, has_section = false, has_payload = false;
    unsigned headers = 0, platform_commands = 0;
    JsonValue::Array members;
    std::set<std::string> versions;
    std::string parse_error;
    auto finish = [&]() {
        if (member.empty()) return;
        std::string error;
        if (!cpu_ok) error = "Selected member is not an ARM64 ALL Mach-O relocatable object";
        else if (platform_commands > 1) error = "Selected member has conflicting or repeated platform load commands";
        else if (!platform.empty() && platform != "ios") error = "Selected member declares non-iOS platform: " + platform;
        else if (platform.empty() && (!has_section || has_payload)) error = "Nonempty member has no iOS platform/version evidence";
        else if (!platform.empty()) {
            std::array<unsigned, 3> required;
            if (!Version(minimum, required)) error = "Selected iOS member has invalid or absent minimum version";
            else if (required > deployment) error = "Member minimum iOS " + minimum + " exceeds deployment " + deployment_target;
            else versions.insert(minimum);
        }
        JsonValue record = JsonValue::ObjectValue();
        record.Set("member", JsonValue::String(member));
        record.Set("platform", JsonValue::String(platform.empty() ? "unversioned-empty" : platform));
        record.Set("minimum_version", JsonValue::String(minimum));
        record.Set("eligible", JsonValue::Boolean(error.empty()));
        if (!error.empty()) { record.Set("error", JsonValue::String(error)); if (parse_error.empty()) parse_error = member + ": " + error; }
        members.push_back(std::move(record));
    };
    while (std::getline(lines, line)) {
        line = Trim(line);
        if (std::regex_match(line, member_header)) {
            finish(); member = line; cpu_ok = false; has_section = false; has_payload = false;
            platform.clear(); minimum.clear(); pending_command.clear(); headers = 0; platform_commands = 0;
            continue;
        }
        if (member.empty()) continue;
        if (line.rfind("MH_", 0) == 0) { ++headers; cpu_ok = headers == 1 && std::regex_match(line, cpu_header); }
        if (line == "Section") has_section = true;
        std::smatch match;
        if (std::regex_match(line, match, size_line)) {
            if (match[1].str().find_first_not_of('0') != std::string::npos) has_payload = true;
        }
        if (line.rfind("cmd ", 0) == 0) {
            pending_command = line.substr(4);
            if (pending_command == "LC_BUILD_VERSION" || pending_command.rfind("LC_VERSION_MIN_", 0) == 0) ++platform_commands;
            if (pending_command == "LC_VERSION_MIN_IPHONEOS") platform = "ios";
            else if (pending_command == "LC_VERSION_MIN_MACOSX") platform = "macos";
            else if (pending_command == "LC_VERSION_MIN_TVOS") platform = "tvos";
            else if (pending_command == "LC_VERSION_MIN_WATCHOS") platform = "watchos";
        }
        if (pending_command == "LC_BUILD_VERSION" && line.rfind("platform ", 0) == 0) platform = Trim(line.substr(9));
        if (pending_command == "LC_BUILD_VERSION" && line.rfind("minos ", 0) == 0) minimum = Trim(line.substr(6));
        if (pending_command == "LC_VERSION_MIN_IPHONEOS" && line.rfind("version ", 0) == 0) minimum = Trim(line.substr(8));
    }
    finish();
    const auto parsed_members = members.size();
    result.evidence.Set("members", JsonValue::ArrayValue(std::move(members)));
    result.evidence.Set("selected_member_count", JsonValue::Number(std::to_string(selected_members)));
    if (parsed_members != selected_members) return fail("LLVM selected private headers do not cover every inventoried ARM64 member");
    if (member.empty()) return fail("LLVM reported no selected ARM64 archive members");
    if (!parse_error.empty()) return fail(parse_error);
    result.architectures.push_back("arm64");
    result.minimum_versions.assign(versions.begin(), versions.end());
    result.eligible = true;
    result.evidence.Set("eligible", JsonValue::Boolean(true));
    return result;
}
} // namespace OpenFruit
