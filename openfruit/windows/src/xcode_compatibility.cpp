#include "xcode_compatibility.hpp"
#include "http_transfer.hpp"
#include "win32_process.hpp"
#include <algorithm>
#include <chrono>
#include <regex>
#include <string_view>
namespace OpenFruit {
namespace {
std::vector<unsigned int> Parts(const std::wstring& value) {
    if (value.empty() || value.size() > 32) return {};
    std::vector<unsigned int> parts;
    std::size_t start = 0;
    while (start < value.size()) {
        const auto end = value.find(L'.', start);
        const auto part = value.substr(start, end == std::wstring::npos ? end : end - start);
        if (part.empty() || part.size() > 5 ||
            !std::all_of(part.begin(), part.end(), [](wchar_t c) { return c >= L'0' && c <= L'9'; })) return {};
        parts.push_back(static_cast<unsigned int>(std::stoul(part)));
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    return parts;
}
std::string Plain(std::string value) {
    value = std::regex_replace(value, std::regex("<[^>]*>"), " ");
    for (const auto& [from, to] : {std::pair{"&nbsp;", " "}, {"&#160;", " "},
             {"&ndash;", "-"}, {"&#8211;", "-"}, {"\xE2\x80\x93", "-"}}) {
        std::size_t pos = 0;
        while ((pos = value.find(from, pos)) != std::string::npos) {
            value.replace(pos, std::char_traits<char>::length(from), to);
            pos += std::char_traits<char>::length(to);
        }
    }
    return value;
}
}
bool XcodeCompatibility::LessVersion(const std::wstring& left, const std::wstring& right) {
    const auto a = Parts(left), b = Parts(right);
    if (a.empty() || b.empty()) return false;
    for (std::size_t i = 0; i < std::max(a.size(), b.size()); ++i) {
        const auto av = i < a.size() ? a[i] : 0, bv = i < b.size() ? b[i] : 0;
        if (av != bv) return av < bv;
    }
    return false;
}
bool XcodeCompatibility::Supports(const XcodeIosSupport& release, const std::wstring& deployment) {
    auto min = Parts(release.minimum_deployment), max = Parts(release.maximum_deployment), target = Parts(deployment);
    if (min.empty() || max.empty() || target.empty()) return false;
    if (LessVersion(release.sdk_version, deployment)) return false;
    // Apple's integer upper bounds denote the complete major release family.
    if (max.size() == 1 && target[0] == max[0]) return !LessVersion(deployment, release.minimum_deployment);
    return !LessVersion(deployment, release.minimum_deployment) &&
        !LessVersion(release.maximum_deployment, deployment) &&
        !LessVersion(release.sdk_version, deployment);
}
std::vector<XcodeIosSupport> XcodeCompatibility::ParseAppleHtml(const std::string& html) {
    std::vector<XcodeIosSupport> result;
    if (html.size() > 8 * 1024 * 1024) return result;
    static const std::regex row_re("<tr[^>]*>([\\s\\S]*?)</tr>", std::regex::icase);
    static const std::regex cell_re("<td[^>]*>([\\s\\S]*?)</td>", std::regex::icase);
    static const std::regex xcode_re(R"(^\s*Xcode\s+([0-9]+(?:\.[0-9]+)*)\s*$)");
    static const std::regex sdk_re(R"(\biOS\s+([0-9]+(?:\.[0-9]+)*))");
    static const std::regex deployment_re(R"(\biOS\s+([0-9]+(?:\.[0-9]+)*)\s*-\s*([0-9]+(?:\.[0-9]+)*))");
    static const std::regex swift_re(R"(\bCompiler:\s*Swift\s+([0-9]+(?:\.[0-9]+)*))");
    for (std::sregex_iterator row(html.begin(), html.end(), row_re), end; row != end; ++row) {
        const std::string body = (*row)[1].str();
        std::vector<std::string> cells;
        for (std::sregex_iterator cell(body.begin(), body.end(), cell_re); cell != end; ++cell)
            cells.push_back(Plain((*cell)[1].str()));
        if (cells.size() < 4) continue;
        std::smatch version, sdk, range;
        if (!std::regex_match(cells[0], version, xcode_re) ||
            !std::regex_search(cells[2], sdk, sdk_re) ||
            !std::regex_search(cells[3], range, deployment_re)) continue;
        XcodeIosSupport support{Win32Process::ToWide(version[1].str()),
            Win32Process::ToWide(sdk[1].str()), Win32Process::ToWide(range[1].str()),
            Win32Process::ToWide(range[2].str())};
        std::smatch compiler;
        if (cells.size() > 6 && std::regex_search(cells[6], compiler, swift_re))
            support.swift_compiler_version = Win32Process::ToWide(compiler[1].str());
        if (!Parts(support.xcode_version).empty() && !Parts(support.sdk_version).empty())
            result.push_back(std::move(support));
    }
    return result;
}
std::vector<XcodeIosSupport> XcodeCompatibility::FetchAppleTable() {
    JsonPostRequest request;
    request.url = L"https://developer.apple.com/xcode/system-requirements/";
    request.max_bytes = 8 * 1024 * 1024;
    request.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(45);
    auto response = HttpTransfer::GetText(request);
    if (!response.Succeeded() || response.http_status != 200) return {};
    return ParseAppleHtml(response.body);
}
}
