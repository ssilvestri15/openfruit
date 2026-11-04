#include "apple_cookies.hpp"
#include "protected_credential_store.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include "text_util.hpp"
#include <algorithm>
#include <charconv>
#include <fstream>
#include <limits>
#include <sstream>
namespace OpenFruit {
namespace {
constexpr std::size_t max_bytes = 128 * 1024;
bool AppleDomain(const std::string& domain) {
    if (domain.empty() || domain.size() > 253 || domain.front() == '.' || domain.back() == '.') return false;
    for (const unsigned char ch : domain)
        if (!(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '.' && ch != '-') return false;
    return domain == "apple.com" || (domain.size() > 10 && domain.ends_with(".apple.com"));
}
bool CookieName(const std::string& value) {
    if (value.empty()) return false;
    for (const unsigned char ch : value)
        if (ch <= 32 || ch >= 127 || std::string("()<>@,;:\\\"/[]?={}").find(ch) != std::string::npos) return false;
    return true;
}
bool CookieValue(const std::string& value) {
    for (const unsigned char ch : value)
        if (ch <= 32 || ch >= 127 || ch == '"' || ch == ',' || ch == ';' || ch == '\\') return false;
    return true;
}
std::string Trim(std::string_view value) {
    const auto first = value.find_first_not_of(" \t");
    if (first == std::string_view::npos) return {};
    const auto last = value.find_last_not_of(" \t");
    return std::string(value.substr(first, last - first + 1));
}
bool DomainMatches(const std::string& host, const std::string& domain) {
    return host == domain || (host.size() > domain.size() && host.ends_with("." + domain));
}
}
bool AppleCookieJar::ImportHttpsResponseCookie(const std::string& origin_host,
    const std::string& origin_path, const std::string& header, std::uint64_t now) {
    const auto host = ToLowerAscii(origin_host);
    if (!AppleDomain(host) || origin_path.empty() || origin_path.front() != '/' ||
        header.empty() || header.size() > 16 * 1024) return false;
    for (const unsigned char ch : header)
        if (ch < 32 || ch >= 127) return false;
    const auto first_end = header.find(';');
    const auto first = Trim(std::string_view(header).substr(0, first_end));
    const auto equals = first.find('=');
    if (equals == std::string::npos) return false;
    AppleCookie cookie;
    cookie.name = first.substr(0, equals);
    cookie.value = first.substr(equals + 1);
    if (!CookieName(cookie.name) || !CookieValue(cookie.value)) return false;
    cookie.domain = host;
    const auto slash = origin_path.rfind('/');
    cookie.path = slash == 0 || slash == std::string::npos ? "/" : origin_path.substr(0, slash);
    bool delete_cookie = false;
    for (auto pos = first_end; pos != std::string::npos;) {
        const auto end = header.find(';', pos + 1);
        const auto attribute = Trim(std::string_view(header).substr(pos + 1,
            end == std::string::npos ? end : end - pos - 1));
        const auto split = attribute.find('=');
        const auto name = ToLowerAscii(Trim(std::string_view(attribute).substr(0, split)));
        const auto value = split == std::string::npos ? std::string{} :
            Trim(std::string_view(attribute).substr(split + 1));
        if (name == "domain") {
            auto domain = ToLowerAscii(value);
            if (domain.starts_with('.')) domain.erase(0, 1);
            if (!AppleDomain(domain) || !DomainMatches(host, domain)) return false;
            cookie.domain = std::move(domain);
            cookie.subdomains = true;
        } else if (name == "path") {
            if (value.empty() || value.front() != '/') return false;
            for (const unsigned char ch : value) if (ch <= 32 || ch >= 127) return false;
            cookie.path = value;
        } else if (name == "max-age") {
            std::int64_t seconds = 0;
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), seconds);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) return false;
            if (seconds <= 0) delete_cookie = true;
            else cookie.expires = now > std::numeric_limits<std::uint64_t>::max() -
                static_cast<std::uint64_t>(seconds) ? std::numeric_limits<std::uint64_t>::max() :
                now + static_cast<std::uint64_t>(seconds);
        } else if (name == "secure") cookie.secure = true;
        else if (name == "httponly") cookie.http_only = true;
        pos = end;
    }
    if (cookie.name.starts_with("__Secure-") && !cookie.secure) return false;
    if (cookie.name.starts_with("__Host-") && (!cookie.secure || cookie.subdomains || cookie.path != "/")) return false;
    auto existing = std::find_if(cookies_.begin(), cookies_.end(), [&](const auto& item) {
        return item.domain == cookie.domain && item.path == cookie.path && item.name == cookie.name;
    });
    if (delete_cookie) {
        if (existing != cookies_.end()) cookies_.erase(existing);
    } else if (existing != cookies_.end()) *existing = std::move(cookie);
    else {
        if (cookies_.size() >= 1024) return false;
        cookies_.push_back(std::move(cookie));
    }
    return true;
}
bool AppleCookieJar::Parse(const std::string& text, AppleCookieJar& output) {
    output.cookies_.clear();
    if (text.empty() || text.size() > max_bytes || text.find('\0') != std::string::npos) return false;
    AppleCookieJar parsed;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        bool http_only = line.starts_with("#HttpOnly_");
        if (http_only) line.erase(0, 10);
        else if (line.front() == '#') continue;
        std::vector<std::string> fields;
        std::size_t start = 0;
        for (;;) {
            const auto end = line.find('\t', start);
            fields.push_back(line.substr(start, end == std::string::npos ? end : end - start));
            if (end == std::string::npos) break;
            start = end + 1;
        }
        if (fields.size() != 7) return false;
        auto domain = ToLowerAscii(fields[0]);
        if (domain.starts_with('.')) domain.erase(0, 1);
        if (!AppleDomain(domain)) continue;
        if ((fields[1] != "TRUE" && fields[1] != "FALSE") ||
            (fields[3] != "TRUE" && fields[3] != "FALSE") || fields[2].empty() || fields[2].front() != '/') return false;
        for (const unsigned char ch : fields[2]) if (ch <= 32 || ch >= 127) return false;
        std::uint64_t expiry = 0;
        const auto converted = std::from_chars(fields[4].data(), fields[4].data() + fields[4].size(), expiry);
        if (converted.ec != std::errc{} || converted.ptr != fields[4].data() + fields[4].size() ||
            !CookieName(fields[5]) || !CookieValue(fields[6])) return false;
        const bool subdomains = fields[1] == "TRUE", secure = fields[3] == "TRUE";
        if (fields[5].starts_with("__Secure-") && !secure) return false;
        if (fields[5].starts_with("__Host-") && (!secure || subdomains || fields[2] != "/")) return false;
        AppleCookie cookie{domain, fields[2], fields[5], fields[6], subdomains, secure, http_only, expiry};
        auto existing = std::find_if(parsed.cookies_.begin(), parsed.cookies_.end(), [&](const auto& item) {
            return item.domain == cookie.domain && item.path == cookie.path && item.name == cookie.name;
        });
        if (existing != parsed.cookies_.end()) *existing = std::move(cookie);
        else parsed.cookies_.push_back(std::move(cookie));
        if (parsed.cookies_.size() > 1024) return false;
    }
    if (parsed.cookies_.empty()) return false;
    output = std::move(parsed);
    return true;
}
bool AppleCookieJar::AddBrowserCookie(AppleCookie cookie) {
    cookie.domain = ToLowerAscii(cookie.domain);
    if (cookie.domain.starts_with('.')) {
        cookie.domain.erase(0, 1);
        cookie.subdomains = true;
    }
    if (!AppleDomain(cookie.domain) || cookie.path.empty() || cookie.path.front() != '/' ||
        !CookieName(cookie.name) || !CookieValue(cookie.value) ||
        (cookie.name.starts_with("__Secure-") && !cookie.secure) ||
        (cookie.name.starts_with("__Host-") && (!cookie.secure || cookie.subdomains || cookie.path != "/"))) return false;
    for (const unsigned char ch : cookie.path) if (ch <= 32 || ch >= 127 || ch == '\t') return false;
    auto existing = std::find_if(cookies_.begin(), cookies_.end(), [&](const auto& item) {
        return item.domain == cookie.domain && item.path == cookie.path && item.name == cookie.name;
    });
    if (existing != cookies_.end()) *existing = std::move(cookie);
    else {
        if (cookies_.size() >= 1024) return false;
        cookies_.push_back(std::move(cookie));
    }
    return true;
}
std::string AppleCookieJar::Serialize() const {
    std::ostringstream text;
    text << "# Netscape HTTP Cookie File\n";
    for (const auto& cookie : cookies_) {
        if (cookie.http_only) text << "#HttpOnly_";
        text << cookie.domain << '\t' << (cookie.subdomains ? "TRUE" : "FALSE") << '\t'
             << cookie.path << '\t' << (cookie.secure ? "TRUE" : "FALSE") << '\t'
             << cookie.expires << '\t' << cookie.name << '\t' << cookie.value << '\n';
    }
    return text.str();
}
std::string AppleCookieJar::ForHttpsRequest(const std::string& requested_host,
    const std::string& requested_path, std::uint64_t now) const {
    const auto host = ToLowerAscii(requested_host);
    const auto path = requested_path.substr(0, requested_path.find_first_of("?#"));
    if (!AppleDomain(host) || path.empty() || path.front() != '/') return {};
    std::vector<const AppleCookie*> matching;
    for (const auto& cookie : cookies_) {
        const bool domain_matches = host == cookie.domain || (cookie.subdomains &&
            host.size() > cookie.domain.size() && host.ends_with("." + cookie.domain));
        const bool path_matches = path.starts_with(cookie.path) && (path.size() == cookie.path.size() ||
            cookie.path.back() == '/' || path[cookie.path.size()] == '/');
        if (domain_matches && path_matches && (!cookie.expires || cookie.expires > now)) matching.push_back(&cookie);
    }
    std::stable_sort(matching.begin(), matching.end(), [](const auto* a, const auto* b) { return a->path.size() > b->path.size(); });
    std::string header;
    for (const auto* cookie : matching) {
        if (!header.empty()) header += "; ";
        header += cookie->name + "=" + cookie->value;
        if (header.size() > 16 * 1024) return {};
    }
    return header;
}
AppleCookieImportResult AppleCookieStore::Import(Secrets& secrets, const std::filesystem::path& source,
    const std::filesystem::path& metadata) {
    OperationSpan span("credentials.apple.cookies.import");
    AppleCookieImportResult result;
    const char* status = "invalid_file";
    std::ifstream input(source, std::ios::binary);
    std::string bytes(max_bytes + 1, '\0');
    if (input && metadata.is_absolute()) {
        input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        bytes.resize(static_cast<std::size_t>(input.gcount()));
        AppleCookieJar jar;
        if (input.bad() || !AppleCookieJar::Parse(bytes, jar)) {
            result.status = AppleCookieImportStatus::InvalidCookies;
            status = "invalid_cookies";
        } else {
            const auto protected_path = metadata.parent_path() / ("apple-cookies-" + NewOperationId() + ".dpapi");
            if (!ProtectedCredentialStore::Write(protected_path, Win32Process::ToWide(jar.Serialize()), CredentialPurpose::AppleCookies)) {
                result.status = AppleCookieImportStatus::ProtectionFailed;
                status = "protection_failed";
            } else {
                Secrets updated = secrets;
                updated.apple_cookies_dpapi_path = protected_path.wstring();
                if (!updated.Save(metadata.wstring())) {
                    std::error_code error;
                    std::filesystem::remove(protected_path, error); // Only the new file owned by this attempt.
                    result.status = AppleCookieImportStatus::PublicationFailed;
                    status = "publication_failed";
                } else {
                    secrets = std::move(updated);
                    result.status = AppleCookieImportStatus::Succeeded;
                    result.count = jar.Count();
                    status = "succeeded";
                }
            }
        }
    }
    SecureZeroMemory(bytes.data(), bytes.size());
    auto data = JsonValue::ObjectValue();
    data.Set("status", JsonValue::String(status));
    data.Set("cookie_count", JsonValue::Number(std::to_string(result.count)));
    data.Set("authentication_verified", JsonValue::Boolean(false));
    span.Complete(std::move(data), result.Succeeded());
    return result;
}
AppleCookieImportResult AppleCookieStore::Protect(Secrets& secrets, const AppleCookieJar& jar,
    const std::filesystem::path& metadata) {
    OperationSpan span("credentials.apple.cookies.protect_browser_session");
    AppleCookieImportResult result;
    if (!metadata.is_absolute() || jar.Count() == 0) {
        result.status = AppleCookieImportStatus::InvalidCookies;
    } else {
        const auto protected_path = metadata.parent_path() / ("apple-cookies-" + NewOperationId() + ".dpapi");
        auto plain = Win32Process::ToWide(jar.Serialize());
        const bool written = ProtectedCredentialStore::Write(protected_path, plain, CredentialPurpose::AppleCookies);
        SecureZeroMemory(plain.data(), plain.size() * sizeof(wchar_t));
        if (!written) result.status = AppleCookieImportStatus::ProtectionFailed;
        else {
            Secrets updated = secrets;
            updated.apple_id.clear(); // Browser cookies do not prove an account identifier.
            updated.apple_session_dpapi_path.clear();
            updated.apple_cookies_dpapi_path = protected_path.wstring();
            if (!updated.Save(metadata.wstring())) {
                std::error_code ec;
                std::filesystem::remove(protected_path, ec);
                result.status = AppleCookieImportStatus::PublicationFailed;
            } else {
                secrets = std::move(updated);
                result.status = AppleCookieImportStatus::Succeeded;
                result.count = jar.Count();
            }
        }
    }
    auto data = JsonValue::ObjectValue();
    data.Set("status", JsonValue::String(result.Succeeded() ? "succeeded" : "failed"));
    data.Set("cookie_count", JsonValue::Number(std::to_string(result.count)));
    span.Complete(std::move(data), result.Succeeded());
    return result;
}
bool AppleCookieStore::Clear(Secrets& secrets, const std::filesystem::path& metadata) {
    OperationSpan span("credentials.apple.cookies.clear");
    bool succeeded = metadata.is_absolute();
    const bool had_reference = !secrets.apple_cookies_dpapi_path.empty();
    if (succeeded && had_reference) {
        Secrets updated = secrets;
        updated.apple_cookies_dpapi_path.clear();
        succeeded = updated.Save(metadata.wstring());
        if (succeeded) secrets = std::move(updated);
    }
    auto data = JsonValue::ObjectValue();
    data.Set("status", JsonValue::String(succeeded ? "succeeded" : "publication_failed"));
    data.Set("had_reference", JsonValue::Boolean(had_reference));
    span.Complete(std::move(data), succeeded);
    return succeeded;
}
bool AppleCookieStore::Load(const Secrets& secrets, AppleCookieJar& jar) {
    jar = AppleCookieJar{};
    std::wstring plain;
    if (secrets.apple_cookies_dpapi_path.empty() || !ProtectedCredentialStore::Read(
        secrets.apple_cookies_dpapi_path, plain, CredentialPurpose::AppleCookies)) return false;
    auto bytes = Win32Process::ToNarrow(plain);
    const bool loaded = AppleCookieJar::Parse(bytes, jar);
    SecureZeroMemory(plain.data(), plain.size() * sizeof(wchar_t));
    SecureZeroMemory(bytes.data(), bytes.size());
    return loaded;
}
}
