#include "packager_signer.hpp"
#include "provisioning_identity.hpp"
#include "signing_credential.hpp"
#include "protected_credential_store.hpp"
#include "asset_catalog_compiler.hpp"

#include "native_zip.hpp"
#include "operation_events.hpp"
#include "interface_builder_compiler.hpp"
#include "win32_process.hpp"
#include "tool_paths.hpp"
#include "text_util.hpp"
#include "artifact_store.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

struct PasswordWiper {
    std::wstring& value;
    ~PasswordWiper() {
        if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
    }
};

std::string EscapeXml(
    const std::string& value
) {
    std::string output;
    output.reserve(value.size());

    for (const char c : value) {
        switch (c) {
        case '&':
            output += "&amp;";
            break;
        case '<':
            output += "&lt;";
            break;
        case '>':
            output += "&gt;";
            break;
        case '"':
            output += "&quot;";
            break;
        case '\'':
            output += "&apos;";
            break;
        default:
            output.push_back(c);
            break;
        }
    }

    return output;
}

std::wstring ExtendedWin32Path(const fs::path& input) {
    if (input.empty()) return {};
    fs::path absolute = input;
    if (absolute.is_relative()) {
        std::error_code ec;
        absolute = fs::absolute(input, ec);
        if (ec) absolute = input;
    }
    const std::wstring value = absolute.lexically_normal().wstring();
    if (value.rfind(L"\\\\?\\", 0) == 0) return value;
    if (value.rfind(L"\\\\", 0) == 0) {
        return L"\\\\?\\UNC\\" + value.substr(2);
    }
    return L"\\\\?\\" + value;
}

fs::path ExtendedFsPath(const fs::path& input) {
    return fs::path(ExtendedWin32Path(input));
}

bool FileIsNonEmpty(
    const fs::path& path
) {
    std::error_code ec;

    const fs::path ext = ExtendedFsPath(path);

    return
        fs::exists(ext, ec) &&
        !ec &&
        fs::is_regular_file(ext, ec) &&
        !ec &&
        fs::file_size(ext, ec) > 0 &&
        !ec;
}

bool DecryptDpapiPassword(const fs::path& path, std::wstring& out_password) {
    return ProtectedCredentialStore::Read(path, out_password, CredentialPurpose::SigningPassword);
}
bool SigningOutputFailed(
    const std::string& output
) {
    return
        output.find("Signed Failed!") !=
            std::string::npos ||
        output.find("Invalid mach-o file") !=
            std::string::npos ||
        output.find("Can't find app's Info.plist") !=
            std::string::npos ||
        output.find("Can't parse BundleExecute file") !=
            std::string::npos;
}



bool MakeTreeWritable(const fs::path& root) {
    const auto clear_read_only = [](const fs::path& path) {
        const std::wstring ext = ExtendedWin32Path(path);
        const DWORD attributes = GetFileAttributesW(ext.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) return false;
        if ((attributes & FILE_ATTRIBUTE_READONLY) == 0) return true;
        return SetFileAttributesW(
            ext.c_str(),
            attributes & ~FILE_ATTRIBUTE_READONLY
        ) != FALSE;
    };

    if (!clear_read_only(root)) return false;
    std::error_code ec;
    const fs::path ext_root = ExtendedFsPath(root);
    if (!fs::is_directory(ext_root, ec)) return !ec;
    for (fs::recursive_directory_iterator it(
             ext_root,
             fs::directory_options::skip_permission_denied,
             ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        if (ec) return false;
        if (!clear_read_only(it->path())) return false;
    }
    return true;
}

// zsign writes a new signature into the space of the one it replaces. When
// the new SuperBlob is smaller, the rest of LC_CODE_SIGNATURE still holds
// bytes of the old signature; codesign leaves that tail zeroed. The tail is
// outside both the CodeDirectory's code limit and the SuperBlob, so zeroing
// it changes no hash or signed byte. Returns false only on an I/O failure.
bool ZeroSignatureSlack(const fs::path& bundle, std::size_t& cleaned, bool check_only = false) {
    const auto u32 = [](const std::string& data, std::size_t at, bool big) -> std::uint32_t {
        if (at + 4 > data.size()) return 0;
        const auto* p = reinterpret_cast<const unsigned char*>(data.data() + at);
        return big ? (std::uint32_t(p[0]) << 24 | std::uint32_t(p[1]) << 16 | std::uint32_t(p[2]) << 8 | p[3])
                   : (std::uint32_t(p[3]) << 24 | std::uint32_t(p[2]) << 16 | std::uint32_t(p[1]) << 8 | p[0]);
    };
    // Only the header, the load commands and the signature space of each
    // slice are read; only a signature space that changes is written back.
    const auto read_at = [](std::fstream& file, std::uint64_t at, std::uint64_t length, std::string& data) {
        data.assign(static_cast<std::size_t>(length), '\0');
        file.clear();
        file.seekg(static_cast<std::streamoff>(at));
        return file.read(data.data(), static_cast<std::streamsize>(length)).good();
    };
    struct Rewrite { std::uint64_t at; std::string bytes; };
    const auto clean_slice = [&](std::fstream& file, std::uint64_t base, std::uint64_t size,
                                 std::vector<Rewrite>& rewrites) {
        std::string header;
        if (size < 32 || !read_at(file, base, 32, header)) return false;
        const auto magic = u32(header, 0, false);
        if (magic != 0xfeedfacf && magic != 0xfeedface) return false;
        const std::uint64_t header_size = magic == 0xfeedfacf ? 32 : 28;
        const auto commands = u32(header, 16, false);
        const std::uint64_t commands_size = u32(header, 20, false);
        std::string table;
        if (header_size + commands_size > size || !read_at(file, base + header_size, commands_size, table))
            return false;
        std::uint64_t at = 0;
        bool changed = false;
        for (std::uint32_t i = 0; i < commands && at + 8 <= table.size(); ++i) {
            const auto command = u32(table, at, false), command_size = u32(table, at + 4, false);
            if (command_size < 8) break;
            if (command == 0x1d && command_size >= 16) {
                const std::uint64_t offset = u32(table, at + 8, false), length = u32(table, at + 12, false);
                std::string blob;
                if (offset + 12 <= size && length <= size - offset && length >= 12 &&
                    read_at(file, base + offset, length, blob) && u32(blob, 0, true) == 0xfade0cc0) {
                    const std::uint64_t used = u32(blob, 4, true);
                    bool dirty = false;
                    for (std::uint64_t byte = used; used >= 12 && used < length && byte < length; ++byte)
                        if (blob[byte]) { blob[byte] = 0; dirty = true; }
                    if (dirty) {
                        rewrites.push_back({base + offset + used, blob.substr(static_cast<std::size_t>(used))});
                        changed = true;
                    }
                }
            }
            at += command_size;
        }
        return changed;
    };
    std::error_code ec;
    for (fs::recursive_directory_iterator it(bundle, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) return false;
        if (it->is_symlink(ec) || !it->is_regular_file(ec)) continue;
        const auto file_size = it->file_size(ec);
        if (ec) return false;
        std::fstream file(it->path(), std::ios::binary | std::ios::in);
        if (!file) continue;
        std::string probe;
        if (file_size < 4 || !read_at(file, 0, 4, probe)) continue;
        const auto magic = u32(probe, 0, true);
        const bool thin = magic == 0xcffaedfe || magic == 0xcefaedfe;
        const bool fat = magic == 0xcafebabe || magic == 0xcafebabf;
        if (!thin && !fat) continue;
        std::vector<Rewrite> rewrites;
        bool changed = false;
        if (thin) {
            changed = clean_slice(file, 0, file_size, rewrites);
        } else {
            const bool wide = magic == 0xcafebabf;
            std::string fat_header;
            if (file_size < 8 || !read_at(file, 0, 8, fat_header)) continue;
            const auto slices = u32(fat_header, 4, true);
            // A Java class file shares the fat magic; its version is never a small slice count.
            if (slices == 0 || slices > 32) continue;
            const std::uint64_t entry_size = wide ? 32 : 20;
            std::string arches;
            if (8 + slices * entry_size > file_size || !read_at(file, 8, slices * entry_size, arches)) continue;
            for (std::uint32_t i = 0; i < slices; ++i) {
                const std::size_t entry = i * entry_size;
                const std::uint64_t offset = wide ? (std::uint64_t(u32(arches, entry + 8, true)) << 32 | u32(arches, entry + 12, true))
                                                  : u32(arches, entry + 8, true);
                const std::uint64_t size = wide ? (std::uint64_t(u32(arches, entry + 16, true)) << 32 | u32(arches, entry + 20, true))
                                                : u32(arches, entry + 12, true);
                if (offset > file_size || size > file_size - offset) continue;
                changed = clean_slice(file, offset, size, rewrites) || changed;
            }
        }
        if (!changed) continue;
        ++cleaned;
        if (check_only) continue;
        file.close();
        std::fstream output(it->path(), std::ios::binary | std::ios::in | std::ios::out);
        for (const auto& rewrite : rewrites) {
            output.seekp(static_cast<std::streamoff>(rewrite.at));
            output.write(rewrite.bytes.data(), static_cast<std::streamsize>(rewrite.bytes.size()));
        }
        output.flush();
        if (!output) return false;
    }
    return !ec;
}

} // namespace

bool PackagerSigner::IsDynamicMachOBinary(const fs::path& binary_path) {
    std::ifstream is(binary_path, std::ios::binary);
    if (!is) return false;

    auto read_u32_be = [](const uint8_t* p) -> uint32_t {
        return (static_cast<uint32_t>(p[0]) << 24) |
               (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8)  |
               static_cast<uint32_t>(p[3]);
    };

    auto read_u32_le = [](const uint8_t* p) -> uint32_t {
        return static_cast<uint32_t>(p[0]) |
               (static_cast<uint32_t>(p[1]) << 8)  |
               (static_cast<uint32_t>(p[2]) << 16) |
               (static_cast<uint32_t>(p[3]) << 24);
    };

    auto read_u64_be = [](const uint8_t* p) -> uint64_t {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (v << 8) | p[i];
        }
        return v;
    };

    auto check_mach_header = [&](uint64_t offset) -> bool {
        is.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!is) return false;
        uint8_t hdr[16];
        if (!is.read(reinterpret_cast<char*>(hdr), sizeof(hdr))) return false;

        const uint32_t magic_le = read_u32_le(hdr);
        const uint32_t magic_be = read_u32_be(hdr);

        if (magic_le == 0xfeedface || magic_le == 0xfeedfacf) {
            return read_u32_le(hdr + 12) == 0x6; // MH_DYLIB
        }
        if (magic_be == 0xfeedface || magic_be == 0xfeedfacf) {
            return read_u32_be(hdr + 12) == 0x6; // MH_DYLIB
        }
        return false;
    };

    uint8_t initial[8];
    if (!is.read(reinterpret_cast<char*>(initial), sizeof(initial))) return false;

    const uint32_t magic_be = read_u32_be(initial);
    const uint32_t magic_le = read_u32_le(initial);

    // Fat Universal Binary
    if (magic_be == 0xcafebabe || magic_le == 0xcafebabe) {
        const bool is_be = (magic_be == 0xcafebabe);
        const uint32_t nfat_arch = is_be ? read_u32_be(initial + 4) : read_u32_le(initial + 4);
        for (uint32_t i = 0; i < nfat_arch && i < 16; ++i) {
            uint8_t arch[20];
            is.seekg(8 + i * 20, std::ios::beg);
            if (!is.read(reinterpret_cast<char*>(arch), sizeof(arch))) break;
            const uint32_t slice_offset = is_be ? read_u32_be(arch + 8) : read_u32_le(arch + 8);
            if (check_mach_header(slice_offset)) return true;
        }
        return false;
    } else if (magic_be == 0xcafebabf || magic_le == 0xcafebabf) {
        const bool is_be = (magic_be == 0xcafebabf);
        const uint32_t nfat_arch = is_be ? read_u32_be(initial + 4) : read_u32_le(initial + 4);
        for (uint32_t i = 0; i < nfat_arch && i < 16; ++i) {
            uint8_t arch64[32];
            is.seekg(8 + i * 32, std::ios::beg);
            if (!is.read(reinterpret_cast<char*>(arch64), sizeof(arch64))) break;
            const uint64_t slice_offset64 = is_be ? read_u64_be(arch64 + 8) : read_u32_le(arch64 + 8);
            if (check_mach_header(slice_offset64)) return true;
        }
        return false;
    }

    // Direct Thin Mach-O
    return check_mach_header(0);
}

bool PackagerSigner::IsDynamicFramework(
    const fs::path& repo_root,
    const fs::path& framework
) {
    fs::path binary = framework / framework.stem();
    if (!FileIsNonEmpty(binary)) {
        const fs::path plist = framework / "Info.plist";
        if (fs::exists(plist)) {
            std::ifstream plist_in(plist);
            std::string line;
            while (std::getline(plist_in, line)) {
                if (line.find("CFBundleExecutable") != std::string::npos) {
                    if (std::getline(plist_in, line)) {
                        const auto start = line.find("<string>");
                        const auto end = line.find("</string>");
                        if (start != std::string::npos && end != std::string::npos && end > start + 8) {
                            binary = framework / line.substr(start + 8, end - start - 8);
                            break;
                        }
                    }
                }
            }
        }
    }

    if (!FileIsNonEmpty(binary)) {
        return false;
    }

    return IsDynamicMachOBinary(binary);
}



bool PackagerSigner::GenerateInfoPlist(
    const std::wstring& output_file,
    const PackagingSpec& spec
) {
    const std::wstring effective_product_name_w =
        spec.product_name.empty() ? spec.app_name : spec.product_name;
    const std::wstring effective_target_name_w =
        spec.target_name.empty()
            ? (spec.app_name.empty() ? effective_product_name_w : spec.app_name)
            : spec.target_name;
    const std::wstring effective_executable_name_w =
        !spec.executable_name.empty()
            ? spec.executable_name
            : effective_product_name_w;

    const auto c99_identifier = [](std::string value) {
        for (char& c : value) {
            const unsigned char u = static_cast<unsigned char>(c);
            const bool ascii_letter =
                (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z');
            const bool ascii_digit = u >= '0' && u <= '9';
            if (!ascii_letter && !ascii_digit && c != '_') {
                c = '_';
            }
        }
        if (value.empty()) return std::string("_");
        if (value.front() >= '0' && value.front() <= '9') {
            value.insert(value.begin(), '_');
        }
        return value;
    };

    const std::string app_name =
        EscapeXml(
            Win32Process::ToNarrow(
                effective_product_name_w
            )
        );

    const std::string executable_name =
        EscapeXml(
            Win32Process::ToNarrow(
                effective_executable_name_w
            )
        );

    const std::string target_name =
        EscapeXml(
            Win32Process::ToNarrow(
                effective_target_name_w
            )
        );

    const std::string module_name =
        EscapeXml(
            spec.module_name.empty()
                ? c99_identifier(Win32Process::ToNarrow(effective_product_name_w))
                : Win32Process::ToNarrow(spec.module_name)
        );

    const std::string bundle_id =
        EscapeXml(
            Win32Process::ToNarrow(
                spec.bundle_id
            )
        );

    const std::string display_name =
        EscapeXml(
            Win32Process::ToNarrow(
                spec.display_name.empty()
                    ? effective_product_name_w
                    : spec.display_name
            )
        );

    const std::string version =
        EscapeXml(
            Win32Process::ToNarrow(
                spec.version.empty()
                    ? L"1.0.0"
                    : spec.version
            )
        );

    const std::string build_version =
        EscapeXml(
            Win32Process::ToNarrow(
                spec.build_version.empty()
                    ? L"1"
                    : spec.build_version
            )
        );

    const std::string minimum =
        EscapeXml(
            Win32Process::ToNarrow(
                spec.minimum_os_version.empty()
                    ? L"18.0"
                    : spec.minimum_os_version
            )
        );

    const std::string icon_name =
        EscapeXml(
            Win32Process::ToNarrow(
                spec.app_icon_name.empty()
                    ? L"AppIcon"
                    : spec.app_icon_name
            )
        );

    std::string plist;

    if (!spec.info_plist_path.empty() &&
        fs::exists(spec.info_plist_path)) {

        std::ifstream input(
            spec.info_plist_path,
            std::ios::binary
        );

        if (input) {
            std::string raw_content(
                (std::istreambuf_iterator<char>(input)),
                std::istreambuf_iterator<char>()
            );

            auto expand_var = [&](const std::string& var_name, const std::string& replacement) {
                for (const std::string& pattern : {"$(" + var_name + ")", "${" + var_name + "}"}) {
                    size_t pos = 0;
                    while ((pos = raw_content.find(pattern, pos)) != std::string::npos) {
                        raw_content.replace(pos, pattern.length(), replacement);
                        pos += replacement.length();
                    }
                }
            };

            expand_var("PRODUCT_NAME:c99extidentifier", module_name);
            expand_var(
                "TARGET_NAME:c99extidentifier",
                EscapeXml(c99_identifier(Win32Process::ToNarrow(effective_target_name_w)))
            );
            expand_var("PRODUCT_MODULE_NAME", module_name);
            expand_var("EXECUTABLE_NAME", executable_name);
            expand_var("PRODUCT_BUNDLE_IDENTIFIER", bundle_id);
            expand_var("PRODUCT_NAME", app_name);
            expand_var("PRODUCT_BUNDLE_PACKAGE_TYPE", "APPL");
            expand_var("MARKETING_VERSION", version);
            expand_var("CURRENT_PROJECT_VERSION", build_version);
            expand_var("DEVELOPMENT_LANGUAGE", "en");
            expand_var("TARGET_NAME", target_name);
            for (const auto& [k, v] : spec.build_settings) {
                expand_var(
                    Win32Process::ToNarrow(k),
                    EscapeXml(Win32Process::ToNarrow(v))
                );
            }

            plist = std::move(raw_content);
        }
    }

    if (plist.empty()) {
        plist =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\">\n"
            "<dict>\n"
            "    <key>CFBundleDevelopmentRegion</key>\n"
            "    <string>en</string>\n"
            "    <key>CFBundleDisplayName</key>\n"
            "    <string>" + display_name + "</string>\n"
            "    <key>CFBundleExecutable</key>\n"
            "    <string>" + executable_name + "</string>\n"
            "    <key>CFBundleIdentifier</key>\n"
            "    <string>" + bundle_id + "</string>\n"
            "    <key>CFBundleInfoDictionaryVersion</key>\n"
            "    <string>6.0</string>\n"
            "    <key>CFBundleName</key>\n"
            "    <string>" + app_name + "</string>\n"
            "    <key>CFBundlePackageType</key>\n"
            "    <string>APPL</string>\n"
            "    <key>CFBundleShortVersionString</key>\n"
            "    <string>" + version + "</string>\n"
            "    <key>CFBundleVersion</key>\n"
            "    <string>" + build_version + "</string>\n"
            "    <key>LSRequiresIPhoneOS</key>\n"
            "    <true/>\n"
            "    <key>MinimumOSVersion</key>\n"
            "    <string>" + minimum + "</string>\n"
            "    <key>UIDeviceFamily</key>\n"
            "    <array>\n"
            "        <integer>1</integer>\n"
            "        <integer>2</integer>\n"
            "    </array>\n"
            "    <key>UILaunchScreen</key>\n"
            "    <dict/>\n"
            "</dict>\n"
            "</plist>\n";
    }

    size_t last_dict_pos = plist.rfind("</dict>");
    if (last_dict_pos != std::string::npos) {
        std::string additions;

        auto has_key = [&](const std::string& key) {
            return plist.find("<key>" + key + "</key>") != std::string::npos;
        };

        if (!has_key("CFBundleDisplayName") && !display_name.empty()) {
            additions += "    <key>CFBundleDisplayName</key>\n    <string>" + display_name + "</string>\n";
        }
        if (!has_key("CFBundleExecutable")) {
            additions += "    <key>CFBundleExecutable</key>\n    <string>" + executable_name + "</string>\n";
        }
        if (!has_key("CFBundleIdentifier")) {
            additions += "    <key>CFBundleIdentifier</key>\n    <string>" + bundle_id + "</string>\n";
        }
        if (!has_key("CFBundleName")) {
            additions += "    <key>CFBundleName</key>\n    <string>" + app_name + "</string>\n";
        }
        if (!has_key("CFBundlePackageType")) {
            additions += "    <key>CFBundlePackageType</key>\n    <string>APPL</string>\n";
        }
        if (!has_key("CFBundleShortVersionString")) {
            additions += "    <key>CFBundleShortVersionString</key>\n    <string>" + version + "</string>\n";
        }
        if (!has_key("CFBundleVersion")) {
            additions += "    <key>CFBundleVersion</key>\n    <string>" + build_version + "</string>\n";
        }
        if (!has_key("MinimumOSVersion")) {
            additions += "    <key>MinimumOSVersion</key>\n    <string>" + minimum + "</string>\n";
        }
        if (!has_key("UIDeviceFamily")) {
            additions += "    <key>UIDeviceFamily</key>\n    <array>\n        <integer>1</integer>\n        <integer>2</integer>\n    </array>\n";
        }
        if (!has_key("LSRequiresIPhoneOS")) {
            additions += "    <key>LSRequiresIPhoneOS</key>\n    <true/>\n";
        }
        if (!has_key("UILaunchScreen") && !has_key("UILaunchStoryboardName")) {
            additions += "    <key>UILaunchScreen</key>\n    <dict/>\n";
        }

        if (!has_key("CFBundleIcons")) {
            additions += "    <key>CFBundleIcons</key>\n"
                         "    <dict>\n"
                         "        <key>CFBundlePrimaryIcon</key>\n"
                         "        <dict>\n"
                         "            <key>CFBundleIconFiles</key>\n"
                         "            <array>\n"
                         "                <string>AppIcon60x60</string>\n"
                         "                <string>AppIcon</string>\n";
            if (icon_name != "AppIcon") {
                additions += "                <string>" + icon_name + "60x60</string>\n"
                             "                <string>" + icon_name + "</string>\n";
            }
            additions += "            </array>\n"
                         "            <key>CFBundleIconName</key>\n"
                         "            <string>" + icon_name + "</string>\n"
                         "        </dict>\n"
                         "    </dict>\n";
        }

        if (!has_key("CFBundleIcons~ipad")) {
            additions += "    <key>CFBundleIcons~ipad</key>\n"
                         "    <dict>\n"
                         "        <key>CFBundlePrimaryIcon</key>\n"
                         "        <dict>\n"
                         "            <key>CFBundleIconFiles</key>\n"
                         "            <array>\n"
                         "                <string>AppIcon60x60</string>\n"
                         "                <string>AppIcon76x76</string>\n"
                         "                <string>AppIcon</string>\n";
            if (icon_name != "AppIcon") {
                additions += "                <string>" + icon_name + "60x60</string>\n"
                             "                <string>" + icon_name + "76x76</string>\n"
                             "                <string>" + icon_name + "</string>\n";
            }
            additions += "            </array>\n"
                         "            <key>CFBundleIconName</key>\n"
                         "            <string>" + icon_name + "</string>\n"
                         "        </dict>\n"
                         "    </dict>\n";
        }

        if (!has_key("CFBundleIconFiles")) {
            additions += "    <key>CFBundleIconFiles</key>\n"
                         "    <array>\n"
                         "        <string>AppIcon60x60</string>\n"
                         "        <string>AppIcon76x76</string>\n"
                         "        <string>AppIcon</string>\n";
            if (icon_name != "AppIcon") {
                additions += "        <string>" + icon_name + "60x60</string>\n"
                             "        <string>" + icon_name + "</string>\n";
            }
            additions += "    </array>\n";
        }

        if (!has_key("CFBundleIconName")) {
            additions += "    <key>CFBundleIconName</key>\n"
                         "    <string>" + icon_name + "</string>\n";
        }



        if (!additions.empty()) {
            plist.insert(last_dict_pos, additions);
        }
    }

    const fs::path path(
        output_file
    );

    std::error_code ec;

    fs::create_directories(
        path.parent_path(),
        ec
    );

    if (ec) {
        return false;
    }

    std::ofstream output(
        path,
        std::ios::binary |
        std::ios::trunc
    );

    if (!output) {
        return false;
    }

    output.write(
        plist.data(),
        static_cast<std::streamsize>(
            plist.size()
        )
    );

    output.flush();

    return
        output.good() &&
        FileIsNonEmpty(path);
}

bool PackagerSigner::CreateIpaArchive(
    const std::wstring& payload_dir,
    const std::wstring& output_ipa
) {
    return NativeZipWriter::
        CreateFromDirectory(
            fs::path(payload_dir),
            fs::path(output_ipa)
        );
}

void PackagerSigner::ApplyDependencyProducts(PackagingSpec& spec, const PackageBuildResult& products) {
    const auto append_unique = [](auto& destination, const auto& values) {
        for (const auto& value : values)
            if (std::find(destination.begin(), destination.end(), value) == destination.end()) destination.push_back(value);
    };
    append_unique(spec.resource_bundles, products.resource_bundles);
    append_unique(spec.embedded_frameworks, products.frameworks);
    append_unique(spec.embedded_frameworks, products.linked_frameworks);
    append_unique(spec.embedded_dynamic_libraries, products.dynamic_libraries);
    spec.signing_products.insert(spec.signing_products.end(), products.signing_products.begin(), products.signing_products.end());
}

PackagingResult
PackagerSigner::PackageUnsigned(const std::wstring& repo_root,
    const AppBuildResult& build_result, const PackagingSpec& spec) {
    return Package(repo_root, build_result, spec, false);
}

PackagingResult PackagerSigner::PackageAndSign(const std::wstring& repo_root,
    const AppBuildResult& build_result, const PackagingSpec& spec) {
    return Package(repo_root, build_result, spec, true);
}

PackagingResult PackagerSigner::Package(
    const std::wstring& repo_root,
    const AppBuildResult& build_result,
    const PackagingSpec& spec,
    bool sign_requested
) {
    PackagingResult result;

    const fs::path root(
        repo_root
    );

    const fs::path build_root(
        sign_requested ? fs::path(build_result.build_root) :
            fs::path(build_result.build_root) / ("unsigned-package-" + NewOperationId())
    );

    const std::wstring effective_product_name =
        spec.product_name.empty() ? spec.app_name : spec.product_name;

    const fs::path payload =
        build_root /
        "Payload";

    const fs::path app =
        payload /
        (effective_product_name + L".app");

    result.app_bundle_path =
        app.wstring();

    result.unsigned_ipa_path =
        (
            fs::path(build_result.build_root) /
            (effective_product_name +
             L"-unsigned.ipa")
        ).wstring();

    result.signed_ipa_path =
        (
            build_root /
            (effective_product_name +
             L"-signed.ipa")
        ).wstring();

    if (!build_result.success ||
        !FileIsNonEmpty(
            fs::path(
                build_result.executable_path
            ))) {

        std::cerr
            << "OPENFRUIT v4: linked executable is missing; packaging aborted."
            << std::endl;

        return result;
    }

    std::error_code ec;

    if (!sign_requested) {
        fs::create_directories(build_root.parent_path(), ec);
        if (ec || !fs::create_directory(build_root, ec) || ec) return result;
    }
    fs::create_directories(
        app,
        ec
    );

    if (ec) {
        return result;
    }

    if (!sign_requested) {
        const fs::path produced_bundle(build_result.product_path);
        if (!produced_bundle.empty()) {
            if (!fs::is_directory(produced_bundle, ec) || ec) return result;
            fs::copy(produced_bundle, app, fs::copy_options::recursive |
                fs::copy_options::overwrite_existing, ec);
        } else {
            const std::wstring effective_executable_name =
                !spec.executable_name.empty()
                    ? spec.executable_name
                    : effective_product_name;
            fs::copy_file(fs::path(build_result.executable_path), app / effective_executable_name,
                fs::copy_options::overwrite_existing, ec);
        }
        if (ec) return result;
    }

    if (sign_requested) fs::remove(
        fs::path(
            result.signed_ipa_path
        ),
        ec
    );

    ec.clear();

    const fs::path plist =
        app /
        "Info.plist";

    if (!GenerateInfoPlist(
            plist.wstring(),
            spec)) {

        std::cerr
            << "OPENFRUIT v4: failed to generate Info.plist."
            << std::endl;

        return result;
    }

    std::cout
        << "OPENFRUIT: Info.plist ready: "
        << plist.string()
        << std::endl;

    {
        std::ofstream pkg(
            app /
            "PkgInfo",
            std::ios::binary |
            std::ios::trunc
        );

        if (!pkg) {
            return result;
        }

        pkg.write(
            "APPL????",
            8
        );
    }

    if (!spec.icon_path.empty() &&
        fs::exists(spec.icon_path)) {

        const std::vector<std::string> icon_filenames = {
            "AppIcon.png",
            "AppIcon@2x.png",
            "AppIcon@3x.png",
            "AppIcon60x60@2x.png",
            "AppIcon60x60@3x.png",
            "AppIcon76x76@2x~ipad.png",
            "AppIcon76x76@2x.png",
            fs::path(spec.icon_path).filename().string()
        };

        for (const auto& target_name : icon_filenames) {
            fs::copy_file(
                spec.icon_path,
                app / target_name,
                fs::copy_options::overwrite_existing,
                ec
            );
            ec.clear();
        }

        if (!spec.app_icon_name.empty()) {
            const std::string custom_name =
                Win32Process::ToNarrow(spec.app_icon_name);
            const std::vector<std::string> custom_filenames = {
                custom_name + ".png",
                custom_name + "@2x.png",
                custom_name + "@3x.png",
                custom_name + "60x60@2x.png",
                custom_name + "60x60@3x.png",
                custom_name + "76x76@2x~ipad.png"
            };
            for (const auto& target_name : custom_filenames) {
                fs::copy_file(
                    spec.icon_path,
                    app / target_name,
                    fs::copy_options::overwrite_existing,
                    ec
                );
                ec.clear();
            }
        }
    }

    std::vector<std::pair<fs::path, SigningProduct>> extension_signing;
    for (const auto& bundle :
         spec.resource_bundles) {

        const fs::path source(
            bundle
        );

        if (!fs::exists(ExtendedFsPath(source))) {
            if (source.extension() == ".appex") {
                std::cerr << "OPENFRUIT signing preflight: declared extension product is missing.\n";
                return result;
            }
            continue;
        }
        const SigningProduct* signing = nullptr;
        if (sign_requested && source.extension() == ".appex") {
            for (const auto& candidate : spec.signing_products) {
                std::error_code match_error;
                if (!candidate.product_path.empty() && fs::equivalent(source, fs::path(candidate.product_path), match_error)) {
                    if (signing) {
                        std::cerr << "OPENFRUIT signing preflight: ambiguous extension signing metadata.\n";
                        return result;
                    }
                    signing = &candidate;
                }
            }
            if (!signing) {
                std::cerr << "OPENFRUIT signing preflight: extension target signing metadata is missing.\n";
                return result;
            }
        }

        const fs::path destination =
            (source.extension() == ".appex")
                ? (app / "PlugIns" / source.filename())
                : (app / source.filename());

        if (signing) {
            for (const auto& [existing, metadata] : extension_signing) {
                std::error_code collision_error;
                if (fs::equivalent(existing, destination, collision_error)) {
                    std::cerr << "OPENFRUIT signing preflight: extension products collide at the same destination.\n";
                    return result;
                }
            }
        }

        if (source.extension() == ".appex") {
            fs::create_directories(ExtendedFsPath(app / "PlugIns"), ec);
            ec.clear();
        }

        fs::remove_all(
            ExtendedFsPath(destination),
            ec
        );

        ec.clear();

        fs::copy(
            ExtendedFsPath(source),
            ExtendedFsPath(destination),
            fs::copy_options::recursive |
                fs::copy_options::
                    overwrite_existing,
            ec
        );

        if (ec) {
            std::cerr
                << "OPENFRUIT v4: failed to copy resource bundle: "
                << source.string()
                << std::endl;

            return result;
        }

        // AppBuilder already evaluated this target's Info.plist. Never invent
        // an extension ID from the container ID or rewrite its target settings.
        if (signing) extension_signing.emplace_back(destination, *signing);
    }

    for (const auto& resource_path :
         spec.resource_files) {

        const fs::path source(
            resource_path
        );

        if (!fs::exists(ExtendedFsPath(source))) {
            continue;
        }

        fs::path destination;
        const fs::path parent = source.parent_path();
        if (ToLowerAscii(parent.extension().string()) == ".lproj") {
            const fs::path lproj_dir = app / parent.filename();
            fs::create_directories(ExtendedFsPath(lproj_dir), ec);
            ec.clear();
            destination = lproj_dir / source.filename();
        } else {
            destination = app / source.filename();
        }

        if (fs::is_directory(ExtendedFsPath(source))) {
            fs::copy(
                ExtendedFsPath(source),
                ExtendedFsPath(destination),
                fs::copy_options::recursive |
                    fs::copy_options::overwrite_existing,
                ec
            );
        } else {
            fs::copy_file(
                ExtendedFsPath(source),
                ExtendedFsPath(destination),
                fs::copy_options::overwrite_existing,
                ec
            );
        }

        ec.clear();
    }

    {
        std::string asset_error;
        if (!AssetCatalogCompiler::Compile(
                spec.asset_catalog_dirs,
                app,
                spec.minimum_os_version,
                AppIconSelection(spec.app_icon_name, spec.include_all_app_icons, spec.alternate_app_icons),
                asset_error)) {
            std::cerr << "OPENFRUIT PackagerSigner: asset catalog compilation failed: "
                      << asset_error << std::endl;
            return result;
        }
    }

    const fs::path frameworks =
        app /
        "Frameworks";

    fs::remove_all(
        ExtendedFsPath(frameworks),
        ec
    );

    for (const auto& framework_value :
         spec.embedded_frameworks) {

        const fs::path framework(
            framework_value
        );

        if (!fs::exists(ExtendedFsPath(framework))) {
            continue;
        }

        if (!PackagerSigner::IsDynamicFramework(
                root,
                framework)) {
            continue;
        }

        std::cout << "OPENFRUIT PackagerSigner: Embedding dynamic framework: " << framework.filename().string() << std::endl;

        fs::create_directories(
            ExtendedFsPath(frameworks),
            ec
        );

        const fs::path destination =
            frameworks /
            framework.filename();

        fs::copy(
            ExtendedFsPath(framework),
            ExtendedFsPath(destination),
            fs::copy_options::recursive |
                fs::copy_options::
                    overwrite_existing,
            ec
        );

        if (ec) {
            std::cerr
                << "OPENFRUIT v4: failed to embed dynamic framework: "
                << framework.string()
                << std::endl;

            return result;
        }

        if (!MakeTreeWritable(destination)) {
            std::cerr
                << "OPENFRUIT v4: unable to make embedded framework writable: "
                << destination.string() << std::endl;
            return result;
        }

        // Xcode standard: embedded frameworks in app bundles strip Headers and Modules
        // which are development-only metadata and not part of the runtime app bundle.
        fs::remove_all(ExtendedFsPath(destination / "Headers"), ec);
        ec.clear();
        fs::remove_all(ExtendedFsPath(destination / "PrivateHeaders"), ec);
        ec.clear();
        fs::remove_all(ExtendedFsPath(destination / "Modules"), ec);
        ec.clear();
    }

    for (const auto& library_value : spec.embedded_dynamic_libraries) {
        const fs::path library(library_value);
        if (!FileIsNonEmpty(library)) continue;
        fs::create_directories(ExtendedFsPath(frameworks), ec);
        if (ec) return result;
        const fs::path destination = frameworks / library.filename();
        fs::copy_file(
            ExtendedFsPath(library),
            ExtendedFsPath(destination),
            fs::copy_options::overwrite_existing,
            ec
        );
        if (ec || !MakeTreeWritable(destination)) {
            std::cerr
                << "OPENFRUIT v4: failed to embed dynamic library: "
                << library.string() << std::endl;
            return result;
        }
    }

    std::string interface_builder_error;
    if (!InterfaceBuilderCompiler::CompileUncompiledInBundle(app, interface_builder_error,
            Win32Process::ToNarrow(spec.module_name))) {
        std::cerr << "OPENFRUIT v4: Interface Builder compilation failed: "
                  << interface_builder_error << std::endl;
        return result;
    }

    if (!sign_requested) {
        result.signed_ipa_path.clear();
        const auto staged_ipa = build_root / "complete-unsigned.ipa";
        if (!CreateIpaArchive(payload.wstring(), staged_ipa.wstring()) ||
            !MoveFileExW(staged_ipa.c_str(), fs::path(result.unsigned_ipa_path).c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            std::cerr << "OPENFRUIT: unsigned IPA publication failed.\n";
            return result;
        }
        result.success = true;
        std::cout << "OPENFRUIT: Unsigned IPA ready: "
                  << Win32Process::ToNarrow(result.unsigned_ipa_path) << '\n';
        return result;
    }
    result.unsigned_ipa_path.clear(); // Signed mode does not publish this artifact.
    const fs::path zsign = ToolPaths::Zsign(root);

    // A nested app supplied by another resource path must not bypass the
    // per-target entitlement checks simply because it was not in the .appex list.
    for (fs::recursive_directory_iterator it(app, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) { std::cerr << "OPENFRUIT signing preflight: cannot enumerate embedded bundles.\n"; return result; }
        if (!it->is_directory(ec)) continue;
        const auto extension = it->path().extension();
        if (extension != ".app" && extension != ".appex") continue;
        bool registered = false;
        for (const auto& [bundle, metadata] : extension_signing) {
            std::error_code match_error;
            registered |= fs::equivalent(bundle, it->path(), match_error);
        }
        if (!registered) {
            std::cerr << "OPENFRUIT signing preflight: nested application signing metadata is missing.\n";
            return result;
        }
    }
    if (ec) { std::cerr << "OPENFRUIT signing preflight: cannot inspect embedded bundles.\n"; return result; }

    const fs::path p12 = spec.p12_path.empty() ? fs::path{} : fs::path(spec.p12_path);
    const fs::path profile = spec.provisioning_profile_path.empty() ? fs::path{} : fs::path(spec.provisioning_profile_path);
    const fs::path dpapi = spec.dpapi_password_path.empty() ? fs::path{} : fs::path(spec.dpapi_password_path);

    if (profile.empty() || !fs::exists(profile)) {
        std::cerr << "OPENFRUIT Error: provisioning profile (.mobileprovision) path not specified or file does not exist.\n"
                  << "  Configure via: openfruit config set signing.provisioning_profile <path-to-.mobileprovision> (or pass --provision <path>)\n";
        return result;
    }
    std::string effective_bundle_id;
    if (spec.match_profile_bundle_id) {
        std::string prefix, pattern, err;
        if (ExtractProfileBundleIdPattern(profile, prefix, pattern, err)) {
            if (pattern.find('*') == std::string::npos) {
                effective_bundle_id = pattern;
            }
            if (!effective_bundle_id.empty()) {
                std::string rebind_err;
                std::vector<std::pair<fs::path, std::wstring>> updated_extensions;
                if (RebindBundleIdentifier(app, effective_bundle_id, rebind_err, &updated_extensions)) {
                    std::cout << "OPENFRUIT signing: re-bound bundle identifier to " << effective_bundle_id << " to match provisioning profile.\n";
                } else {
                    std::cerr << "OPENFRUIT signing warning: unable to rebind bundle identifier: " << rebind_err << "\n";
                }
            }

            std::error_code ext_ec;
            std::vector<fs::path> extensions_to_remove;
            for (fs::recursive_directory_iterator it(app, ext_ec); it != fs::recursive_directory_iterator(); it.increment(ext_ec)) {
                if (ext_ec) break;
                if (it->is_directory(ext_ec) && it->path().extension() == ".appex") {
                    const auto ext_info_path = it->path() / "Info.plist";
                    std::string ext_bundle_id;
                    std::ifstream in(ext_info_path, std::ios::binary);
                    std::string content((std::istreambuf_iterator<char>(in)), {});
                    in.close();
                    const auto pos = content.find("<key>CFBundleIdentifier</key>");
                    if (pos != std::string::npos) {
                        const auto str_start = content.find("<string>", pos);
                        const auto str_end = content.find("</string>", str_start);
                        if (str_start != std::string::npos && str_end != std::string::npos) {
                            ext_bundle_id = content.substr(str_start + 8, str_end - (str_start + 8));
                        }
                    }
                    if (!MatchesProvisioningPattern(pattern, ext_bundle_id)) {
                        extensions_to_remove.push_back(it->path());
                    }
                }
            }
            for (const auto& ext_path : extensions_to_remove) {
                std::cout << "OPENFRUIT signing: stripping extension " << ext_path.filename().string()
                          << " (not authorized by provisioning profile " << pattern << ").\n";
                for (auto it = extension_signing.begin(); it != extension_signing.end(); ) {
                    std::error_code eq_err;
                    if (it->first == ext_path || fs::equivalent(it->first, ext_path, eq_err)) {
                        it = extension_signing.erase(it);
                    } else {
                        ++it;
                    }
                }
                std::error_code rm_ec;
                fs::remove_all(ext_path, rm_ec);
            }
        }
    }

    std::string identity_error;
    if (!ValidateProvisioningBundleIdentities(profile, app, identity_error)) {
        std::cerr << "OPENFRUIT signing preflight: " << identity_error << "\n";
        return result;
    }
    std::vector<PreparedEntitlementRequest> prepared_requests;
    {
        PreparedEntitlementRequest prepared;
        if (!PrepareProvisioningSignatureInput(profile, app,
                fs::path(spec.code_sign_entitlements_path), spec.build_settings, prepared, identity_error,
                spec.match_profile_bundle_id)) {
            std::cerr << "OPENFRUIT signing preflight: " << identity_error << "\n";
            return result;
        }
        prepared_requests.push_back(std::move(prepared));
    }

    for (const auto& [bundle, signing] : extension_signing) {
        if (!ValidateBundleSigningIdentity(bundle, signing.bundle_id, identity_error)) {
            std::cerr << "OPENFRUIT signing preflight: " << identity_error << "\n";
            return result;
        }
        {
            PreparedEntitlementRequest prepared;
            if (!PrepareProvisioningSignatureInput(profile, bundle,
                    fs::path(signing.entitlements_path), signing.build_settings, prepared, identity_error,
                    spec.match_profile_bundle_id)) {
                std::cerr << "OPENFRUIT signing preflight: " << identity_error << "\n";
                return result;
            }
            prepared_requests.push_back(std::move(prepared));
        }
    }
    result.prepared_entitlement_requests = std::move(prepared_requests);

    if (!fs::exists(zsign)) {
        std::cerr << "OPENFRUIT Error: signing tool 'zsign' not found. Configure tools.zsign.\n";
        return result;
    }
    if (p12.empty() || !fs::exists(p12)) {
        std::cerr << "OPENFRUIT Error: signing certificate (.p12) path not specified or file does not exist.\n"
                  << "  Configure via: openfruit config set signing.p12 <path-to-.p12> (or pass --p12 <path>)\n";
        return result;
    }
    if (dpapi.empty() || !fs::exists(dpapi)) {
        std::cerr << "OPENFRUIT Error: signing password DPAPI store not specified or file does not exist.\n"
                  << "  Configure via: openfruit config set signing.password <password>\n";
        return result;
    }

    std::wstring password;
    PasswordWiper password_wiper{password};

    if (!DecryptDpapiPassword(
            dpapi,
            password)) {

        std::cerr
            << "OPENFRUIT v4: unable to decrypt signing password via DPAPI."
            << std::endl;

        return result;
    }

    SigningCredential credential;
    if (!PrepareSigningCredential(p12, password, credential, identity_error)) {
        result.prepared_entitlement_requests.clear();
        std::cerr << "OPENFRUIT signing preflight: " << identity_error << "\n";
        return result;
    }
    for (const auto& request : result.prepared_entitlement_requests) {
        if (!ValidateProvisioningSigningCertificate(request, credential, identity_error)) {
            result.prepared_entitlement_requests.clear();
            std::cerr << "OPENFRUIT signing preflight: " << identity_error << "\n";
            return result;
        }
    }

    // zsign opens files by their full path, so a bundle member at 260 or
    // more characters would be sealed as empty. Sign through a short link to
    // the Payload; the link is removed afterwards and never packaged.
    fs::path signing_payload = payload;
    const fs::path signing_link = ToolPaths::LocalHome() / "sg" /
        ("z" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64() % 100000));
    const bool linked = NativeArtifactStore::CreateDirectoryJunction(signing_link, payload);
    if (linked) signing_payload = signing_link;
    const auto unlink = [&] {
        if (linked) RemoveDirectoryW(signing_link.c_str());
    };
    const fs::path signing_app = signing_payload / (effective_product_name + L".app");
    // Through that link zsign cannot create a directory, so a bundle that
    // arrives unsigned (no _CodeSignature yet) could not be sealed. Create
    // the seal directory of every bundle it seals, as codesign would, and
    // drop any that stays empty.
    std::vector<fs::path> created_seals;
    {
        std::vector<fs::path> bundles{app};
        for (fs::recursive_directory_iterator it(app, ec), end; !ec && it != end; it.increment(ec)) {
            const auto extension = ToLowerAscii(it->path().extension().string());
            if ((extension == ".app" || extension == ".appex" || extension == ".framework") && it->is_directory(ec))
                bundles.push_back(it->path());
        }
        ec.clear();
        for (const auto& bundle : bundles) {
            const auto seal = bundle / "_CodeSignature";
            if (!fs::exists(ExtendedFsPath(bundle / "Info.plist"), ec) || fs::exists(ExtendedFsPath(seal), ec)) continue;
            if (fs::create_directory(ExtendedFsPath(seal), ec)) created_seals.push_back(seal);
            ec.clear();
        }
    }
    const auto drop_empty_seals = [&] {
        for (const auto& seal : created_seals) {
            std::error_code seal_ec;
            if (fs::is_empty(ExtendedFsPath(seal), seal_ec) && !seal_ec) fs::remove(ExtendedFsPath(seal), seal_ec);
        }
    };

    const auto run_zsign = [&]() {
        std::cout
            << "OPENFRUIT: Signing app bundle natively with zsign..."
            << std::endl;

        ProcessResult sign =
            Win32Process::Run(
                zsign.wstring(),
                {
                    zsign.wstring(),
                    L"--force",
                    L"--pkey",
                    p12.wstring(),
                    L"--password",
                    password,
                    L"--prov",
                    profile.wstring(),
                    L"--bundle_id",
                    effective_bundle_id.empty() ? spec.bundle_id : Win32Process::ToWide(effective_bundle_id),
                    L"--bundle_name",
                    effective_product_name,
                    signing_app.wstring()
                },
                signing_payload
                    .wstring()
            );

        if (!sign.std_out.empty()) {
            std::cout
                << "OPENFRUIT: Signing output: "
                << sign.std_out
                << std::endl;
        }

        if (!sign.std_err.empty()) {
            std::cerr
                << "OPENFRUIT: Signing stderr: "
                << sign.std_err
                << std::endl;
        }

        return sign.success &&
            !SigningOutputFailed(
                sign.std_out +
                "\n" +
                sign.std_err);
    };

    // A smaller new signature leaves bytes of the replaced one in its load
    // command's space. Zeroing them changes those files after the enclosing
    // bundle sealed them, so the bundle is signed once more over the final
    // bytes; that pass writes signatures of the same size and leaves none.
    bool signed_ok = run_zsign();
    std::size_t cleaned_images = 0;
    bool slack_ok = signed_ok && ZeroSignatureSlack(app, cleaned_images);
    if (slack_ok && cleaned_images) {
        std::cout
            << "OPENFRUIT: cleared stale signature bytes left by re-signing in "
            << cleaned_images << " Mach-O image(s); sealing the bundle again."
            << std::endl;
        signed_ok = run_zsign();
        std::size_t remaining = 0;
        slack_ok = signed_ok && ZeroSignatureSlack(app, remaining, true) && remaining == 0;
    }
    unlink();
    drop_empty_seals();

    if (!password.empty()) {
        SecureZeroMemory(
            password.data(),
            password.size() *
                sizeof(wchar_t)
        );
        password.clear();
    }

    if (!signed_ok) {
        std::cerr
            << "OPENFRUIT v4: signing failed; IPA will not be created."
            << std::endl;

        return result;
    }

    if (!slack_ok) {
        std::cerr
            << "OPENFRUIT v4: signed images still carry stale signature bytes; IPA will not be created."
            << std::endl;
        return result;
    }

    // zsign may place its acceleration metadata beside the .app. It is a host
    // implementation detail, not part of an Xcode Payload, and must never be
    // shipped inside the IPA.
    ec.clear();
    fs::remove_all(payload / ".zsign_cache", ec);
    if (ec) {
        std::cerr
            << "OPENFRUIT v4: unable to remove signing cache from Payload: "
            << ec.message()
            << std::endl;
        return result;
    }

    if (!CreateIpaArchive(
            payload.wstring(),
            result.signed_ipa_path)) {

        std::cerr
            << "OPENFRUIT v4: native ZIP/IPA creation failed."
            << std::endl;

        return result;
    }

    result.success = true;
    result.bundle_id = effective_bundle_id.empty() ? spec.bundle_id : Win32Process::ToWide(effective_bundle_id);

    std::cout
        << "OPENFRUIT: Signed IPA ready: "
        << Win32Process::ToNarrow(
            result.signed_ipa_path
        )
        << std::endl;

    return result;
}

} // namespace OpenFruit
