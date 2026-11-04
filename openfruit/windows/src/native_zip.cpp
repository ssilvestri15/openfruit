#include "native_zip.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {

struct CentralEntry {
    std::string name;
    std::uint32_t crc32 = 0;
    std::uint32_t size = 0;
    std::uint32_t local_offset = 0;
    std::uint16_t dos_time = 0;
    std::uint16_t dos_date = 0;
    bool is_executable = false;
};

void WriteU16(
    std::ofstream& out,
    std::uint16_t value
) {
    const char bytes[2] = {
        static_cast<char>(
            value & 0xFF
        ),
        static_cast<char>(
            (value >> 8) & 0xFF
        )
    };

    out.write(bytes, 2);
}

void WriteU32(
    std::ofstream& out,
    std::uint32_t value
) {
    const char bytes[4] = {
        static_cast<char>(
            value & 0xFF
        ),
        static_cast<char>(
            (value >> 8) & 0xFF
        ),
        static_cast<char>(
            (value >> 16) & 0xFF
        ),
        static_cast<char>(
            (value >> 24) & 0xFF
        )
    };

    out.write(bytes, 4);
}

// Slicing-by-8 tables for the reflected CRC-32 that ZIP uses (0xEDB88320).
const std::array<std::array<std::uint32_t, 256>, 8>& CrcTables() {
    static const auto tables = [] {
        std::array<std::array<std::uint32_t, 256>, 8> result{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t value = i;
            for (int bit = 0; bit < 8; ++bit)
                value = (value & 1) ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
            result[0][i] = value;
        }
        for (std::uint32_t i = 0; i < 256; ++i)
            for (std::size_t slice = 1; slice < 8; ++slice)
                result[slice][i] = (result[slice - 1][i] >> 8) ^ result[0][result[slice - 1][i] & 0xFFu];
        return result;
    }();
    return tables;
}

std::uint32_t UpdateCrc32(
    std::uint32_t crc,
    const unsigned char* data,
    std::size_t size
) {
    const auto& t = CrcTables();
    while (size >= 8) {
        const std::uint32_t low = crc ^ (std::uint32_t(data[0]) | std::uint32_t(data[1]) << 8 |
            std::uint32_t(data[2]) << 16 | std::uint32_t(data[3]) << 24);
        crc = t[7][low & 0xFFu] ^ t[6][(low >> 8) & 0xFFu] ^ t[5][(low >> 16) & 0xFFu] ^ t[4][low >> 24] ^
            t[3][data[4]] ^ t[2][data[5]] ^ t[1][data[6]] ^ t[0][data[7]];
        data += 8;
        size -= 8;
    }
    while (size--) crc = t[0][(crc ^ *data++) & 0xFFu] ^ (crc >> 8);
    return crc;
}

std::string ZipPath(
    const fs::path& relative
) {
    std::string value =
        relative.generic_string();

    while (!value.empty() &&
           value.front() == '/') {
        value.erase(
            value.begin()
        );
    }

    return value;
}

void DosTimestamp(
    std::uint16_t& time,
    std::uint16_t& date
) {
    // Deterministic timestamp: 2026-01-01 00:00:00.
    time = 0;
    date =
        static_cast<std::uint16_t>(
            ((2026 - 1980) << 9) |
            (1 << 5) |
            1
        );
}

// Streams one member's bytes into the archive and returns their CRC-32 and
// size, reading the file once.
bool CopyFileBytes(
    const fs::path& path,
    std::ofstream& output,
    std::uint32_t& crc,
    std::uint32_t& size
) {
    std::error_code ec;
    const std::uintmax_t file_size = fs::file_size(path, ec);
    if (ec || file_size > 0xFFFFFFFFull) return false;
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    std::vector<char> buffer(1024 * 1024);
    std::uint32_t state = 0xFFFFFFFFu;
    std::uint64_t total = 0;
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = input.gcount();
        if (got <= 0) break;
        state = UpdateCrc32(state, reinterpret_cast<const unsigned char*>(buffer.data()),
            static_cast<std::size_t>(got));
        output.write(buffer.data(), got);
        total += static_cast<std::uint64_t>(got);
    }
    if (input.bad() || total != file_size) return false;
    crc = state ^ 0xFFFFFFFFu;
    size = static_cast<std::uint32_t>(file_size);
    return output.good();
}

} // namespace

bool NativeZipWriter::CreateFromDirectory(
    const fs::path& root_directory,
    const fs::path& output_zip
) {
    if (!fs::exists(root_directory) ||
        !fs::is_directory(root_directory)) {
        return false;
    }

    std::vector<fs::path>
        files;

    std::error_code ec;

    for (fs::recursive_directory_iterator it(
             root_directory,
             fs::directory_options::
                 skip_permission_denied,
             ec);
         it !=
             fs::recursive_directory_iterator();
         it.increment(ec)) {

        if (ec) {
            ec.clear();
            continue;
        }

        if (it->is_regular_file(ec)) {
            files.push_back(
                it->path()
            );
        }
    }

    std::sort(
        files.begin(),
        files.end()
    );

    if (files.size() >
        0xFFFFu) {
        std::cerr
            << "OPENFRUIT ZIP: too many files for ZIP32."
            << std::endl;

        return false;
    }

    fs::create_directories(
        output_zip.parent_path(),
        ec
    );

    ec.clear();

    fs::remove(
        output_zip,
        ec
    );

    std::ofstream output(
        output_zip,
        std::ios::binary |
        std::ios::trunc
    );

    if (!output) {
        return false;
    }

    std::vector<CentralEntry>
        entries;

    entries.reserve(
        files.size()
    );

    for (const auto& file :
         files) {

        CentralEntry entry;

        entry.name =
            ZipPath(
                fs::relative(
                    file,
                    root_directory.parent_path(),
                    ec
                )
            );

        const auto ext = file.extension().string();
        entry.is_executable = ext.empty() || ext == ".sh";

        if (ec ||
            entry.name.empty() ||
            entry.name.size() >
                0xFFFFu) {

            return false;
        }

        const std::streampos local_pos =
            output.tellp();

        const std::streamoff local_off =
            static_cast<std::streamoff>(
                local_pos
            );

        if (local_off < 0 ||
            static_cast<std::uint64_t>(
                local_off) >
                0xFFFFFFFFull) {
            return false;
        }

        entry.local_offset =
            static_cast<std::uint32_t>(
                local_off
            );

        DosTimestamp(
            entry.dos_time,
            entry.dos_date
        );

        // Local file header.
        WriteU32(output, 0x04034B50u);
        WriteU16(output, 20);
        WriteU16(output, 0x0800); // UTF-8 paths
        WriteU16(output, 0); // store
        WriteU16(output, entry.dos_time);
        WriteU16(output, entry.dos_date);
        // CRC-32 and sizes are known once the bytes are written; they are
        // filled in below, so each member is read only once.
        WriteU32(output, 0);
        WriteU32(output, 0);
        WriteU32(output, 0);
        WriteU16(
            output,
            static_cast<std::uint16_t>(
                entry.name.size()
            )
        );
        WriteU16(output, 0);
        output.write(
            entry.name.data(),
            static_cast<std::streamsize>(
                entry.name.size()
            )
        );

        if (!CopyFileBytes(
                file,
                output,
                entry.crc32,
                entry.size)) {
            return false;
        }
        const std::streampos member_end = output.tellp();
        output.seekp(local_pos + std::streamoff(14));
        WriteU32(output, entry.crc32);
        WriteU32(output, entry.size);
        WriteU32(output, entry.size);
        output.seekp(member_end);
        if (!output) return false;

        entries.push_back(
            std::move(entry)
        );
    }

    const std::streampos central_begin_pos =
        output.tellp();

    const std::streamoff central_begin_off =
        static_cast<std::streamoff>(
            central_begin_pos
        );

    if (central_begin_off < 0 ||
        static_cast<std::uint64_t>(
            central_begin_off) >
            0xFFFFFFFFull) {
        return false;
    }

    const std::uint32_t
        central_begin =
            static_cast<std::uint32_t>(
                central_begin_off
            );

    for (const auto& entry :
         entries) {

        // Central directory header.
        WriteU32(output, 0x02014B50u);
        WriteU16(output, (3 << 8) | 20); // Host: UNIX (3), spec: 2.0 (20)
        WriteU16(output, 20);
        WriteU16(output, 0x0800); // UTF-8 paths
        WriteU16(output, 0);
        WriteU16(output, entry.dos_time);
        WriteU16(output, entry.dos_date);
        WriteU32(output, entry.crc32);
        WriteU32(output, entry.size);
        WriteU32(output, entry.size);
        WriteU16(
            output,
            static_cast<std::uint16_t>(
                entry.name.size()
            )
        );
        WriteU16(output, 0);
        WriteU16(output, 0);
        WriteU16(output, 0);
        WriteU16(output, 0);
        const std::uint32_t unix_mode = entry.is_executable ? 0100755u : 0100644u;
        WriteU32(output, unix_mode << 16);
        WriteU32(
            output,
            entry.local_offset
        );

        output.write(
            entry.name.data(),
            static_cast<std::streamsize>(
                entry.name.size()
            )
        );
    }

    const std::streampos central_end_pos =
        output.tellp();

    const std::streamoff central_end_off =
        static_cast<std::streamoff>(
            central_end_pos
        );

    if (central_end_off < 0 ||
        static_cast<std::uint64_t>(
            central_end_off) >
            0xFFFFFFFFull) {
        return false;
    }

    const std::uint32_t
        central_end =
            static_cast<std::uint32_t>(
                central_end_off
            );

    const std::uint32_t
        central_size =
            central_end -
            central_begin;

    // End of central directory.
    WriteU32(output, 0x06054B50u);
    WriteU16(output, 0);
    WriteU16(output, 0);

    WriteU16(
        output,
        static_cast<std::uint16_t>(
            entries.size()
        )
    );

    WriteU16(
        output,
        static_cast<std::uint16_t>(
            entries.size()
        )
    );

    WriteU32(
        output,
        central_size
    );

    WriteU32(
        output,
        central_begin
    );

    WriteU16(output, 0);

    output.flush();
    return output.good();
}

} // namespace OpenFruit
