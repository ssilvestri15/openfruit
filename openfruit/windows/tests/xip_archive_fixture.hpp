#pragma once
#include <zlib.h>
#include <lzma.h>
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <limits>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>
#include <stdexcept>
namespace OpenFruitOwnedFixture {
namespace fs = std::filesystem;
using Bytes = std::vector<std::uint8_t>;
inline void BE(Bytes& output, std::uint64_t value, unsigned length) {
    for (unsigned i = length; i; --i) output.push_back(static_cast<std::uint8_t>(value >> (8 * (i - 1))));
}
inline void Text(Bytes& output, std::string_view text) { output.insert(output.end(), text.begin(), text.end()); }
inline void Entry(Bytes& output, std::string_view name, std::string_view contents, unsigned mode = 0100644, unsigned inode = 1, unsigned links = 1) {
    std::ostringstream header;
    header << "070707" << std::oct << std::setfill('0') << std::setw(6) << 1 << std::setw(6) << inode
        << std::setw(6) << mode << std::setw(6) << 0 << std::setw(6) << 0 << std::setw(6) << links
        << std::setw(6) << 0 << std::setw(11) << 0 << std::setw(6) << name.size() + 1 << std::setw(11) << contents.size();
    Text(output, header.str()); Text(output, name); output.push_back(0); Text(output, contents);
}
inline Bytes Payload(const Bytes& cpio, bool compressed) {
    Bytes result; Text(result, "pbzx"); BE(result, 256, 8);
    for (std::size_t start = 0; start < cpio.size(); start += 256) {
        const auto length = std::min<std::size_t>(256, cpio.size() - start);
        Bytes encoded;
        if (compressed) {
            encoded.resize(lzma_stream_buffer_bound(length)); std::size_t end = 0;
            if (lzma_easy_buffer_encode(1, LZMA_CHECK_CRC64, nullptr, cpio.data() + start, length, encoded.data(), &end, encoded.size()) != LZMA_OK)
                throw std::runtime_error("fixture encoding failed");
            encoded.resize(end);
        } else encoded.assign(cpio.begin() + start, cpio.begin() + start + length);
        BE(result, length, 8); BE(result, encoded.size(), 8); result.insert(result.end(), encoded.begin(), encoded.end());
    }
    return result;
}
inline Bytes Archive(const Bytes& payload, const std::string& supplied_toc = {}) {
    const auto toc = supplied_toc.empty() ? "<xar><toc><file><name>Content</name><data><offset>0</offset><length>" +
        std::to_string(payload.size()) + "</length></data></file></toc></xar>" : supplied_toc;
    Bytes compressed(compressBound(static_cast<uLong>(toc.size())));
    uLongf size = static_cast<uLongf>(compressed.size());
    if (compress2(compressed.data(), &size, reinterpret_cast<const Bytef*>(toc.data()), static_cast<uLong>(toc.size()), 1) != Z_OK)
        throw std::runtime_error("fixture TOC failed");
    compressed.resize(size);
    Bytes result; Text(result, "xar!"); BE(result, 28, 2); BE(result, 1, 2); BE(result, size, 8); BE(result, toc.size(), 8); BE(result, 0, 4);
    result.insert(result.end(), compressed.begin(), compressed.end()); result.insert(result.end(), payload.begin(), payload.end());
    return result;
}
inline std::array<std::uint8_t, 20> Sha1(const Bytes& bytes) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::array<std::uint8_t, 20> digest{};
    const bool opened = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA1_ALGORITHM, nullptr, 0) >= 0;
    const bool created = opened && BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
    const bool passed = created && bytes.size() <= std::numeric_limits<ULONG>::max() &&
        BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) >= 0 &&
        BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!passed) throw std::runtime_error("fixture checksum failed");
    return digest;
}
inline std::string Hex(const std::array<std::uint8_t, 20>& digest) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (const auto byte : digest) { result += digits[byte >> 4]; result += digits[byte & 15]; }
    return result;
}
inline Bytes ArchiveWithChecksums(const Bytes& payload, const std::string& additional_toc = {}) {
    const auto toc = "<xar><toc><checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum>"
        + additional_toc +
        "<file><name>Content</name><data><offset>20</offset><length>" + std::to_string(payload.size()) +
        "</length><archived-checksum style=\"sha1\">" + Hex(Sha1(payload)) +
        "</archived-checksum></data></file></toc></xar>";
    Bytes compressed(compressBound(static_cast<uLong>(toc.size())));
    uLongf size = static_cast<uLongf>(compressed.size());
    if (compress2(compressed.data(), &size, reinterpret_cast<const Bytef*>(toc.data()), static_cast<uLong>(toc.size()), 1) != Z_OK)
        throw std::runtime_error("fixture TOC failed");
    compressed.resize(size);
    const auto digest = Sha1(compressed);
    Bytes result; Text(result, "xar!"); BE(result, 28, 2); BE(result, 1, 2); BE(result, size, 8);
    BE(result, toc.size(), 8); BE(result, 1, 4);
    result.insert(result.end(), compressed.begin(), compressed.end());
    result.insert(result.end(), digest.begin(), digest.end());
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}
inline void Write(const fs::path& path, const Bytes& bytes) { std::ofstream output(path, std::ios::binary); output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
}
