#include "xip_archive.hpp"
#include "apple_software_update_trust.hpp"
#include "json_value.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <xmllite.h>
#include <wrl/client.h>
#include <zlib.h>
#include <lzma.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <vector>
namespace OpenFruit {
namespace {
using Microsoft::WRL::ComPtr;
constexpr std::size_t buffer_size = 64 * 1024;
struct Failure { XipStatus status; const char* message; };
[[noreturn]] void Invalid(const char* message) { throw Failure{XipStatus::InvalidArchive, message}; }
void Check(const XipReadOptions& options) {
    if (options.cancellation.Requested()) throw Failure{XipStatus::Cancelled, "archive.cancelled"};
    if (std::chrono::steady_clock::now() >= options.deadline) throw Failure{XipStatus::TimedOut, "archive.deadline"};
}
std::uint64_t BigEndian(const std::uint8_t* bytes, std::size_t size) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < size; ++i) value = (value << 8) | bytes[i];
    return value;
}
std::uint64_t Number(std::string_view text, int base = 10) {
    std::uint64_t value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (text.empty() || result.ec != std::errc{} || result.ptr != text.data() + text.size()) Invalid("archive.invalid_number");
    return value;
}
struct DigestSpec { const wchar_t* algorithm; std::size_t size; };
DigestSpec DigestAlgorithm(std::string_view style) {
    if (style == "sha1") return {BCRYPT_SHA1_ALGORITHM, 20};
    if (style == "sha256") return {BCRYPT_SHA256_ALGORITHM, 32};
    if (style == "sha512") return {BCRYPT_SHA512_ALGORITHM, 64};
    Invalid("archive.unsupported_checksum");
}
std::vector<std::uint8_t> HexDigest(std::string_view text, std::size_t expected) {
    if (text.size() != expected * 2) Invalid("archive.invalid_checksum");
    std::vector<std::uint8_t> bytes(expected);
    auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < expected; ++i) {
        const int high = nibble(text[i * 2]), low = nibble(text[i * 2 + 1]);
        if (high < 0 || low < 0) Invalid("archive.invalid_checksum");
        bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return bytes;
}
class Digest {
public:
    explicit Digest(DigestSpec spec) : size_(spec.size) {
        if (BCryptOpenAlgorithmProvider(&algorithm_, spec.algorithm, nullptr, 0) < 0)
            Invalid("archive.checksum_unavailable");
        if (BCryptCreateHash(algorithm_, &hash_, nullptr, 0, nullptr, 0, 0) < 0) {
            BCryptCloseAlgorithmProvider(algorithm_, 0);
            algorithm_ = nullptr;
            Invalid("archive.checksum_unavailable");
        }
    }
    ~Digest() { if (hash_) BCryptDestroyHash(hash_); if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0); }
    Digest(const Digest&) = delete;
    Digest& operator=(const Digest&) = delete;
    void Update(std::span<const std::uint8_t> bytes) {
        if (bytes.size() > std::numeric_limits<ULONG>::max() ||
            BCryptHashData(hash_, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) < 0)
            Invalid("archive.checksum_failed");
    }
    std::vector<std::uint8_t> Finish() {
        std::vector<std::uint8_t> bytes(size_);
        if (BCryptFinishHash(hash_, bytes.data(), static_cast<ULONG>(bytes.size()), 0) < 0)
            Invalid("archive.checksum_failed");
        return bytes;
    }
private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::size_t size_;
};
class Source {
public:
    Source(const std::filesystem::path& path, const XipReadOptions& options) : options_(options) {
        const auto absolute = std::filesystem::absolute(path).wstring();
        const auto native = absolute.starts_with(L"\\\\?\\") ? absolute : absolute.starts_with(L"\\\\")
            ? L"\\\\?\\UNC\\" + absolute.substr(2) : L"\\\\?\\" + absolute;
        handle_ = CreateFileW(native.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        LARGE_INTEGER size{};
        if (handle_ == INVALID_HANDLE_VALUE || !GetFileSizeEx(handle_, &size) || size.QuadPart < 0) {
            if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
            throw Failure{XipStatus::IoFailure, "archive.open_failed"};
        }
        size_ = static_cast<std::uint64_t>(size.QuadPart);
    }
    ~Source() { if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_); }
    void Seek(std::uint64_t position) {
        if (position > size_) Invalid("archive.offset_out_of_bounds");
        LARGE_INTEGER offset{}; offset.QuadPart = static_cast<LONGLONG>(position);
        if (!SetFilePointerEx(handle_, offset, nullptr, FILE_BEGIN)) throw Failure{XipStatus::IoFailure, "archive.seek_failed"};
        position_ = position;
    }
    void Read(std::span<std::uint8_t> bytes) {
        if (bytes.size() > size_ - position_) Invalid("archive.truncated");
        while (!bytes.empty()) {
            Check(options_);
            const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(bytes.size(), buffer_size));
            DWORD count = 0;
            if (!ReadFile(handle_, bytes.data(), requested, &count, nullptr)) throw Failure{XipStatus::IoFailure, "archive.read_failed"};
            if (!count) Invalid("archive.truncated");
            position_ += count; bytes = bytes.subspan(count);
        }
    }
    std::uint64_t Size() const { return size_; }
private:
    const XipReadOptions& options_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::uint64_t size_ = 0, position_ = 0;
};
struct ContentRange {
    std::uint64_t offset = 0, length = 0;
    std::string checksum_style;
    std::vector<std::uint8_t> checksum;
};
ContentRange Locate(Source& source, const XipReadOptions& options, XipReadResult& read_result) {
    std::array<std::uint8_t, 28> header{}; source.Read(header);
    if (std::memcmp(header.data(), "xar!", 4) || BigEndian(header.data() + 6, 2) != 1) Invalid("archive.unsupported_xar");
    const auto header_size = BigEndian(header.data() + 4, 2);
    const auto compressed_size = BigEndian(header.data() + 8, 8), decoded_size = BigEndian(header.data() + 16, 8);
    const auto toc_algorithm = BigEndian(header.data() + 24, 4);
    if (header_size < header.size() || header_size > source.Size() || compressed_size > source.Size() - header_size)
        Invalid("archive.invalid_toc_range");
    if (!compressed_size || !decoded_size || compressed_size > 16 * 1024 * 1024 || decoded_size > 32 * 1024 * 1024)
        throw Failure{XipStatus::ResourceLimit, "archive.toc_limit"};
    source.Seek(header_size);
    std::vector<std::uint8_t> compressed(static_cast<std::size_t>(compressed_size)), decoded(static_cast<std::size_t>(decoded_size));
    source.Read(compressed);
    uLongf output_size = static_cast<uLongf>(decoded_size);
    uLong input_size = static_cast<uLong>(compressed_size);
    if (uncompress2(decoded.data(), &output_size, compressed.data(), &input_size) != Z_OK ||
        output_size != decoded_size || input_size != compressed_size) Invalid("archive.invalid_toc_compression");
    ComPtr<IStream> stream;
    stream.Attach(SHCreateMemStream(decoded.data(), static_cast<UINT>(decoded.size())));
    ComPtr<IXmlReader> xml;
    if (!stream || FAILED(CreateXmlReader(__uuidof(IXmlReader), reinterpret_cast<void**>(xml.GetAddressOf()), nullptr)) ||
        FAILED(xml->SetProperty(XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit)) ||
        FAILED(xml->SetProperty(XmlReaderProperty_MaxElementDepth, 32)) || FAILED(xml->SetInput(stream.Get())))
        Invalid("archive.xml_reader_failed");
    std::vector<std::wstring> stack;
    std::wstring name, offset, length, field, checksum_offset, checksum_size;
    std::wstring toc_style, content_style, content_hash, signature_style, signature_offset, signature_size, certificate_base64;
    std::vector<std::wstring> encoded_certificates;
    bool found = false, checksum_seen = false, signature_seen = false;
    ContentRange range{};
    auto finish_file = [&] {
        if (name != L"Content") return;
        if (found || offset.empty() || length.empty()) Invalid("archive.ambiguous_content");
        range.offset = Number(Win32Process::ToNarrow(offset));
        range.length = Number(Win32Process::ToNarrow(length));
        if (!content_style.empty() || !content_hash.empty()) {
            range.checksum_style = Win32Process::ToNarrow(content_style);
            range.checksum = HexDigest(Win32Process::ToNarrow(content_hash), DigestAlgorithm(range.checksum_style).size);
        }
        found = true;
    };
    XmlNodeType type{}; HRESULT result = S_OK;
    while ((result = xml->Read(&type)) == S_OK) {
        Check(options);
        if (type == XmlNodeType_Element) {
            const wchar_t* local = nullptr; const wchar_t* ns = nullptr;
            xml->GetLocalName(&local, nullptr); xml->GetNamespaceUri(&ns, nullptr);
            // XAR fields are unqualified. Foreign extension trees (for example
            // certificate metadata) are not XAR fields, even with the same local name.
            stack.emplace_back(ns && *ns ? L"{" + std::wstring(ns) + L"}" + local : local);
            if (stack.size() == 1 && stack[0] != L"xar") Invalid("archive.invalid_xml_root");
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"file"}) {
                name.clear(); offset.clear(); length.clear(); content_style.clear(); content_hash.clear();
            }
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"checksum"}) {
                if (checksum_seen) Invalid("archive.ambiguous_toc_checksum");
                checksum_seen = true;
            }
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"signature"}) {
                if (signature_seen) Invalid("archive.ambiguous_signature");
                signature_seen = true;
            }
            field.clear();
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"checksum"} ||
                stack == std::vector<std::wstring>{L"xar", L"toc", L"signature"} ||
                stack == std::vector<std::wstring>{L"xar", L"toc", L"file", L"data", L"archived-checksum"}) {
                const wchar_t* value = nullptr;
                if (xml->MoveToAttributeByName(L"style", nullptr) != S_OK ||
                    FAILED(xml->GetValue(&value, nullptr)) || !value)
                    Invalid("archive.invalid_checksum_style");
                std::wstring style(value);
                if (FAILED(xml->MoveToElement())) Invalid("archive.invalid_checksum_style");
                (stack.size() == 3 ? (stack.back() == L"checksum" ? toc_style : signature_style) : content_style) = std::move(style);
            }
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"checksum", L"offset"}) field = L"checksum_offset";
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"checksum", L"size"}) field = L"checksum_size";
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"signature", L"offset"}) field = L"signature_offset";
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"signature", L"size"}) field = L"signature_size";
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"signature",
                L"{http://www.w3.org/2000/09/xmldsig#}KeyInfo", L"{http://www.w3.org/2000/09/xmldsig#}X509Data",
                L"{http://www.w3.org/2000/09/xmldsig#}X509Certificate"}) {
                if (encoded_certificates.size() >= 8) Invalid("archive.certificate_limit");
                certificate_base64.clear(); field = L"certificate";
            }
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"file", L"name"}) field = L"name";
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"file", L"data", L"offset"}) field = L"offset";
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"file", L"data", L"length"}) field = L"length";
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"file", L"data", L"archived-checksum"}) field = L"content_hash";
            if (xml->IsEmptyElement()) { stack.pop_back(); field.clear(); }
        } else if (type == XmlNodeType_Text || type == XmlNodeType_CDATA || type == XmlNodeType_Whitespace) {
            const wchar_t* value = nullptr; UINT size = 0; xml->GetValue(&value, &size);
            auto* destination = field == L"name" ? &name : field == L"offset" ? &offset : field == L"length" ? &length
                : field == L"checksum_offset" ? &checksum_offset : field == L"checksum_size" ? &checksum_size
                : field == L"signature_offset" ? &signature_offset : field == L"signature_size" ? &signature_size
                : field == L"certificate" ? &certificate_base64
                : field == L"content_hash" ? &content_hash : nullptr;
            if (destination) {
                if (destination->size() + size > (field == L"certificate" ? 131072u : 1024u))
                    Invalid("archive.xml_field_limit");
                destination->append(value, size);
            }
        } else if (type == XmlNodeType_EndElement) {
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"signature",
                L"{http://www.w3.org/2000/09/xmldsig#}KeyInfo", L"{http://www.w3.org/2000/09/xmldsig#}X509Data",
                L"{http://www.w3.org/2000/09/xmldsig#}X509Certificate"})
                encoded_certificates.push_back(std::move(certificate_base64));
            if (stack == std::vector<std::wstring>{L"xar", L"toc", L"file"}) finish_file();
            if (stack.empty()) Invalid("archive.invalid_xml_nesting");
            stack.pop_back(); field.clear();
        }
    }
    if (result != S_FALSE || !stack.empty() || !found) Invalid("archive.invalid_xml");
    const auto heap = header_size + compressed_size;
    std::vector<std::uint8_t> verified_toc_digest;
    if (toc_algorithm) {
        const std::string style = toc_algorithm == 1 ? "sha1" : toc_algorithm == 3 ? "sha256"
            : toc_algorithm == 4 ? "sha512" : "";
        if (style.empty() || toc_style != Win32Process::ToWide(style) || checksum_offset.empty() || checksum_size.empty())
            Invalid("archive.invalid_toc_checksum");
        const auto spec = DigestAlgorithm(style);
        const auto position = Number(Win32Process::ToNarrow(checksum_offset));
        const auto size = Number(Win32Process::ToNarrow(checksum_size));
        if (size != spec.size || position > source.Size() - heap || size > source.Size() - heap - position)
            Invalid("archive.invalid_toc_checksum_range");
        Digest digest(spec); digest.Update(compressed);
        source.Seek(heap + position);
        std::vector<std::uint8_t> expected(spec.size); source.Read(expected);
        verified_toc_digest = digest.Finish();
        if (verified_toc_digest != expected) Invalid("archive.toc_checksum_mismatch");
        read_result.toc_checksum_verified = true;
    } else if (checksum_seen) Invalid("archive.invalid_toc_checksum");
    if (signature_seen) {
        if (!read_result.toc_checksum_verified || signature_style != L"RSA" || signature_offset.empty() ||
            signature_size.empty() || encoded_certificates.empty() || encoded_certificates.front().empty())
            Invalid("archive.invalid_signature_metadata");
        const auto position = Number(Win32Process::ToNarrow(signature_offset));
        const auto size = Number(Win32Process::ToNarrow(signature_size));
        if (size < 64 || size > 8192 || position > source.Size() - heap || size > source.Size() - heap - position)
            Invalid("archive.invalid_signature_range");
        source.Seek(heap + position);
        std::vector<std::uint8_t> signature(static_cast<std::size_t>(size)); source.Read(signature);
        std::vector<std::vector<std::uint8_t>> certificates;
        certificates.reserve(encoded_certificates.size());
        for (const auto& base64 : encoded_certificates) {
            DWORD der_size = 0;
            if (!CryptStringToBinaryW(base64.c_str(), static_cast<DWORD>(base64.size()),
                CRYPT_STRING_BASE64, nullptr, &der_size, nullptr, nullptr) || !der_size || der_size > 65536)
                Invalid("archive.invalid_signing_certificate");
            auto& der = certificates.emplace_back(der_size);
            if (!CryptStringToBinaryW(base64.c_str(), static_cast<DWORD>(base64.size()),
                CRYPT_STRING_BASE64, der.data(), &der_size, nullptr, nullptr))
                Invalid("archive.invalid_signing_certificate");
        }
        const auto certificate = CertCreateCertificateContext(X509_ASN_ENCODING,
            certificates.front().data(), static_cast<DWORD>(certificates.front().size()));
        if (!certificate) Invalid("archive.invalid_signing_certificate");
        BCRYPT_KEY_HANDLE key = nullptr;
        const bool imported = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
            &certificate->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, &key) != 0;
        CertFreeCertificateContext(certificate);
        if (!imported || !key) {
            if (key) BCryptDestroyKey(key);
            Invalid("archive.invalid_signing_certificate");
        }
        BCRYPT_PKCS1_PADDING_INFO padding{DigestAlgorithm(Win32Process::ToNarrow(toc_style)).algorithm};
        const bool valid = BCryptVerifySignature(key, &padding, verified_toc_digest.data(),
            static_cast<ULONG>(verified_toc_digest.size()), signature.data(),
            static_cast<ULONG>(signature.size()), BCRYPT_PAD_PKCS1) >= 0;
        BCryptDestroyKey(key);
        if (!valid) Invalid("archive.invalid_signature");
        read_result.xar_signature_valid = true;
        const auto trust = VerifyAppleSoftwareUpdateChain(certificates);
        read_result.apple_signing_chain_valid = trust.chain_valid;
        read_result.apple_revocation_valid = trust.revocation_valid;
    }
    if (range.offset > source.Size() - heap || range.length > source.Size() - heap - range.offset || range.length < 12)
        Invalid("archive.invalid_content_range");
    range.offset += heap;
    return range;
}
class Payload {
public:
    Payload(Source& source, ContentRange range, const XipReadOptions& options, XipReadResult& result)
        : source_(source), remaining_(range.length), options_(options), result_(result) {
        if (!range.checksum.empty()) {
            digest_.emplace(DigestAlgorithm(range.checksum_style));
            expected_checksum_ = std::move(range.checksum);
        }
        result_.encoded_total = range.length;
        source_.Seek(range.offset);
        std::array<std::uint8_t, 12> header{}; Encoded(header);
        if (std::memcmp(header.data(), "pbzx", 4)) Invalid("archive.unsupported_payload");
        chunk_size_ = BigEndian(header.data() + 4, 8);
        if (!chunk_size_ || chunk_size_ > 64 * 1024 * 1024) throw Failure{XipStatus::ResourceLimit, "archive.chunk_limit"};
    }
    ~Payload() { lzma_end(&decoder_); }
    void Read(std::span<std::uint8_t> destination) {
        while (!destination.empty()) {
            if (available_.empty() && !Next()) Invalid("archive.truncated_cpio");
            const auto size = std::min(destination.size(), available_.size());
            std::copy_n(available_.data(), size, destination.data());
            available_ = available_.subspan(size); destination = destination.subspan(size);
        }
    }
    void Consume(std::uint64_t size, XipVisitor& visitor) {
        while (size) {
            if (available_.empty() && !Next()) Invalid("archive.truncated_cpio");
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(size, available_.size()));
            try { visitor.Data(available_.first(count)); } catch (...) { throw Failure{XipStatus::ConsumerFailure, "archive.consumer_failed"}; }
            available_ = available_.subspan(count); size -= count;
        }
    }
    void Finish() {
        // CPIO permits NUL block padding after its trailer; no extra members.
        for (;;) {
            for (const auto byte : available_) if (byte) Invalid("archive.trailing_payload");
            available_ = {};
            if (!chunk_active_ && !remaining_) break;
            if (!Next()) break;
        }
        if (digest_) {
            if (digest_->Finish() != expected_checksum_) Invalid("archive.content_checksum_mismatch");
            result_.content_checksum_verified = true;
        }
    }
private:
    void Encoded(std::span<std::uint8_t> bytes) {
        if (bytes.size() > remaining_) Invalid("archive.truncated_pbzx");
        source_.Read(bytes);
        if (digest_) digest_->Update(bytes);
        remaining_ -= bytes.size(); result_.encoded_bytes += bytes.size();
    }
    void StartChunk() {
        if (!remaining_ || final_chunk_) Invalid("archive.truncated_cpio");
        std::array<std::uint8_t, 16> header{}; Encoded(header);
        decoded_expected_ = BigEndian(header.data(), 8); encoded_left_ = BigEndian(header.data() + 8, 8);
        if (!decoded_expected_ || decoded_expected_ > chunk_size_ || !encoded_left_ || encoded_left_ > remaining_)
            Invalid("archive.invalid_chunk");
        if (decoded_expected_ > options_.max_decoded_bytes - result_.decoded_bytes)
            throw Failure{XipStatus::ResourceLimit, "archive.decoded_limit"};
        raw_ = encoded_left_ == decoded_expected_; decoded_chunk_ = 0;
        final_chunk_ = decoded_expected_ < chunk_size_; chunk_active_ = true;
        if (!raw_) {
            lzma_end(&decoder_); decoder_ = LZMA_STREAM_INIT;
            if (lzma_stream_decoder(&decoder_, 256ull * 1024 * 1024, 0) != LZMA_OK)
                throw Failure{XipStatus::ResourceLimit, "archive.decoder_limit"};
        }
    }
    bool Next() {
        Check(options_);
        if (!chunk_active_ && !remaining_) return false;
        if (!chunk_active_) StartChunk();
        std::size_t count = 0;
        if (raw_) {
            count = static_cast<std::size_t>(std::min<std::uint64_t>(output_.size(), encoded_left_));
            Encoded(std::span(output_).first(count)); encoded_left_ -= count;
            if (!encoded_left_) chunk_active_ = false;
        } else {
            decoder_.next_out = output_.data(); decoder_.avail_out = output_.size();
            while (decoder_.avail_out && chunk_active_) {
                Check(options_);
                if (!decoder_.avail_in && encoded_left_) {
                    const auto size = static_cast<std::size_t>(std::min<std::uint64_t>(input_.size(), encoded_left_));
                    Encoded(std::span(input_).first(size)); encoded_left_ -= size;
                    decoder_.next_in = input_.data(); decoder_.avail_in = size;
                }
                const auto before_in = decoder_.avail_in, before_out = decoder_.avail_out;
                const auto code = lzma_code(&decoder_, encoded_left_ ? LZMA_RUN : LZMA_FINISH);
                if (code == LZMA_STREAM_END) {
                    if (decoder_.avail_in || encoded_left_) Invalid("archive.trailing_xz");
                    chunk_active_ = false;
                } else if (code == LZMA_MEMLIMIT_ERROR) throw Failure{XipStatus::ResourceLimit, "archive.decoder_limit"};
                else if (code != LZMA_OK || (before_in == decoder_.avail_in && before_out == decoder_.avail_out))
                    Invalid("archive.invalid_xz");
            }
            count = output_.size() - decoder_.avail_out;
        }
        decoded_chunk_ += count;
        if (decoded_chunk_ > decoded_expected_ || (!chunk_active_ && decoded_chunk_ != decoded_expected_)) Invalid("archive.chunk_size_mismatch");
        if (!chunk_active_ && final_chunk_ && remaining_) Invalid("archive.trailing_chunks");
        result_.decoded_bytes += count;
        const auto now = std::chrono::steady_clock::now();
        if ((context_ || options_.progress) && now - last_progress_ >= std::chrono::milliseconds(100)) {
            if (options_.progress) options_.progress(result_.encoded_bytes, result_.encoded_total);
            if (context_) {
                auto data = JsonValue::ObjectValue();
                data.Set("basis", JsonValue::String("archive_payload_bytes"));
                data.Set("completed_units", JsonValue::Number(std::to_string(result_.encoded_bytes)));
                data.Set("planned_units", JsonValue::Number(std::to_string(result_.encoded_total)));
                data.Set("decoded_bytes", JsonValue::Number(std::to_string(result_.decoded_bytes)));
                data.Set("entries", JsonValue::Number(std::to_string(result_.entries)));
                context_->Emit("progress.updated", std::move(data));
            }
            last_progress_ = now;
        }
        available_ = std::span(output_).first(count);
        if (available_.empty()) {
            if (!chunk_active_) return remaining_ ? Next() : false;
            Invalid("archive.truncated_cpio");
        }
        return true;
    }
    Source& source_;
    std::uint64_t remaining_, chunk_size_ = 0, encoded_left_ = 0, decoded_expected_ = 0, decoded_chunk_ = 0;
    const XipReadOptions& options_; XipReadResult& result_;
    bool chunk_active_ = false, raw_ = false, final_chunk_ = false;
    lzma_stream decoder_ = LZMA_STREAM_INIT;
    std::array<std::uint8_t, buffer_size> input_{}, output_{};
    std::optional<Digest> digest_;
    std::vector<std::uint8_t> expected_checksum_;
    std::span<const std::uint8_t> available_;
    OperationContextPtr context_ = CurrentOperationContext();
    std::chrono::steady_clock::time_point last_progress_ = std::chrono::steady_clock::now();
};
}
const char* XipStatusName(XipStatus status) noexcept {
    switch (status) {
    case XipStatus::Completed: return "completed";
    case XipStatus::Stopped: return "stopped";
    case XipStatus::InvalidArchive: return "invalid_archive";
    case XipStatus::IoFailure: return "io_failure";
    case XipStatus::ResourceLimit: return "resource_limit";
    case XipStatus::Cancelled: return "cancelled";
    case XipStatus::TimedOut: return "timed_out";
    case XipStatus::ConsumerFailure: return "consumer_failure";
    }
    return "invalid_archive";
}
XipReadResult XipArchive::Walk(const std::filesystem::path& path, XipVisitor& visitor, const XipReadOptions& options) {
    OperationSpan span("sdk.archive.read");
    XipReadResult result;
    try {
        Check(options);
        Source source(path, options);
        Payload payload(source, Locate(source, options, result), options, result);
        for (;;) {
            Check(options);
            std::array<std::uint8_t, 76> raw{}; payload.Read(raw);
            const std::string_view header(reinterpret_cast<const char*>(raw.data()), raw.size());
            if (!header.starts_with("070707")) Invalid("archive.unsupported_cpio");
            XipEntry entry;
            entry.device = static_cast<std::uint32_t>(Number(header.substr(6, 6), 8));
            entry.inode = static_cast<std::uint32_t>(Number(header.substr(12, 6), 8));
            entry.mode = static_cast<std::uint32_t>(Number(header.substr(18, 6), 8));
            // Validate all odc numeric fields even where extraction does not use them.
            Number(header.substr(24, 6), 8); Number(header.substr(30, 6), 8);
            entry.links = static_cast<std::uint32_t>(Number(header.substr(36, 6), 8));
            Number(header.substr(42, 6), 8); Number(header.substr(48, 11), 8);
            const auto name_size = Number(header.substr(59, 6), 8);
            entry.size = Number(header.substr(65, 11), 8);
            if (!name_size || name_size > 32768) throw Failure{XipStatus::ResourceLimit, "archive.name_limit"};
            std::vector<std::uint8_t> name(static_cast<std::size_t>(name_size)); payload.Read(name);
            if (name.back() || std::find(name.begin(), name.end() - 1, 0) != name.end() - 1) Invalid("archive.invalid_name");
            entry.path.assign(reinterpret_cast<const char*>(name.data()), name.size() - 1);
            if (entry.path == "TRAILER!!!") {
                if (entry.size) Invalid("archive.invalid_trailer");
                payload.Finish(); result.status = XipStatus::Completed; break;
            }
            if (++result.entries > options.max_entries) throw Failure{XipStatus::ResourceLimit, "archive.entry_limit"};
            try { visitor.Begin(entry); } catch (...) { throw Failure{XipStatus::ConsumerFailure, "archive.consumer_failed"}; }
            payload.Consume(entry.size, visitor);
            XipVisit visit;
            try { visit = visitor.End(); } catch (...) { throw Failure{XipStatus::ConsumerFailure, "archive.consumer_failed"}; }
            if (visit == XipVisit::Stop) { result.status = XipStatus::Stopped; break; }
        }
    } catch (const Failure& failure) { result.status = failure.status; result.error = failure.message; }
    catch (const std::bad_alloc&) { result.status = XipStatus::ResourceLimit; result.error = "archive.memory_limit"; }
    catch (...) { result.status = XipStatus::IoFailure; result.error = "archive.read_failed"; }
    auto data = JsonValue::ObjectValue();
    data.Set("status", JsonValue::String(XipStatusName(result.status)));
    data.Set("entries", JsonValue::Number(std::to_string(result.entries)));
    data.Set("encoded_bytes", JsonValue::Number(std::to_string(result.encoded_bytes)));
    data.Set("encoded_total", JsonValue::Number(std::to_string(result.encoded_total)));
    data.Set("decoded_bytes", JsonValue::Number(std::to_string(result.decoded_bytes)));
    data.Set("publisher_verified", JsonValue::Boolean(false));
    data.Set("toc_checksum_verified", JsonValue::Boolean(result.toc_checksum_verified));
    data.Set("content_checksum_verified", JsonValue::Boolean(result.content_checksum_verified));
    data.Set("xar_signature_valid", JsonValue::Boolean(result.xar_signature_valid));
    data.Set("apple_signing_chain_valid", JsonValue::Boolean(result.apple_signing_chain_valid));
    data.Set("apple_revocation_valid", JsonValue::Boolean(result.apple_revocation_valid));
    data.Set("diagnostic_code", JsonValue::String(result.error));
    span.Complete(std::move(data), result.status == XipStatus::Cancelled ? OperationOutcome::Cancelled :
        result.status == XipStatus::Completed || result.status == XipStatus::Stopped ? OperationOutcome::Succeeded : OperationOutcome::Failed);
    return result;
}
SDKArchiveMetadata SDKArchiveMetadata::DiscoverIos(const std::filesystem::path& path, const XipReadOptions& options) {
    SDKArchiveMetadata result;
    class Visitor final : public XipVisitor {
    public:
        explicit Visitor(SDKArchiveMetadata& result) : result_(result) {}
        void Begin(const XipEntry& entry) override {
            entry_ = entry; bytes_.clear();
            capture_ = (entry.mode & 0170000) == 0100000 && entry.path.ends_with(".sdk/SDKSettings.json") && entry.size <= 1024 * 1024;
        }
        void Data(std::span<const std::uint8_t> bytes) override { if (capture_) bytes_.append(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
        XipVisit End() override {
            if (!capture_) return XipVisit::Continue;
            const auto json = JsonValue::Parse(bytes_);
            if (!json || !json->IsObject()) return XipVisit::Continue;
            const auto* properties = json->Get("DefaultProperties");
            const auto* targets = json->Get("SupportedTargets");
            const auto version = json->GetString("Version");
            bool numeric = !version.empty() && version.size() <= 32, digit = false;
            for (const auto ch : version) { if (ch >= '0' && ch <= '9') digit = true; else if (ch == '.' && digit) digit = false; else numeric = false; }
            if (!numeric || !digit || !properties || !properties->IsObject() || properties->GetString("PLATFORM_NAME") != "iphoneos" ||
                !targets || !targets->IsObject() || !targets->Get("iphoneos") || !targets->Get("iphoneos")->IsObject()) return XipVisit::Continue;
            result_.sdk_root = entry_.path.substr(0, entry_.path.size() - std::strlen("/SDKSettings.json"));
            result_.version = version; result_.canonical_name = json->GetString("CanonicalName");
            return XipVisit::Stop;
        }
    private:
        SDKArchiveMetadata& result_; XipEntry entry_; std::string bytes_; bool capture_ = false;
    } visitor(result);
    result.read = XipArchive::Walk(path, visitor, options);
    return result;
}
JsonValue SDKArchiveMetadata::ToJson() const {
    auto data = JsonValue::ObjectValue();
    data.Set("schema_version", JsonValue::Number("1"));
    data.Set("status", JsonValue::String(XipStatusName(read.status)));
    data.Set("found", JsonValue::Boolean(Found()));
    data.Set("version", JsonValue::String(version));
    data.Set("canonical_name", JsonValue::String(canonical_name));
    data.Set("sdk_root", JsonValue::String(sdk_root));
    data.Set("encoded_bytes", JsonValue::Number(std::to_string(read.encoded_bytes)));
    data.Set("encoded_total", JsonValue::Number(std::to_string(read.encoded_total)));
    data.Set("decoded_bytes", JsonValue::Number(std::to_string(read.decoded_bytes)));
    data.Set("entries", JsonValue::Number(std::to_string(read.entries)));
    data.Set("diagnostic_code", JsonValue::String(read.error));
    data.Set("publisher_verified", JsonValue::Boolean(false));
    data.Set("toc_checksum_verified", JsonValue::Boolean(read.toc_checksum_verified));
    data.Set("content_checksum_verified", JsonValue::Boolean(read.content_checksum_verified));
    data.Set("xar_signature_valid", JsonValue::Boolean(read.xar_signature_valid));
    data.Set("apple_signing_chain_valid", JsonValue::Boolean(read.apple_signing_chain_valid));
    data.Set("apple_revocation_valid", JsonValue::Boolean(read.apple_revocation_valid));
    data.Set("archive_fully_read", JsonValue::Boolean(read.status == XipStatus::Completed));
    return data;
}
}
