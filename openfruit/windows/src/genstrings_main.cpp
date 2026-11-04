// genstrings: Xcode's localizable-string extractor, for build phases that
// invoke it by name.
#include "genstrings.hpp"

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>

namespace fs = std::filesystem;
using namespace OpenFruit::Genstrings;

namespace {

std::string Narrow(const std::wstring& text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size, nullptr, nullptr);
    return out;
}

std::wstring Widen(const std::string& text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size);
    return out;
}

// Sources are UTF-8, or UTF-16 when they carry a byte-order mark.
std::string ReadSource(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("couldn't read " + path.string());
    std::string bytes((std::istreambuf_iterator<char>(input)), {});
    if (bytes.size() >= 2 && static_cast<unsigned char>(bytes[0]) == 0xFF && static_cast<unsigned char>(bytes[1]) == 0xFE) {
        std::wstring wide(reinterpret_cast<const wchar_t*>(bytes.data() + 2), (bytes.size() - 2) / 2);
        return Narrow(wide);
    }
    if (bytes.size() >= 3 && bytes.compare(0, 3, "\xEF\xBB\xBF") == 0) bytes.erase(0, 3);
    return bytes;
}

void Usage() {
    std::cerr << "usage: genstrings [-a] [-q] [-o <outputDir>] [-s <routine>]... [-skipTable <table>]...\n"
                 "                  [-noPositionalParameters] [-u] [-bigEndian | -littleEndian] file...\n";
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    Options options;
    bool custom_routines = false, append = false, quiet = false, big_endian = false;
    fs::path output_dir = ".";
    std::set<std::string> skipped;
    std::vector<fs::path> files;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        const auto next = [&]() -> std::wstring {
            if (i + 1 >= argc) { Usage(); std::exit(1); }
            return argv[++i];
        };
        if (arg == L"-a") append = true;
        else if (arg == L"-q") quiet = true;
        else if (arg == L"-o") output_dir = next();
        else if (arg == L"-s") {
            if (!custom_routines) { options.routines.clear(); custom_routines = true; }
            options.routines.push_back(Narrow(next()));
        } else if (arg == L"-skipTable") skipped.insert(Narrow(next()));
        else if (arg == L"-noPositionalParameters") options.positional_parameters = false;
        else if (arg == L"-u") {} // \U escapes are kept as written, as .strings files accept them.
        else if (arg == L"-bigEndian") big_endian = true;
        else if (arg == L"-littleEndian") big_endian = false;
        else if (!arg.empty() && arg[0] == L'-') {
            std::cerr << "genstrings: unsupported option " << Narrow(arg) << "\n"; Usage(); return 1;
        } else files.emplace_back(arg);
    }
    if (files.empty()) { Usage(); return 1; }
    Tables tables;
    std::vector<std::string> warnings;
    try {
        for (const auto& file : files) {
            const auto extension = file.extension().wstring();
            const auto language = extension == L".swift" ? Language::Swift : Language::ObjectiveC;
            Extract(ReadSource(file), language, Narrow(file.wstring()), options, tables, warnings);
        }
        for (const auto& [name, table] : tables) {
            if (skipped.contains(name)) continue;
            const auto path = output_dir / Widen(name + ".strings");
            const auto mode = std::ios::binary | (append ? std::ios::app : std::ios::trunc);
            const bool fresh = !append || !fs::exists(path);
            std::ofstream out(path, mode);
            if (!out) throw std::runtime_error("couldn't write " + path.string());
            const auto text = Widen(Render(table));
            const auto put = [&](wchar_t unit) {
                const char lo = static_cast<char>(unit & 0xFF), hi = static_cast<char>((unit >> 8) & 0xFF);
                if (big_endian) { out.put(hi); out.put(lo); } else { out.put(lo); out.put(hi); }
            };
            if (fresh) put(0xFEFF);
            for (const auto unit : text) put(unit);
            if (!out) throw std::runtime_error("couldn't write " + path.string());
        }
    } catch (const std::exception& error) {
        std::cerr << "genstrings: error: " << error.what() << "\n";
        return 1;
    }
    if (!quiet) for (const auto& warning : warnings) std::cerr << "genstrings: warning: " << warning << "\n";
    return 0;
}
