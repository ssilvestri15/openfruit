#include "darwin_image.hpp"
#include "darwin_closure.hpp"
#include "darwin_mapping.hpp"
#include "darwin_arm64.hpp"
#include "darwin_files.hpp"
#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "operation_events.hpp"
#include "content_hash.hpp"
#include "json_value.hpp"
#include <fstream>
#include <array>
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <optional>
#include <windows.h>
#include <realtimeapiset.h>
#include <cstdlib>
#include <cstdio>

using namespace OpenFruit;
namespace fs = std::filesystem;
namespace {
thread_local const char* diagnostic_stage="setup";
void DiagnosticStage(const char* name){
    diagnostic_stage=name;
    if(GetEnvironmentVariableA("OPENFRUIT_TEST_TRACE",nullptr,0)>0){std::fprintf(stderr,"[darwin-image-stage] %s\n",name);std::fflush(stderr);}
}
LONG CALLBACK DiagnosticException(EXCEPTION_POINTERS* exception){
    if(exception&&exception->ExceptionRecord&&exception->ExceptionRecord->ExceptionCode==EXCEPTION_ACCESS_VIOLATION){
        const auto* record=exception->ExceptionRecord;
        std::fprintf(stderr,"[darwin-image-fault] stage=%s address=%p operation=%llu target=%p\n",diagnostic_stage,
            record->ExceptionAddress,static_cast<unsigned long long>(record->ExceptionInformation[0]),
            reinterpret_cast<void*>(record->ExceptionInformation[1]));
        void* frames[24]{};const auto count=CaptureStackBackTrace(0,24,frames,nullptr);
        for(unsigned n=0;n<count;++n){HMODULE module=nullptr;char path[MAX_PATH]{};
            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<const char*>(frames[n]),&module);
            if(module)GetModuleFileNameA(module,path,MAX_PATH);
            std::fprintf(stderr,"[darwin-image-frame] %u %s+0x%llx\n",n,path,
                static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(frames[n])-reinterpret_cast<std::uintptr_t>(module)));
        }
        std::fflush(stderr);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
void Require(bool value, const std::string& error) { if (!value) throw std::runtime_error(error); }
std::string Read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary); Require(bool(input), "fixture read failed");
    return {std::istreambuf_iterator<char>(input), {}};
}
void Write(const fs::path& path, const std::string& bytes) {
    std::ofstream output(path, std::ios::binary); output << bytes; Require(bool(output), "fixture write failed");
}
void Run(const fs::path& tool, std::vector<std::wstring> args) {
    args.insert(args.begin(), tool.wstring());
    const auto result = Win32Process::Run(tool.wstring(), args);
    if (!result.success) std::cerr << result.std_out << result.std_err;
    Require(result.success, "original compiler/linker fixture failed");
}
std::uint32_t Little32(std::string_view bytes, std::size_t offset) {
    Require(offset + 4 <= bytes.size(), "fixture integer missing");
    std::uint32_t value; std::memcpy(&value, bytes.data() + offset, 4); return value;
}
void Big32(std::string& bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes[offset + i] = static_cast<char>(value >> ((3 - i) * 8));
}
void Big64(std::string& bytes, std::size_t offset, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) bytes[offset + i] = static_cast<char>(value >> ((7 - i) * 8));
}
void Little32(std::string& bytes, std::size_t offset, std::uint32_t value) {
    std::memcpy(bytes.data() + offset, &value, 4);
}
JsonValue Metadata(const fs::path& path, const DarwinImage& image) {
    auto value = JsonValue::ObjectValue();
    value.Set("file", JsonValue::String(path.string()));
    value.Set("sha256", JsonValue::String(image.sha256));
    value.Set("cpu", JsonValue::Number(std::to_string(image.cpu)));
    value.Set("subtype", JsonValue::Number(std::to_string(image.subtype)));
    value.Set("platform", JsonValue::Number(std::to_string(image.platform)));
    value.Set("file_type", JsonValue::Number(std::to_string(image.file_type)));
    value.Set("slice_offset", JsonValue::Number(std::to_string(image.slice_offset)));
    value.Set("slice_size", JsonValue::Number(std::to_string(image.slice_size)));
    value.Set("install_name", JsonValue::String(image.install_name));
    auto rpaths = JsonValue::ArrayValue(), dependencies = JsonValue::ArrayValue();
    for (const auto& path : image.rpaths) rpaths.ArrayItems().push_back(JsonValue::String(path));
    for (const auto& dependency : image.dependencies) {
        auto entry = JsonValue::ObjectValue();
        entry.Set("install_name", JsonValue::String(dependency.install_name));
        entry.Set("weak", JsonValue::Boolean(dependency.weak));
        entry.Set("reexport", JsonValue::Boolean(dependency.reexport));
        entry.Set("upward", JsonValue::Boolean(dependency.upward));
        entry.Set("lazy", JsonValue::Boolean(dependency.lazy));
        dependencies.ArrayItems().push_back(std::move(entry));
    }
    value.Set("rpaths", std::move(rpaths)); value.Set("dependencies", std::move(dependencies));
    return value;
}
int Inventory() {
    const auto directory = ToolPaths::DarlingRoot({}) / "windows-plugin-view";
    auto report = JsonValue::ObjectValue(), images = JsonValue::ArrayValue(), errors = JsonValue::ArrayValue();
    std::error_code ec;
    for (fs::directory_iterator file(directory, ec), end; !ec && file != end; file.increment(ec)) {
        if (!file->is_regular_file(ec) || file->is_symlink(ec)) continue;
        DarwinImage image; std::string error;
        if (ReadDarwinImage(file->path(), image, error)) images.ArrayItems().push_back(Metadata(file->path(), image));
        else {
            auto entry = JsonValue::ObjectValue(); entry.Set("file", JsonValue::String(file->path().string()));
            entry.Set("error", JsonValue::String(error)); errors.ArrayItems().push_back(std::move(entry));
        }
    }
    if (ec) { std::cerr << ec.message() << '\n'; return 1; }
    report.Set("scope", JsonValue::String("Native read-only selected-host-slice load-command metadata; not transitive closure or execution"));
    report.Set("runtime_execution_validated", JsonValue::Boolean(false));
    report.Set("process_cpu", JsonValue::Number(std::to_string(DarwinProcessCpu())));
    report.Set("images", std::move(images)); report.Set("errors", std::move(errors));
    std::cout << report.Serialize(true) << '\n'; return 0;
}
}
int main(int argc, char** argv) {
    if(GetEnvironmentVariableA("OPENFRUIT_TEST_TRACE",nullptr,0)>0)SetUnhandledExceptionFilter(DiagnosticException);
    fs::path root;
    try {
        if (argc == 2 && std::string(argv[1]) == "--inventory") return Inventory();
        const auto clang = ToolPaths::SwiftBin({}) / "clang.exe";
        const auto linker = ToolPaths::LlvmBin({}) / "ld64.lld.exe";
        if (!fs::is_regular_file(clang) || !fs::is_regular_file(linker)) return 77;
        root = fs::temp_directory_path() / ("OPENFRUIT-darwin-image-" + NewOperationId());
        fs::create_directories(root);
        Write(root / "provider.c", "int needed = 17;\n");
        Write(root / "consumer.c", "extern int needed; int* result(void) { return &needed; }\n");
        std::vector<std::string> thin;
        for (const auto& arch : {std::wstring(L"x86_64"), std::wstring(L"arm64")}) {
            const auto minimum = arch == L"arm64" ? L"11.0" : L"10.15";
            const auto provider = root / (arch + L"-provider.dylib");
            const auto consumer = root / (arch + L"-consumer.dylib");
            for (const auto* name : {L"provider", L"consumer"})
                Run(clang, {L"-target", arch + L"-apple-macos" + minimum, L"-c", (root / (std::wstring(name) + L".c")).wstring(),
                    L"-o", (root / (std::wstring(name) + L".o")).wstring()});
            Run(linker, {L"-dylib", L"-arch", arch, L"-platform_version", L"macos", minimum, L"26.0",
                L"-install_name", L"@rpath/libOwnedProvider.dylib", L"-o", provider.wstring(), (root / "provider.o").wstring()});
            Run(linker, {L"-dylib", L"-arch", arch, L"-platform_version", L"macos", minimum, L"26.0",
                L"-install_name", L"@rpath/libOwnedConsumer.dylib", L"-rpath", L"@loader_path/../libraries",
                L"-weak_library", provider.wstring(), L"-o", consumer.wstring(), (root / "consumer.o").wstring()});
            thin.push_back(Read(consumer));
            DarwinImage image; std::string error;
            Require(InspectDarwinImage(thin.back(), Little32(thin.back(), 4), image, error), error);
            Require(image.install_name == "@rpath/libOwnedConsumer.dylib" && image.platform == 1 &&
                image.dependencies.size() == 1 && image.dependencies[0].weak &&
                image.dependencies[0].install_name == "@rpath/libOwnedProvider.dylib" &&
                image.rpaths == std::vector<std::string>{"@loader_path/../libraries"}, "compiler metadata not derived");
        }
        const std::uint32_t first = 4096, second = (first + static_cast<std::uint32_t>(thin[0].size()) + 4095) & ~4095u;
        std::string fat(second + thin[1].size(), '\0');
        Big32(fat, 0, 0xcafebabe); Big32(fat, 4, 2);
        for (unsigned i = 0; i < 2; ++i) {
            const auto offset = i ? second : first;
            Big32(fat, 8 + i * 20, Little32(thin[i], 4)); Big32(fat, 12 + i * 20, Little32(thin[i], 8));
            Big32(fat, 16 + i * 20, offset); Big32(fat, 20 + i * 20, static_cast<std::uint32_t>(thin[i].size()));
            Big32(fat, 24 + i * 20, 12); fat.replace(offset, thin[i].size(), thin[i]);
        }
        const auto path = root / "opaque-image";
        Write(path, fat);
        DarwinImage image; std::string error;
        Require(ReadDarwinImage(path, image, error), error);
        Require(image.cpu == DarwinProcessCpu() && image.sha256 == Sha256File(path), "host selection/hash failed");
        std::vector<DarwinImage> inventory;
        Require(ReadDarwinImageSlices(path, inventory, error) && inventory.size() == thin.size(), error);
        for (unsigned index = 0; index < inventory.size(); ++index) {
            Require(inventory[index].cpu == Little32(thin[index], 4) && inventory[index].subtype == Little32(thin[index], 8)
                && inventory[index].sha256 == Sha256File(path) && inventory[index].dependencies.size() == 1
                && inventory[index].dependencies[0].weak, "all-slice original metadata/hash not derived");
        }
        const auto foreign = DarwinProcessCpu() == Little32(thin[0], 4) ? 1u : 0u;
        const auto foreign_path = root / "foreign-image"; Write(foreign_path, thin[foreign]);
        Require(ReadDarwinImageSlices(foreign_path, inventory, error) && inventory.size() == 1
            && inventory.front().cpu == Little32(thin[foreign], 4), "foreign slice metadata rejected");
        Require(!ReadDarwinImage(foreign_path, image, error) && image.sha256.empty(), "foreign inventory bypassed runtime host CPU gate");
        if (argc == 2) {
            const auto executable = fs::absolute(argv[1]).wstring();
            const auto cli = Win32Process::Run(executable, {executable, L"runtime", L"inspect-image", path.wstring()},
                L"", {{L"OPENFRUIT_USER_STATE", root.wstring()}});
            const auto json = JsonValue::Parse(cli.std_out);
            Require(cli.success && json && json->Get("metadata_inspected")->Bool(false)
                && json->Get("images")->ArrayItems().size() == thin.size()
                && !json->Get("execution_validated")->Bool(true) && !json->Get("closure_complete")->Bool(true)
                && !fs::exists(root / "config.toml") && !fs::exists(root / "credentials"), "native CLI inventory propagation or read-only boundary failed");
        }

        for (unsigned i = 0; i < 2; ++i) {
            Require(InspectDarwinImage(fat, Little32(thin[i], 4), image, error), error);
            Require(image.slice_offset == (i ? second : first) && image.slice_size == thin[i].size(), "wrong FAT slice selected");
        }
        auto fat64 = fat;
        Big32(fat64, 0, 0xcafebabf);
        for (unsigned i = 0; i < 2; ++i) {
            const auto p = 8 + i * 32;
            Big32(fat64, p, Little32(thin[i], 4)); Big32(fat64, p + 4, Little32(thin[i], 8));
            Big64(fat64, p + 8, i ? second : first); Big64(fat64, p + 16, thin[i].size());
            Big32(fat64, p + 24, 12); Big32(fat64, p + 28, 0);
        }
        Require(InspectDarwinImage(fat64, DarwinProcessCpu(), image, error), error);
        Require(InspectDarwinImageSlices(fat64, inventory, error) && inventory.size() == 2, "FAT64 slice inventory failed");
        auto swapped = fat;
        Little32(swapped, 0, 0xcafebabe); Little32(swapped, 4, 2);
        for (unsigned i = 0; i < 2; ++i) {
            const auto p = 8 + i * 20;
            Little32(swapped, p, Little32(thin[i], 4)); Little32(swapped, p + 4, Little32(thin[i], 8));
            Little32(swapped, p + 8, i ? second : first); Little32(swapped, p + 12, static_cast<std::uint32_t>(thin[i].size()));
            Little32(swapped, p + 16, 12);
        }
        Require(InspectDarwinImage(swapped, DarwinProcessCpu(), image, error), error);
        Require(InspectDarwinImageSlices(swapped, inventory, error) && inventory.size() == 2, "FAT32 swapped slice inventory failed");
        HANDLE writer = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        Require(writer != INVALID_HANDLE_VALUE, "owned concurrent writer fixture failed");
        const bool denied = !ReadDarwinImage(path, image, error);
        const bool inventory_denied = !ReadDarwinImageSlices(path, inventory, error);
        CloseHandle(writer);
        Require(denied && inventory_denied && inventory.empty() && image.sha256.empty(), "mutable image was accepted as a stable snapshot");
        Require(ReadDarwinImage(path, image, error), error);
        const auto reject = [&](const std::string& bytes) {
            Require(!InspectDarwinImage(bytes, DarwinProcessCpu(), image, error) && !error.empty() &&
                image.dependencies.empty() && image.segments.empty(), "malformed/unsupported image accepted or partial metadata leaked");
        };
        reject("MZowned PE sentinel"); reject(fat.substr(0, 40));
        auto foreign_bad = fat; Little32(foreign_bad, (foreign ? second : first) + 12, 1);
        Require(InspectDarwinImage(foreign_bad, DarwinProcessCpu(), image, error), "host selection unexpectedly reads foreign image header");
        Require(!InspectDarwinImageSlices(foreign_bad, inventory, error) && inventory.empty() && !error.empty(),
            "invalid foreign slice leaked partial inventory");
        auto unsupported = fat; Big32(unsupported, 12 + foreign * 20, 8);
        Require(!InspectDarwinImageSlices(unsupported, inventory, error) && inventory.empty(), "specialized CPU silently inventoried");
        auto bad = fat; Big32(bad, 36, first); reject(bad); // overlapping slices
        bad = fat; Big32(bad, 20, 0xffffffff); reject(bad);
        bad = fat; Big32(bad, 24, 63); reject(bad);
        bad = fat64; Big64(bad, 16, std::uint64_t{1} << 63); reject(bad);
        bad = fat64; Big32(bad, 36, 1); reject(bad);
        const auto selected = DarwinProcessCpu() == Little32(thin[0], 4) ? 0 : 1;
        const auto start = selected ? second : first;
        bad = fat; Little32(bad, start + 8, 8); reject(bad); // header/table ABI disagreement
        bad = fat; Little32(bad, start + 20, 0xffffffff); reject(bad);
        bad = fat; Little32(bad, start + 36, 7); reject(bad);
        bad = fat;
        Big32(bad, selected ? 8 : 28, DarwinProcessCpu());
        Big32(bad, selected ? 12 : 32, Little32(thin[selected], 8));
        reject(bad);
        Require(error.find("Ambiguous") != std::string::npos, "duplicate host slices not classified as ambiguous");
        auto commands = thin[selected];
        for (std::size_t p = 32; p < 32 + Little32(commands, 20); p += Little32(commands, p + 4)) {
            if (Little32(commands, p) == 0x8000001c) {
                Little32(commands, p + 8, 0xffffffff); reject(commands); break;
            }
        }
        const auto tree = root / "original-tree"; fs::create_directories(tree / "origin/runtime");
        Write(root / "child.c", "extern int needed; int childValue = 3; int* child(void) { return &needed; }\n");
        Write(root / "parent.c", "extern int childValue; static int localValue=1; int* localPointer=&localValue; int* parent(void) { return &childValue; }\n");
        const auto arch = DarwinProcessCpu() == Little32(thin[0], 4) ? L"x86_64" : L"arm64";
        const auto minimum = std::wstring(arch) == L"arm64" ? L"11.0" : L"10.15";
        for (const auto* source : {L"provider", L"child", L"parent"})
            Run(clang, {L"-target", std::wstring(arch) + L"-apple-macos" + minimum, L"-c", (root / (std::wstring(source) + L".c")).wstring(),
                L"-o", (root / (std::wstring(source) + L".o")).wstring()});
        const auto leaf = tree / "origin/runtime/libLeaf.dylib", child = tree / "origin/runtime/libChild.dylib", parent = tree / "origin/server";
        Run(linker, {L"-dylib", L"-arch", arch, L"-platform_version", L"macos", minimum, L"26.0",
            L"-install_name", L"@rpath/libLeaf.dylib", L"-o", leaf.wstring(), (root / "provider.o").wstring()});
        Run(linker, {L"-dylib", L"-arch", arch, L"-platform_version", L"macos", minimum, L"26.0",
            L"-install_name", L"@rpath/libChild.dylib", L"-o", child.wstring(), (root / "child.o").wstring(), leaf.wstring()});
        Run(linker, {L"-dylib", L"-arch", arch, L"-platform_version", L"macos", minimum, L"26.0",
            L"-install_name", L"@rpath/libParent.dylib", L"-rpath", L"@loader_path/runtime",
            L"-o", parent.wstring(), (root / "parent.o").wstring(), child.wstring()});
        const auto graph = DarwinClosure::Inspect("/origin/server", {}, {tree});
        Require(graph.StrongImagesResolved() && graph.images.size() == 3 && graph.edges.size() == 2
            && graph.edges[1].owner == "/origin/runtime/libChild.dylib"
            && graph.edges[1].resolved_path == "/origin/runtime/libLeaf.dylib", "original inherited RPATH chain not derived from compiler metadata");
        DarwinImage exported; Require(ReadDarwinImage(child, exported, error), error);
        const auto found_export = std::find_if(exported.exports.begin(), exported.exports.end(), [](const auto& symbol) {
            return symbol.symbol == "_childValue";
        });
        Require(exported.exports_present && found_export != exported.exports.end() && found_export->flags == 0,
            "real compiler-produced regular export not derived");
        const auto header_segment = std::find_if(exported.segments.begin(), exported.segments.end(), [](const auto& segment) {
            return segment.file_offset == 0 && segment.file_size;
        });
        Require(header_segment != exported.segments.end(), "owned export header segment absent");
        const auto symbol_address = header_segment->address + found_export->value;
        const auto symbol_segment = std::find_if(exported.segments.begin(), exported.segments.end(), [&](const auto& segment) {
            return symbol_address >= segment.address && symbol_address - segment.address + 4 <= segment.file_size;
        });
        const auto child_bytes = Read(child);
        Require(symbol_segment != exported.segments.end() && Little32(child_bytes,
            symbol_segment->file_offset + symbol_address - symbol_segment->address) == 3,
            "export VM offset does not identify original compiler-produced initializer");
        const auto export_offset = static_cast<std::size_t>(exported.exports_file_offset);
        const auto reject_export = [&](const std::string& bytes) {
            Require(!InspectDarwinImage(bytes, DarwinProcessCpu(), exported, error) && !error.empty()
                && exported.exports.empty() && !exported.exports_present, "malformed export leaked partial image");
        };
        auto malformed_export = child_bytes;
        Require(exported.exports_data_size >= 10, "owned export fixture too short");
        for (unsigned i = 0; i < 10; ++i) malformed_export[export_offset + i] = static_cast<char>(0x80);
        reject_export(malformed_export);
        malformed_export = child_bytes; malformed_export[export_offset] = static_cast<char>(0x7f); reject_export(malformed_export);
        Require(child_bytes[export_offset] == 0 && child_bytes[export_offset + 1] != 0, "owned trie root lacks children");
        const auto edge_end = child_bytes.find('\0', export_offset + 2);
        Require(edge_end != std::string::npos && static_cast<unsigned char>(child_bytes[edge_end + 1]) < 128,
            "owned export first child offset not single-byte");
        malformed_export = child_bytes; malformed_export[edge_end + 1] = 0; reject_export(malformed_export);
        fs::create_directories(tree / "wrong"); fs::rename(leaf, tree / "wrong/libLeaf.dylib");
        const auto missing = DarwinClosure::Inspect("/origin/server", {}, {tree});
        Require(missing.analyzed && !missing.StrongImagesResolved() && missing.images.size() == 2
            && missing.edges.back().resolved_path.empty(), "basename-only provider incorrectly satisfied original path");
        fs::rename(tree / "wrong/libLeaf.dylib", leaf);
        fs::rename(leaf, tree / "origin/runtime/LIBLEAF.dylib");
        Require(!DarwinClosure::Inspect("/origin/server", {}, {tree}).StrongImagesResolved(), "Windows case folding incorrectly resolved Darwin dependency");
        fs::rename(tree / "origin/runtime/LIBLEAF.dylib", leaf);
        const auto ambiguous = DarwinClosure::Inspect("/origin/server", {}, {tree, tree});
        Require(!ambiguous.analyzed && ambiguous.images.empty() && ambiguous.edges.empty(), "ambiguous original mounts accepted");
        DarwinClosureOptions limits; limits.max_images = 1;
        Require(!DarwinClosure::Inspect("/origin/server", {}, {tree}, limits).analyzed, "closure image budget ignored");
        CancellationSource stop; stop.Cancel(); limits = {}; limits.cancellation = stop.Token();
        Require(!DarwinClosure::Inspect("/origin/server", {}, {tree}, limits).analyzed, "closure cancellation ignored");
        limits = {}; limits.deadline = std::chrono::steady_clock::now();
        Require(!DarwinClosure::Inspect("/origin/server", {}, {tree}, limits).analyzed, "closure deadline ignored");
        Require(!DarwinClosure::Inspect("/../../escape", {}, {tree}).analyzed, "virtual root escape accepted");
        if (argc == 2) {
            const auto executable = fs::absolute(argv[1]).wstring();
            const auto cli = Win32Process::Run(executable, {executable, L"runtime", L"inspect-closure", L"/origin/server", L"-", tree.wstring()});
            const auto report = JsonValue::Parse(cli.std_out);
            Require(cli.success && report && report->Get("analysis_complete")->Bool(false)
                && report->Get("strong_image_dependencies_resolved")->Bool(false)
                && !report->Get("execution_validated")->Bool(true), "native closure CLI propagation failed");
        }
        const auto chained_path = root / "compiler-chained.dylib";
        Run(linker, {L"-dylib", L"-arch", arch, L"-platform_version", L"macos", L"11.0", L"26.0",
            L"-install_name", L"@rpath/libChained.dylib", L"-fixup_chains", L"-o", chained_path.wstring(),
            (root / "parent.o").wstring(), child.wstring()});
        const auto chained_bytes = Read(chained_path);
        Require(ReadDarwinImage(chained_path, image, error) && image.chained_fixups.present
            && image.chained_fixups.imports.size() == 1 && image.chained_fixups.imports.front().symbol == "_childValue"
            && image.chained_fixups.imports.front().library_ordinal == 1 && !image.chained_fixups.imports.front().weak
            && !image.chained_fixups.segments.empty(), "real LLD chained imports/page metadata not derived");
        Require(image.exports_present && !image.exports.empty(), "modern chained image export trie not parsed");
        const auto chain_offset = static_cast<std::size_t>(image.chained_fixups.file_offset);
        Require(image.chained_fixups.pointers_walked && image.chained_fixups.pointers.size() >= 2,
            "compiler-produced pointer chains not walked");
        std::optional<DarwinChainedPointer> bind_pointer, rebase_pointer;
        for (const auto& pointer : image.chained_fixups.pointers) {
            if (pointer.bind) bind_pointer = pointer; else rebase_pointer = pointer;
        }
        Require(bind_pointer && rebase_pointer && bind_pointer->import_index == 0,
            "real chained bind/rebase locations not derived");
        const auto chain_reject = [&](std::string bytes) {
            Require(!InspectDarwinImage(bytes, DarwinProcessCpu(), image, error) && !error.empty()
                && !image.chained_fixups.present && image.dependencies.empty(), "malformed chained payload accepted or partial result leaked");
        };
        auto malformed_chain = chained_bytes; Little32(malformed_chain, chain_offset, 1); chain_reject(malformed_chain);
        const auto put_pointer = [](std::string& bytes, std::size_t offset, std::uint64_t bits) {
            for (unsigned i = 0; i < 8; ++i) bytes[offset + i] = static_cast<char>(bits >> (i * 8));
        };
        malformed_chain = chained_bytes;
        put_pointer(malformed_chain, bind_pointer->file_offset, (1ull << 63) | 0xffffff); chain_reject(malformed_chain);
        malformed_chain = chained_bytes;
        put_pointer(malformed_chain, bind_pointer->file_offset, (1ull << 63) | (1ull << 32)); chain_reject(malformed_chain);
        malformed_chain = chained_bytes;
        put_pointer(malformed_chain, rebase_pointer->file_offset, (1ull << 44)); chain_reject(malformed_chain);
        malformed_chain = chained_bytes;
        put_pointer(malformed_chain, bind_pointer->file_offset, (1ull << 63) | (0xfffull << 51)); chain_reject(malformed_chain);
        // Format-6 targets are offsets; make a diagnostic copy of the owned
        // format-2 fixture to exercise decoding without modifying its source.
        auto offset_chain = chained_bytes;
        const auto starts_table = chain_offset + Little32(chained_bytes, chain_offset + 4);
        for (std::size_t i = 0; i < Little32(chained_bytes, starts_table); ++i) {
            const auto relative = Little32(chained_bytes, starts_table + 4 + i * 4);
            if (relative) { offset_chain[starts_table + relative + 6] = 6; offset_chain[starts_table + relative + 7] = 0; }
        }
        Require(InspectDarwinImage(offset_chain, DarwinProcessCpu(), image, error)
            && image.chained_fixups.pointers_walked && image.chained_fixups.pointers.front().target_is_offset,
            "format-6 pointer representation not decoded");
        malformed_chain = chained_bytes; Little32(malformed_chain, chain_offset + 4, 0xffffffff); chain_reject(malformed_chain);
        malformed_chain = chained_bytes; Little32(malformed_chain, chain_offset + 8, 0xffffffff); chain_reject(malformed_chain);
        malformed_chain = chained_bytes; Little32(malformed_chain, chain_offset + 12, 0xffffffff); chain_reject(malformed_chain);
        malformed_chain = chained_bytes; Little32(malformed_chain, chain_offset + 16, 0xffffffff); chain_reject(malformed_chain);
        malformed_chain = chained_bytes; Little32(malformed_chain, chain_offset + 20, 99); chain_reject(malformed_chain);
        malformed_chain = chained_bytes; Little32(malformed_chain, chain_offset + 24, 1); chain_reject(malformed_chain);
        const auto import_offset = chain_offset + Little32(chained_bytes, chain_offset + 8);
        malformed_chain = chained_bytes; Little32(malformed_chain, import_offset, 0xffffffff); chain_reject(malformed_chain);
        const auto flat_path = root / "compiler-flat.dylib";
        Run(linker, {L"-dylib", L"-arch", arch, L"-platform_version", L"macos", L"11.0", L"26.0",
            L"-install_name", L"@rpath/libFlat.dylib", L"-fixup_chains", L"-undefined", L"dynamic_lookup", L"-o", flat_path.wstring(),
            (root / "parent.o").wstring()});
        Require(ReadDarwinImage(flat_path, image, error) && image.chained_fixups.imports.size() == 1
            && image.chained_fixups.imports[0].library_ordinal == -2 && image.dependencies.empty(),
            "real special flat ordinal not decoded from chained import");
        Require(Read(chained_path) == chained_bytes, "owned original chained image changed");
        const auto map_tree = root / "mapping-tree"; fs::create_directories(map_tree / "origin/runtime");
        const auto map_leaf = map_tree / "origin/runtime/libLeaf.dylib", map_child = map_tree / "origin/runtime/libChild.dylib";
        const auto map_parent = map_tree / "origin/server";
        Run(linker, {L"-dylib", L"-arch", arch, L"-platform_version", L"macos", L"11.0", L"26.0", L"-fixup_chains",
            L"-install_name", L"@rpath/libLeaf.dylib", L"-o", map_leaf.wstring(), (root / "provider.o").wstring()});
        Run(linker, {L"-dylib", L"-arch", arch, L"-platform_version", L"macos", L"11.0", L"26.0", L"-fixup_chains",
            L"-install_name", L"@rpath/libChild.dylib", L"-o", map_child.wstring(), (root / "child.o").wstring(), map_leaf.wstring()});
        Run(linker, {L"-dylib", L"-arch", arch, L"-platform_version", L"macos", L"11.0", L"26.0", L"-fixup_chains",
            L"-install_name", L"@rpath/libParent.dylib", L"-rpath", L"@loader_path/runtime", L"-o", map_parent.wstring(),
            (root / "parent.o").wstring(), map_child.wstring()});
        const auto map_plugin=map_tree / "origin/plugin.dylib";
        Run(linker,{L"-dylib",L"-arch",arch,L"-platform_version",L"macos",L"11.0",L"26.0",L"-fixup_chains",
            L"-install_name",L"@rpath/libAdditional.dylib",L"-rpath",L"@loader_path/runtime",L"-o",map_plugin.wstring(),
            (root / "parent.o").wstring(),map_child.wstring()});
        const auto original_plugin=Read(map_plugin);
        auto with_plugin=DarwinMappedImages::Load("/origin/server",{map_tree},error,{},DarwinMappingMode::NativeCpu,{}, {"/origin/plugin.dylib"});
        Require(with_plugin&&with_plugin->ImageCount()==4,"Additional original plugin graph not mapped: "+error);
        Require(with_plugin->EagerInitializationOrder()==std::vector<std::string>{"/origin/runtime/libLeaf.dylib","/origin/runtime/libChild.dylib","/origin/server","/origin/plugin.dylib"},"Dependency/plugin initialization order not propagated to mapped images");
        const auto plugin_pointer=static_cast<const int* const*>(with_plugin->Symbol("/origin/plugin.dylib","_localPointer",error));
        Require(plugin_pointer&&*plugin_pointer&&**plugin_pointer==1,"Plugin rebase not applied in mapped memory");
        Require(Read(map_plugin)==original_plugin,"Original plugin mapping changed source bytes");
        with_plugin.reset();
        Require(!DarwinMappedImages::Load("/origin/server",{map_tree},error,{},DarwinMappingMode::NativeCpu,{}, {"/origin/absent.dylib"})
            &&error=="Original root image is missing.","Missing plugin silently accepted or lost causal diagnostic");
        const auto map_original_parent = Read(map_parent), map_original_child = Read(map_child), map_original_leaf = Read(map_leaf);
        auto mapped = DarwinMappedImages::Load("/origin/server", {map_tree}, error);
        Require(mapped && error.empty() && mapped->ImageCount() == 3 && mapped->AppliedFixups() >= 3, "native map/fixup failed: " + error);
        const auto mapped_child_value = static_cast<const int*>(mapped->Symbol("/origin/runtime/libChild.dylib", "_childValue", error));
        Require(mapped_child_value && *mapped_child_value == 3, "mapped export original initializer lost");
        const auto mapped_needed = static_cast<const int*>(mapped->Symbol("/origin/runtime/libLeaf.dylib", "_needed", error));
        Require(mapped_needed && *mapped_needed == 17, "transitive mapped export lost");
        const auto mapped_local_pointer = static_cast<const int* const*>(mapped->Symbol("/origin/server", "_localPointer", error));
        Require(mapped_local_pointer && *mapped_local_pointer && **mapped_local_pointer == 1, "original local rebase not applied in mapped memory");
        DarwinImage mapped_metadata; Require(ReadDarwinImage(map_parent, mapped_metadata, error), error);
        const auto mapped_function = static_cast<const char*>(mapped->Symbol("/origin/server", "_parent", error));
        Require(mapped_function, "mapped code export missing");
        const auto function_export = std::find_if(mapped_metadata.exports.begin(), mapped_metadata.exports.end(), [](const auto& symbol) { return symbol.symbol == "_parent"; });
        Require(function_export != mapped_metadata.exports.end(), "owned parent metadata missing");
        const auto mapped_base = reinterpret_cast<std::uintptr_t>(mapped_function) - function_export->value;
        const auto header_vm = std::find_if(mapped_metadata.segments.begin(), mapped_metadata.segments.end(), [](const auto& segment) { return !segment.file_offset && segment.file_size; })->address;
        bool verified_original_bind = false;
        for (const auto& pointer : mapped_metadata.chained_fixups.pointers) if (pointer.bind) {
            std::uint64_t value = 0; std::memcpy(&value, reinterpret_cast<const void*>(mapped_base + pointer.address - header_vm), 8);
            Require(value == reinterpret_cast<std::uint64_t>(mapped_child_value), "bind write did not resolve actual dependency export");
            verified_original_bind = true;
        }
        Require(verified_original_bind, "owned mapped graph did not exercise original bind");
        if (argc == 2) {
            const auto executable = fs::absolute(argv[1]).wstring();
            const auto cli = Win32Process::Run(executable, {executable, L"runtime", L"map-image", L"/origin/server", map_tree.wstring()});
            const auto report = JsonValue::Parse(cli.std_out);
            Require(cli.success && report && report->Get("mapped")->Bool(false)
                && !report->Get("runtime_initialized")->Bool(true) && !report->Get("execution_validated")->Bool(true),
                "native mapping CLI propagation failed");
        }
        MEMORY_BASIC_INFORMATION mapping_info{};
        Require(VirtualQuery(mapped_function, &mapping_info, sizeof(mapping_info)) && mapping_info.Protect == PAGE_EXECUTE_READ,
            "original code segment protection not preserved");
        const auto released_address = mapped_base;
        mapped.reset();
        Require(VirtualQuery(reinterpret_cast<const void*>(released_address), &mapping_info, sizeof(mapping_info)) && mapping_info.State == MEM_FREE,
            "native image allocation not released");
        Require(!DarwinMappedImages::Load("/origin/server", {tree}, error) && !error.empty(), "legacy fixups silently ignored by native mapper");
        fs::rename(map_leaf, map_tree / "missing-leaf.dylib");
        Require(!DarwinMappedImages::Load("/origin/server", {map_tree}, error) && !error.empty(), "missing strong original provider silently mapped");
        fs::rename(map_tree / "missing-leaf.dylib", map_leaf);
        Write(root / "replacement.c", "int alternativeValue=3;\n");
        Run(clang, {L"-target", std::wstring(arch) + L"-apple-macos11.0", L"-c", (root / "replacement.c").wstring(),
            L"-o", (root / "replacement.o").wstring()});
        Run(linker, {L"-dylib", L"-arch", arch, L"-platform_version", L"macos", L"11.0", L"26.0", L"-fixup_chains",
            L"-install_name", L"@rpath/libChild.dylib", L"-o", map_child.wstring(), (root / "replacement.o").wstring()});
        Require(!DarwinMappedImages::Load("/origin/server", {map_tree}, error)
            && error.find("strong imported symbol") != std::string::npos, "missing strong export silently bound");
        Write(map_child, map_original_child);
        auto unknown_command = map_original_parent;
        for (std::size_t p = 32; p < 32 + Little32(unknown_command, 20); p += Little32(unknown_command, p + 4)) {
            if (Little32(unknown_command, p) == 0xd) { Little32(unknown_command, p, 0x8000ffff); break; }
        }
        Write(map_parent, unknown_command);
        Require(!DarwinMappedImages::Load("/origin/server", {map_tree}, error)
            && error.find("Required Mach-O command") != std::string::npos, "unknown required command silently mapped");
        Write(map_parent, map_original_parent);
        CancellationSource map_cancel; map_cancel.Cancel(); DarwinClosureOptions map_options; map_options.cancellation = map_cancel.Token();
        Require(!DarwinMappedImages::Load("/origin/server", {map_tree}, error, map_options) && !error.empty(), "cancelled mapping published");
        Require(Read(map_parent) == map_original_parent && Read(map_child) == map_original_child && Read(map_leaf) == map_original_leaf,
            "native mapping changed original file bytes");
        const auto startup_source=root/"startup.c",startup_object=root/"startup.o",startup_path=root/"startup";
        Write(startup_source,"int startupInitialized; __thread int startupTls=7; __thread int startupZero;\n"
            "__attribute__((constructor)) static void startupInit(void){startupInitialized=42;}\n"
            "int main(void){return startupInitialized+startupTls+startupZero;}\n");
        Run(clang,{L"-target",std::wstring(arch)+L"-apple-macos11.0",L"-c",startup_source.wstring(),L"-o",startup_object.wstring()});
        // Legacy linking preserves constructor pointers; chained linking below emits offsets.
        Run(linker,{L"-arch",arch,L"-platform_version",L"macos",L"11.0",L"26.0",L"-headerpad",L"1000",L"-undefined",L"dynamic_lookup",L"-e",L"_main",L"-o",startup_path.wstring(),startup_object.wstring()});
        const auto startup_bytes=Read(startup_path);DarwinImage startup_metadata;
        Require(ReadDarwinImage(startup_path,startup_metadata,error)&&startup_metadata.entrypoint.present&&startup_metadata.entrypoint.address,
            "Original main entrypoint not derived: "+error);
        const auto startup_has=[&](unsigned kind){return std::any_of(startup_metadata.sections.begin(),startup_metadata.sections.end(),[&](const auto& section){return (section.flags&255)==kind;});};
        Require(startup_has(9)&&startup_has(17)&&startup_has(18)&&startup_has(19),"Original constructor/TLS section metadata not preserved");
        Require(std::any_of(startup_metadata.sections.begin(),startup_metadata.sections.end(),[](const auto& section){return section.name=="__unwind_info"||section.name=="__eh_frame";}),"Original unwind section metadata lost");
        Require(startup_metadata.ToJson().Get("sections")->ArrayItems().size()==startup_metadata.sections.size()
            &&startup_metadata.ToJson().Get("entrypoint")->Get("present")->Bool(),"Native startup metadata serialization lost fields");
        const auto startup_bad=[&](const std::string& bytes){DarwinImage rejected;Require(!InspectDarwinImage(bytes,DarwinProcessCpu(),rejected,error)&&rejected.sections.empty()&&!rejected.entrypoint.present&&!rejected.unix_thread.present,"Malformed startup metadata accepted or partial data published");};
        std::size_t startup_main_command=0,startup_section=0;
        for(std::size_t p=32;p<32+Little32(startup_bytes,20);p+=Little32(startup_bytes,p+4)){
            if(Little32(startup_bytes,p)==0x80000028)startup_main_command=p;
            if(!startup_section&&Little32(startup_bytes,p)==0x19&&Little32(startup_bytes,p+64))startup_section=p+72;
        }
        Require(startup_main_command&&startup_section,"Real linker startup commands absent");
        const auto unix_command=[&](std::uint32_t cpu){
            const auto arm=cpu==0x0100000c;const auto words=arm?68u:42u;
            std::string command(16+words*4,'\0');Little32(command,0,5);Little32(command,4,static_cast<std::uint32_t>(command.size()));
            Little32(command,8,arm?6:4);Little32(command,12,words);Little32(command,16,0x12345678);
            const auto pc=startup_metadata.entrypoint.address;std::memcpy(command.data()+16+(arm?32:16)*8,&pc,8);
            return command;};
        for(const auto cpu:{0x01000007u,0x0100000cu}){
            auto owner=startup_metadata;owner.cpu=cpu;auto command=unix_command(cpu);DarwinUnixThread state;
            Require(InspectDarwinUnixThread(command,owner,state,error)&&state.present&&state.pc==owner.entrypoint.address
                &&state.sp==0&&state.state_words[0]==0x12345678&&state.ToJson().Get("present")->Bool(),
                "Owned Unix thread state not decoded: "+error);
            const auto bad_thread=[&](const std::string& malformed,const DarwinImage& image){
                Require(!InspectDarwinUnixThread(malformed,image,state,error)&&!state.present&&state.state_words.empty(),
                    "Malformed Unix thread state accepted or partially published");};
            auto malformed=command;Little32(malformed,12,0xffffffff);bad_thread(malformed,owner);
            malformed=command;Little32(malformed,8,0xffffffff);bad_thread(malformed,owner);
            malformed=command;malformed.resize(malformed.size()-8);bad_thread(malformed,owner);
            malformed=command;const auto invalid_pc=UINT64_MAX;std::memcpy(malformed.data()+16+(cpu==0x0100000c?32:16)*8,&invalid_pc,8);bad_thread(malformed,owner);
            auto library_owner=owner;library_owner.file_type=6;bad_thread(command,library_owner);
            auto nonexec_owner=owner;for(auto& segment:nonexec_owner.segments)segment.initial_protection&=~4u;bad_thread(command,nonexec_owner);
        }
        // Declare an owned LC_UNIXTHREAD format fixture in linker header padding.
        // Keep original section bytes/offsets intact; only startup metadata differs.
        const auto thread_command=unix_command(DarwinProcessCpu());std::string thread_commands;
        for(std::size_t p=32;p<32+Little32(startup_bytes,20);p+=Little32(startup_bytes,p+4))
            if(p!=startup_main_command)thread_commands+=startup_bytes.substr(p,Little32(startup_bytes,p+4));
        thread_commands+=thread_command;
        Require(32+thread_commands.size()<=Little32(startup_bytes,startup_section+48),"Owned startup fixture header padding unavailable");
        auto unix_image=startup_bytes;std::memcpy(unix_image.data()+32,thread_commands.data(),thread_commands.size());
        Little32(unix_image,20,static_cast<std::uint32_t>(thread_commands.size()));DarwinImage thread_metadata;
        Require(InspectDarwinImage(unix_image,DarwinProcessCpu(),thread_metadata,error)&&thread_metadata.unix_thread.present
            &&!thread_metadata.entrypoint.present&&thread_metadata.unix_thread.pc==startup_metadata.entrypoint.address,
            "Native standalone Unix thread propagation failed: "+error);
        auto conflicting_image=unix_image;auto conflicting_commands=thread_commands+startup_bytes.substr(startup_main_command,24);
        std::memcpy(conflicting_image.data()+32,conflicting_commands.data(),conflicting_commands.size());
        Little32(conflicting_image,16,Little32(unix_image,16)+1);Little32(conflicting_image,20,static_cast<std::uint32_t>(conflicting_commands.size()));startup_bad(conflicting_image);
        auto duplicate_image=unix_image;auto duplicate_commands=thread_commands+thread_command;
        std::memcpy(duplicate_image.data()+32,duplicate_commands.data(),duplicate_commands.size());
        Little32(duplicate_image,16,Little32(unix_image,16)+1);Little32(duplicate_image,20,static_cast<std::uint32_t>(duplicate_commands.size()));startup_bad(duplicate_image);
        const auto section_command=startup_section-72;
        auto cache_command=startup_bytes.substr(section_command,Little32(startup_bytes,section_command+4));
        const auto cache_owner=std::find_if(startup_metadata.segments.begin(),startup_metadata.segments.end(),[&](const auto& segment){return segment.name==startup_metadata.sections.front().segment_name;});
        Require(cache_owner!=startup_metadata.segments.end(),"Owned cache section owner absent");
        Little32(cache_command,72+52,63);std::vector<DarwinSection> cache_sections;
        Require(InspectDarwinSegmentSections(cache_command,*cache_owner,false,cache_sections,error)
            &&cache_sections.front().alignment==63,"Cache VM placement rejected original linker alignment metadata");
        Require(!InspectDarwinSegmentSections(cache_command,*cache_owner,true,cache_sections,error)
            &&cache_sections.empty(),"Standalone nonempty section alignment not enforced");
        Little32(cache_command,72+52,64);
        Require(!InspectDarwinSegmentSections(cache_command,*cache_owner,false,cache_sections,error)
            &&cache_sections.empty(),"Malformed cache alignment exponent accepted");
        auto invalid_startup=startup_bytes;const auto outside_vm=UINT64_MAX;std::memcpy(invalid_startup.data()+startup_section+32,&outside_vm,8);startup_bad(invalid_startup);
        invalid_startup=startup_bytes;Little32(invalid_startup,startup_section+52,64);startup_bad(invalid_startup);
        invalid_startup=startup_bytes;Little32(invalid_startup,startup_section+48,static_cast<std::uint32_t>(startup_bytes.size()));startup_bad(invalid_startup);
        invalid_startup=startup_bytes;invalid_startup[startup_section+16]='X';startup_bad(invalid_startup);
        invalid_startup=startup_bytes;const auto nonexec_entry=startup_bytes.size()-1;std::memcpy(invalid_startup.data()+startup_main_command+8,&nonexec_entry,8);startup_bad(invalid_startup);
        const auto startup_offset_path=root/"startup-offsets";
        Run(linker,{L"-arch",arch,L"-platform_version",L"macos",L"11.0",L"26.0",L"-fixup_chains",L"-init_offsets",L"-undefined",L"dynamic_lookup",L"-e",L"_main",L"-o",startup_offset_path.wstring(),startup_object.wstring()});
        DarwinImage offset_initializers;Require(ReadDarwinImage(startup_offset_path,offset_initializers,error)
            &&std::any_of(offset_initializers.sections.begin(),offset_initializers.sections.end(),[](const auto& section){return (section.flags&255)==22;}),"Original initializer offsets section not derived: "+error);
        Require(Read(startup_path)==startup_bytes,"Startup metadata parser altered original fixture");
        const auto init_tree=root/"init-tree";fs::create_directories(init_tree/"origin");
        const auto init_source=root/"init-owned.c",init_object=root/"init-owned.o",init_file=init_tree/"origin/server";
        Write(init_source,"int initObserved; __attribute__((constructor)) static void initOwned(void){initObserved=42;} int main(void){return initObserved;}\n");
        Run(clang,{L"-target",std::wstring(arch)+L"-apple-macos11.0",L"-c",init_source.wstring(),L"-o",init_object.wstring()});
        Run(linker,{L"-dylib",L"-arch",arch,L"-platform_version",L"macos",L"11.0",L"26.0",L"-fixup_chains",L"-install_name",L"/origin/server",L"-o",init_file.wstring(),init_object.wstring()});
        const auto init_bytes=Read(init_file);DarwinImage init_metadata;Require(ReadDarwinImage(init_file,init_metadata,error),"Owned initializer metadata absent: "+error);
        auto init_mapped=DarwinMappedImages::Load("/origin/server",{init_tree},error);
        Require(init_mapped&&init_mapped->Initializers().size()==1,"Original initializer offset not decoded from mapped memory: "+error);
        const auto& initializer=init_mapped->Initializers().front();
        const auto observed=static_cast<const int*>(init_mapped->Symbol("/origin/server","_initObserved",error));
        Require(observed&&*observed==0&&initializer.owner=="/origin/server"&&initializer.offset_encoding,"Initializer discovery executed code or lost ownership");
        DiagnosticStage("native initializer");
        reinterpret_cast<void(*)()>(initializer.target)();
        DiagnosticStage("native initializer complete");
        Require(*observed==42,"Mapped initializer address did not execute the original owned constructor");
        init_mapped.reset();
        const auto order_tree=root/"order-tree";fs::create_directories(order_tree/"order");
        const auto order_file=[&](const std::string& name){return order_tree/"order"/(name+".dylib");};
        for(const auto& [name,digit]:std::vector<std::pair<std::string,int>>{{"shared",1},{"leaf",2},{"server",3},{"up1",4},{"up2",5},{"plugin",6}}){
            const auto source=root/("order-"+name+".c");
            Write(source,(name=="shared"?"int initSequence; ":"extern int initSequence; ")+std::string("__attribute__((constructor)) static void initOrder(void){initSequence=initSequence*10+")+std::to_string(digit)+";}\n");
            Run(clang,{L"-target",std::wstring(arch)+L"-apple-macos11.0",L"-c",source.wstring(),L"-o",(root/("order-"+name+".o")).wstring()});
        }
        const auto link_order=[&](const std::string& name,const std::vector<std::wstring>& deps){
            std::vector<std::wstring> args={L"-dylib",L"-arch",arch,L"-platform_version",L"macos",L"11.0",L"26.0",L"-fixup_chains",L"-install_name",L"/order/"+Win32Process::ToWide(name+".dylib"),L"-o",order_file(name).wstring(),(root/("order-"+name+".o")).wstring()};
            args.insert(args.end(),deps.begin(),deps.end());Run(linker,args);
        };
        link_order("shared",{});link_order("up2",{order_file("shared").wstring()});
        link_order("up1",{order_file("shared").wstring(),order_file("up2").wstring()});
        link_order("leaf",{order_file("shared").wstring(),order_file("up1").wstring()});
        link_order("shared",{order_file("leaf").wstring()}); // Genuine normal dependency cycle.
        link_order("up2",{order_file("shared").wstring(),order_file("leaf").wstring()});
        link_order("server",{order_file("leaf").wstring(),order_file("shared").wstring()});
        link_order("plugin",{order_file("shared").wstring()});
        // This LLD ignores -upward_library. Declare upward command types only
        // in owned fixtures, retaining original linker paths/ordinals/code/fixups.
        for(const auto& [owner,target]:std::vector<std::pair<std::string,std::string>>{{"leaf","/order/up1.dylib"},{"up1","/order/up2.dylib"}}){
            auto bytes=Read(order_file(owner));bool changed=false;
            for(std::size_t p=32;p<32+Little32(bytes,20);p+=Little32(bytes,p+4))if(Little32(bytes,p)==0xc){
                const auto name=p+Little32(bytes,p+8);if(bytes.substr(name,target.size())==target&&bytes[name+target.size()]=='\0'){Little32(bytes,p,0x80000023);changed=true;}}
            Require(changed,"Owned upward command input absent");Write(order_file(owner),bytes);
        }
        const auto order_graph=DarwinClosure::Inspect("/order/server.dylib",{"/order/plugin.dylib"},{order_tree});
        std::vector<std::string> scheduled;
        Require(order_graph.EagerInitializationOrder("/order/server.dylib",{"/order/plugin.dylib"},scheduled,error)
            &&scheduled==std::vector<std::string>{"/order/shared.dylib","/order/leaf.dylib","/order/server.dylib","/order/up1.dylib","/order/up2.dylib","/order/plugin.dylib"},"Real cyclic/upward initializer schedule incorrect: "+error);
        auto order_mapped=DarwinMappedImages::Load("/order/server.dylib",{order_tree},error,{},DarwinMappingMode::NativeCpu,{}, {"/order/plugin.dylib"});
        Require(order_mapped&&order_mapped->EagerInitializationOrder()==scheduled,"Real initializer schedule lost at loader boundary: "+error);
        const auto sequence=static_cast<const int*>(order_mapped->Symbol("/order/shared.dylib","_initSequence",error));
        Require(sequence&&*sequence==0,"Schedule generation executed an initializer");
        DiagnosticStage("native ordered initializers");
        for(const auto& owner:order_mapped->EagerInitializationOrder())for(const auto& init:order_mapped->Initializers())if(init.owner==owner)reinterpret_cast<void(*)()>(init.target)();
        DiagnosticStage("native ordered initializers complete");
        Require(*sequence==123456,"Native original owned constructors did not run in dependency/upward/plugin order");
        CancellationSource schedule_cancel;schedule_cancel.Cancel();DarwinClosureOptions schedule_limits;schedule_limits.cancellation=schedule_cancel.Token();
        Require(!order_graph.EagerInitializationOrder("/order/server.dylib",{},scheduled,error,schedule_limits)&&scheduled.empty(),"Cancelled initializer scheduling published partial order");
        Require(!order_graph.EagerInitializationOrder("/order/absent.dylib",{},scheduled,error)&&scheduled.empty(),"Absent initializer root accepted");
        const auto offsets=std::find_if(init_metadata.sections.begin(),init_metadata.sections.end(),[](const auto& s){return (s.flags&255)==22;});
        Require(offsets!=init_metadata.sections.end(),"Real linker initializer offsets absent");
        auto invalid_init=init_bytes;Little32(invalid_init,static_cast<std::size_t>(offsets->file_offset),UINT32_MAX);Write(init_file,invalid_init);
        Require(!DarwinMappedImages::Load("/origin/server",{init_tree},error)&&error.find("Initializer target")!=std::string::npos,"Invalid initializer offset silently mapped");
        Write(init_file,init_bytes);
        if(argc==2){
            const auto executable=fs::absolute(argv[1]).wstring();
            const auto cli=Win32Process::Run(executable,{executable,L"runtime",L"map-image",L"/origin/server",init_tree.wstring()});
            const auto report=JsonValue::Parse(cli.std_out);
            Require(cli.success&&report&&report->Get("initializers")->ArrayItems().size()==1
                &&!report->Get("runtime_initialized")->Bool(true),"Initializer address lost at native CLI boundary");
        }
        Require(Read(init_file)==init_bytes,"Initializer discovery changed original owned file");
        // Preserve a genuine chained rebase in an owned custom pointer section,
        // then declare its section type as initializer pointers (LLD normally converts these to offsets).
        Write(init_source,"int initObserved; void initOwned(void){initObserved=42;} __attribute__((section(\"__DATA,__owned_init\"))) void(*initPointer)(void)=initOwned;\n");
        Run(clang,{L"-target",std::wstring(arch)+L"-apple-macos11.0",L"-c",init_source.wstring(),L"-o",init_object.wstring()});
        Run(linker,{L"-dylib",L"-arch",arch,L"-platform_version",L"macos",L"11.0",L"26.0",L"-fixup_chains",L"-install_name",L"/origin/server",L"-o",init_file.wstring(),init_object.wstring()});
        auto pointer_bytes=Read(init_file);bool pointer_section=false;
        for(std::size_t p=32;p<32+Little32(pointer_bytes,20);p+=Little32(pointer_bytes,p+4))if(Little32(pointer_bytes,p)==0x19)
            for(std::size_t index=0;index<Little32(pointer_bytes,p+64);++index){const auto section=p+72+index*80;
                if(pointer_bytes.substr(section,12)=="__owned_init"){Little32(pointer_bytes,section+64,9);pointer_section=true;}}
        Require(pointer_section,"Owned linker pointer section missing");Write(init_file,pointer_bytes);
        init_mapped=DarwinMappedImages::Load("/origin/server",{init_tree},error);
        Require(init_mapped&&init_mapped->AppliedFixups()&&init_mapped->Initializers().size()==1
            &&!init_mapped->Initializers().front().offset_encoding,"Initializer pointer not decoded after genuine chained rebase: "+error);
        const auto pointer_observed=static_cast<const int*>(init_mapped->Symbol("/origin/server","_initObserved",error));
        Require(pointer_observed&&*pointer_observed==0,"Initializer pointer decoding executed code");
        reinterpret_cast<void(*)()>(init_mapped->Initializers().front().target)();
        Require(*pointer_observed==42&&Read(init_file)==pointer_bytes,"Rebased owned initializer target incorrect or original file changed");
        init_mapped.reset();
        const auto args_tree=root/"arguments-tree";fs::create_directories(args_tree/"args");fs::create_directories(args_tree/"usr/lib");
        const auto args_source=root/"arguments-owned.c",args_object=root/"arguments-owned.o",args_file=args_tree/"args/server";
        Write(args_source,"struct Vars {const void* mh; int* argc; const char*** argv; const char*** env; const char** name;};\n"
            "unsigned long long argProbe(int n,const char** a,const char** e,const char** p,const struct Vars* v){return n==2&&a[0][0]=='/'&&a[1][0]=='h'&&!a[2]&&e[0][0]=='K'&&!e[1]&&p[0][0]=='e'&&!p[1]&&v->mh&&*v->argc==2&&*v->argv==a&&*v->env==e&&(*v->name)[0]=='s'?42:0;}\nint main(void){return 0;}\n");
        Run(clang,{L"-target",std::wstring(arch)+L"-apple-macos11.0",L"-c",args_source.wstring(),L"-o",args_object.wstring()});
        Run(linker,{L"-arch",arch,L"-platform_version",L"macos",L"11.0",L"26.0",L"-fixup_chains",L"-e",L"_main",L"-o",args_file.wstring(),args_object.wstring()});
        // Isolated owned interpreter-format input; no Apple runtime is replaced.
        Run(linker,{L"-dylib",L"-arch",arch,L"-platform_version",L"macos",L"11.0",L"26.0",L"-fixup_chains",L"-install_name",L"/usr/lib/dyld",L"-o",(args_tree/"usr/lib/dyld").wstring(),args_object.wstring()});
        auto owned_interpreter=Read(args_tree/"usr/lib/dyld");Little32(owned_interpreter,12,7);Write(args_tree/"usr/lib/dyld",owned_interpreter);
        auto args_mapped=DarwinMappedImages::Load("/args/server",{args_tree},error);
        Require(bool(args_mapped),"Owned argument executable graph not mapped: "+error);
        auto process_args=args_mapped->ProcessArguments("/args/server",{"/args/server","hello"},{"KEY=value"},{"executable_path=/args/server"},error);
        Require(process_args&&process_args->kernel_args%16==0&&process_args->argc==2,"Original argument layout absent or unaligned: "+error);
        const auto* kernel=reinterpret_cast<const std::uint64_t*>(process_args->kernel_args);
        Require(kernel[0]==process_args->main_header&&kernel[1]==2&&kernel[2]==reinterpret_cast<const std::uint64_t*>(process_args->argv)[0]
            &&std::string(reinterpret_cast<const char* const*>(process_args->argv)[1])=="hello","Darwin kernel argument values/pointers lost");
#if defined(_M_X64) || defined(__x86_64__)
        using ArgumentProbe=unsigned long long(__attribute__((sysv_abi)) *)(int,const char**,const char**,const char**,const void*);
#else
        using ArgumentProbe=unsigned long long(*)(int,const char**,const char**,const char**,const void*);
#endif
        const auto probe=reinterpret_cast<ArgumentProbe>(const_cast<void*>(args_mapped->Symbol("/args/server","_argProbe",error)));
        DiagnosticStage("native argument ABI consumer");
        Require(probe&&probe(2,reinterpret_cast<const char**>(process_args->argv),reinterpret_cast<const char**>(process_args->envp),
            reinterpret_cast<const char**>(process_args->apple),reinterpret_cast<const void*>(process_args->program_vars))==42,"Original owned Darwin ABI consumer rejected process arguments/ProgramVars");
        DiagnosticStage("native argument ABI consumer complete");
        auto process_stack=DarwinProcessStack::Create(*process_args,error);
        Require(bool(process_stack),"Guarded Darwin stack not created: "+error);
        DarwinProcessThread missing_thread;
        Require(!args_mapped->ProcessThread("/args/server",*process_stack,missing_thread,error)&&missing_thread.owner.empty(),
            "Interpreter without Unix thread state accepted for startup");
        auto startup_stack=args_mapped->ProcessStack("/args/server",{"/args/server","hello"},{"KEY=value"},{"executable_path=/args/server"},error);
        Require(bool(startup_stack),"Darwin startup stack failed: "+error);
        const auto& startup_args=startup_stack->Arguments();
        const auto* startup_apple=reinterpret_cast<const char* const*>(startup_args.apple);
        Require(startup_args.apple_count==5&&!startup_apple[5]&&std::string(startup_apple[0])=="executable_path=/args/server",
            "Startup Apple vector did not preserve caller bytes/terminator");
        const auto hex_values=[](const char* text,const std::string& key){
            const std::string value(text);Require(value.starts_with(key),"Darwin startup key is absent");
            std::vector<std::uint64_t> values;std::size_t cursor=key.size();
            do{const auto end=value.find(',',cursor);const auto word=value.substr(cursor,end==std::string::npos?end:end-cursor);
                std::size_t used=0;values.push_back(std::stoull(word,&used,16));Require(used==word.size(),"Malformed startup hex value");
                if(end==std::string::npos)break;cursor=end+1;}while(cursor<value.size());return values;};
        const auto guard_words=hex_values(startup_apple[1],"stack_guard=");
        const auto malloc_words=hex_values(startup_apple[2],"malloc_entropy=");
        const auto munge_words=hex_values(startup_apple[3],"ptr_munge=");
        const auto stack_words=hex_values(startup_apple[4],"main_stack=");
        Require(guard_words.size()==1&&(guard_words[0]&0xff00)==0&&malloc_words.size()==2&&munge_words.size()==1,
            "Darwin startup entropy word counts or embedded zero byte differ");
        const auto startup_json=startup_stack->ToJson();
        Require(stack_words.size()==4&&stack_words[0]==startup_stack->Range().address+startup_stack->Range().size
            &&stack_words[1]==startup_stack->Range().size
            &&std::to_string(stack_words[2])==startup_json.Get("reservation")->Serialize()
            &&stack_words[2]+stack_words[3]==stack_words[0]&&startup_json.Get("startup_parameters_prepared")->Bool(),
            "Darwin main_stack was not derived from actual stack allocation");
        auto second_startup=args_mapped->ProcessStack("/args/server",{"/args/server"},{},{},error);
        Require(bool(second_startup),"Second process startup failed: "+error);
        const auto* second_apple=reinterpret_cast<const char* const*>(second_startup->Arguments().apple);
        Require(std::string(second_apple[1])!=startup_apple[2],"Independent processes reused malloc entropy");
        for(const auto key:{"stack_guard=","malloc_entropy=","ptr_munge=","main_stack="})
            Require(!args_mapped->ProcessStack("/args/server",{"/args/server"},{},{std::string(key)+"0"},error),
                "Caller overrode a process-owned startup key");
        const auto& stack_args=process_stack->Arguments();const auto stack_range=process_stack->Range();
        Require(stack_args.kernel_args%16==0&&stack_args.kernel_args>=stack_range.address&&stack_args.kernel_args<stack_range.address+stack_range.size
            &&stack_args.main_header==process_args->main_header&&stack_args.main_entry==process_args->main_entry,"Stack argument frame lost image identity or alignment");
        Require(probe(2,reinterpret_cast<const char**>(stack_args.argv),reinterpret_cast<const char**>(stack_args.envp),
            reinterpret_cast<const char**>(stack_args.apple),reinterpret_cast<const void*>(stack_args.program_vars))==42,"Relocated stack argument consumer failed");
        const auto stack_frame_address=stack_args.kernel_args;
        const auto stack_value=process_stack->ToJson();
        Require(stack_value.Get("effective_limit")->Serialize()==std::to_string(8*1024*1024-(DarwinProcessCpu()==0x0100000c?16384:0)),"Default stack did not use original CPU platform limits");
        for(const auto guard_address:{stack_range.address-1,stack_range.address+stack_range.size}){
            MEMORY_BASIC_INFORMATION info{};Require(VirtualQuery(reinterpret_cast<const void*>(guard_address),&info,sizeof(info))
                &&info.State==MEM_RESERVE,"Windows stack guard is accessible or unreserved");}
        Run(linker,{L"-arch",arch,L"-platform_version",L"macos",L"11.0",L"26.0",L"-fixup_chains",L"-stack_size",L"10000",L"-e",L"_main",L"-o",args_file.wstring(),args_object.wstring()});
        // This LLD does not emit the requested stack size. Supply an owned
        // LC_MAIN format fixture so the loader must derive it from original bytes.
        auto stack_hint_bytes=Read(args_file);bool stack_hint_command=false;
        for(std::size_t p=32;p<32+Little32(stack_hint_bytes,20);p+=Little32(stack_hint_bytes,p+4))if(Little32(stack_hint_bytes,p)==0x80000028){const std::uint64_t hint=65536;std::memcpy(stack_hint_bytes.data()+p+16,&hint,8);stack_hint_command=true;}
        Require(stack_hint_command,"Owned linked LC_MAIN command absent");Write(args_file,stack_hint_bytes);
        auto hinted_mapped=DarwinMappedImages::Load("/args/server",{args_tree},error);Require(bool(hinted_mapped),"Owned stack-hint executable not mapped: "+error);
        auto hinted_args=hinted_mapped->ProcessArguments("/args/server",{"/args/server","hello"},{"KEY=value"},{"executable_path=/args/server"},error);
        Require(hinted_args&&hinted_args->stack_size_hint==65536,"Original LC_MAIN stack-size hint not derived from linked executable");
        auto custom_stack=DarwinProcessStack::Create(*hinted_args,error);
        Require(custom_stack&&custom_stack->Range().size==65536,"Original LC_MAIN stack-size hint ignored: "+error);
        custom_stack.reset();auto overflowing_stack=Read(args_file);
        for(std::size_t p=32;p<32+Little32(overflowing_stack,20);p+=Little32(overflowing_stack,p+4))if(Little32(overflowing_stack,p)==0x80000028){const auto maximum=UINT64_MAX;std::memcpy(overflowing_stack.data()+p+16,&maximum,8);}
        Write(args_file,overflowing_stack);auto overflowing_mapped=DarwinMappedImages::Load("/args/server",{args_tree},error);
        Require(bool(overflowing_mapped),"Owned overflowing stack metadata could not reach stack validation: "+error);
        auto overflowing_args=overflowing_mapped->ProcessArguments("/args/server",{"/args/server"},{},{},error);
        Require(overflowing_args&&!DarwinProcessStack::Create(*overflowing_args,error),"Overflowing original Darwin stack hint accepted");
        Require(!DarwinProcessStack::Create(*process_args,error,4096),"Stack with no argument working space accepted");
        auto maximum_stack=DarwinProcessStack::Create(*process_args,error,64*1024*1024);
        Require(maximum_stack&&maximum_stack->Range().size==64*1024*1024,"Supported inherited maximum stack limit rejected: "+error);
        MEMORY_BASIC_INFORMATION maximum_guard{};
        Require(VirtualQuery(reinterpret_cast<const void*>(maximum_stack->Range().address-1),&maximum_guard,sizeof(maximum_guard))
            &&maximum_guard.State==MEM_RESERVE,"Inherited maximum stack lost its lower guard");maximum_stack.reset();
        process_stack.reset();MEMORY_BASIC_INFORMATION stack_info{};
        Require(VirtualQuery(reinterpret_cast<const void*>(stack_frame_address),&stack_info,sizeof(stack_info))&&stack_info.State==MEM_FREE,"Guarded stack reservation leaked");
        Require(!args_mapped->ProcessArguments("/args/server",{}, {},{},error),"Empty process argv accepted");
        Require(!args_mapped->ProcessArguments("/args/server",{"/args/server",std::string("bad\0arg",7)}, {},{},error),"Embedded NUL argument accepted");
        Require(!args_mapped->ProcessArguments("/args/server",{"/args/server",std::string(1024*1024,'x')}, {},{},error),"Oversized process arguments accepted");
        const auto arguments_address=process_args->Range().address;process_args.reset();MEMORY_BASIC_INFORMATION args_info{};
        Require(VirtualQuery(reinterpret_cast<const void*>(arguments_address),&args_info,sizeof(args_info))&&args_info.State==MEM_FREE,"Darwin argument backing memory leaked");
        Require(Read(args_tree/"usr/lib/dyld")==owned_interpreter,"Argument state preparation altered owned interpreter bytes");
        const auto weak_tree=root/"weak-scope";fs::create_directories(weak_tree/"scope");
        const auto weak_main=weak_tree/"scope/main",weak_first=weak_tree/"scope/first.dylib",
            weak_second=weak_tree/"scope/second.dylib",weak_strong=weak_tree/"scope/strong.dylib";
        for(const auto& [name,code]:std::vector<std::pair<std::string,std::string>>{
            {"main","int scopeAnchor=0;\n"},
            {"first","__attribute__((weak)) int ownedChoice=11; int* firstPointer=&ownedChoice;\n"},
            {"second","__attribute__((weak)) int ownedChoice=22; int* secondPointer=&ownedChoice;\n"},
            {"strong","int ownedChoice=33; __attribute__((weak)) int unrelatedChoice=44;\n"}}){
            Write(root/("weak-"+name+".c"),code);
            Run(clang,{L"-target",std::wstring(arch)+L"-apple-macos11.0",L"-c",(root/("weak-"+name+".c")).wstring(),L"-o",(root/("weak-"+name+".o")).wstring()});
            const auto output=name=="main"?weak_main:weak_tree/"scope"/(name+".dylib");
            Run(linker,{L"-dylib",L"-arch",arch,L"-platform_version",L"macos",L"11.0",L"26.0",L"-fixup_chains",
                L"-install_name",L"/scope/"+Win32Process::ToWide(name+".dylib"),L"-o",output.wstring(),(root/("weak-"+name+".o")).wstring()});
        }
        DarwinImage first_weak_metadata;
        Require(ReadDarwinImage(weak_first,first_weak_metadata,error)&&(first_weak_metadata.header_flags&0x8000)
            &&std::any_of(first_weak_metadata.chained_fixups.imports.begin(),first_weak_metadata.chained_fixups.imports.end(),[](const auto& entry){return entry.symbol=="_ownedChoice"&&entry.library_ordinal==-3&&!entry.weak;}),
            "Real linker did not produce the original weak-lookup contract");
        const auto first_weak_original=Read(weak_first),second_weak_original=Read(weak_second),strong_weak_original=Read(weak_strong);
        const auto check_weak=[&](const std::vector<std::string>& roots,int expected){
            auto scope=DarwinMappedImages::Load("/scope/main",{weak_tree},error,{},DarwinMappingMode::NativeCpu,{},roots);
            Require(bool(scope),"Owned weak scope failed: "+error);
            const auto first=static_cast<const int* const*>(scope->Symbol("/scope/first.dylib","_firstPointer",error));
            const auto second=static_cast<const int* const*>(scope->Symbol("/scope/second.dylib","_secondPointer",error));
            Require(first&&second&&*first&&*first==*second&&**first==expected,"Weak clients did not bind the same canonical original definition");
            Require(scope->WeakBindings().size()==2&&std::all_of(scope->WeakBindings().begin(),scope->WeakBindings().end(),[&](const auto& binding){return binding.symbol=="_ownedChoice"&&binding.target==reinterpret_cast<std::uint64_t>(*first);}),"Weak binding diagnostics lost actual canonical targets");
        };
        check_weak({"/scope/first.dylib","/scope/second.dylib"},11);
        check_weak({"/scope/second.dylib","/scope/first.dylib"},22);
        check_weak({"/scope/first.dylib","/scope/second.dylib","/scope/strong.dylib"},33);
        Require(Read(weak_first)==first_weak_original&&Read(weak_second)==second_weak_original&&Read(weak_strong)==strong_weak_original,
            "Weak coalescing changed original inputs");
        const auto arm_tree = root / "arm64-execution"; fs::create_directories(arm_tree / "origin/runtime");
        Write(root / "arm-provider.c", "int guestValue=17;\n");
        Write(root / "arm-consumer.c", "extern int guestValue; static int guestLocal=1; int* guestPointer=&guestLocal;\n"
            "int original_result(int a,int b){return guestValue+*guestPointer+a+b;}\n"
            "int original_no_args(void){return original_result(0,0);}\n"
            "int syscall_probe(void){__asm__ volatile(\"svc #0x80\"); return 99;}\n"
            "int endless(void){for(;;)__asm__ volatile(\"nop\");}\n"
            "unsigned long long privileged_probe(void){unsigned long long level;__asm__ volatile(\"mrs %0, CurrentEL\":\"=r\"(level));return level;}\n"
            "int pac_probe(int data){register unsigned long long x __asm__(\"x0\")=0x180004800ULL; "
            "register unsigned long long y __asm__(\"x1\")=0x1234000180004840ULL; unsigned flags=0; "
            "for(unsigned attempt=0;attempt<4;++attempt){x=0x180004800ULL;y+=attempt; "
            "if(data)__asm__ volatile(\".inst 0xdac10820\":\"+r\"(x):\"r\"(y)); "
            "else __asm__ volatile(\".inst 0xdac10020\":\"+r\"(x):\"r\"(y)); "
            "unsigned long long signedValue=x;if(x!=0x180004800ULL)flags|=1; "
            "if(data)__asm__ volatile(\".inst 0xdac11820\":\"+r\"(x):\"r\"(y)); "
            "else __asm__ volatile(\".inst 0xdac11020\":\"+r\"(x):\"r\"(y)); "
            "if(x==0x180004800ULL)flags|=2;x=signedValue^(1ULL<<48); "
            "if(data)__asm__ volatile(\".inst 0xdac11820\":\"+r\"(x):\"r\"(y)); "
            "else __asm__ volatile(\".inst 0xdac11020\":\"+r\"(x):\"r\"(y)); "
            "if(x!=0x180004800ULL)flags|=4;if(flags==7)break;}return flags;}\n"
            "int pac_policy_probe(int key){register unsigned long long x __asm__(\"x0\"); "
            "register unsigned long long y __asm__(\"x1\")=0x1234000180004840ULL;unsigned flags=0;"
            "for(unsigned attempt=0;attempt<4;++attempt){x=0x180004800ULL;y+=attempt;"
            "switch(key){case 0:__asm__ volatile(\".inst 0xdac10020\":\"+r\"(x):\"r\"(y));break;"
            "case 1:__asm__ volatile(\".inst 0xdac10420\":\"+r\"(x):\"r\"(y));break;"
            "case 2:__asm__ volatile(\".inst 0xdac10820\":\"+r\"(x):\"r\"(y));break;"
            "default:__asm__ volatile(\".inst 0xdac10c20\":\"+r\"(x):\"r\"(y));}"
            "unsigned long long signedValue=x;if(x!=0x180004800ULL)flags|=1;"
            "for(unsigned bad=0;bad<2;++bad){x=signedValue^(bad?(1ULL<<48):0);unsigned long long input=x;"
            "switch(key){case 0:__asm__ volatile(\".inst 0xdac11020\":\"+r\"(x):\"r\"(y));break;"
            "case 1:__asm__ volatile(\".inst 0xdac11420\":\"+r\"(x):\"r\"(y));break;"
            "case 2:__asm__ volatile(\".inst 0xdac11820\":\"+r\"(x):\"r\"(y));break;"
            "default:__asm__ volatile(\".inst 0xdac11c20\":\"+r\"(x):\"r\"(y));}"
            "if(!bad&&x==0x180004800ULL)flags|=2;if(bad&&x!=0x180004800ULL)flags|=4;"
            "if(bad&&x==input)flags|=8;}if((flags&7)==7)break;}return flags;}\n"
            "__asm__(\".text\\n.p2align 2\\n.globl _ib_return_probe\\n_ib_return_probe:\\npacibsp\\ncbz x0,1f\\nmov x10,#1\\nlsl x10,x10,#48\\neor x30,x30,x10\\n1: autibsp\\nret\\n\");\n");
        for (const auto* source : {L"arm-provider", L"arm-consumer"})
            Run(clang, {L"-target", L"arm64-apple-macos11.0", L"-c", (root / (std::wstring(source) + L".c")).wstring(),
                L"-o", (root / (std::wstring(source) + L".o")).wstring()});
        const auto arm_provider = arm_tree / "origin/runtime/libProvider.dylib", arm_consumer = arm_tree / "origin/server";
        Run(linker, {L"-dylib", L"-arch", L"arm64", L"-platform_version", L"macos", L"11.0", L"26.0", L"-fixup_chains",
            L"-install_name", L"@rpath/libProvider.dylib", L"-o", arm_provider.wstring(), (root / "arm-provider.o").wstring()});
        Run(linker, {L"-dylib", L"-arch", L"arm64", L"-platform_version", L"macos", L"11.0", L"26.0", L"-fixup_chains",
            L"-install_name", L"@rpath/libConsumer.dylib", L"-rpath", L"@loader_path/runtime", L"-o", arm_consumer.wstring(),
            (root / "arm-consumer.o").wstring(), arm_provider.wstring()});
        DiagnosticStage("arm64 linked consumer");
        // Owned enabled-JOP fixtures declare that ABI explicitly. The provider
        // stays ARM64: it must not select the task's PAC controls.
        auto owned_arm64e=Read(arm_consumer);Little32(owned_arm64e,8,2);Write(arm_consumer,owned_arm64e);
        const auto original_arm_consumer = Read(arm_consumer), original_arm_provider = Read(arm_provider);
        const auto thread_tree=root/"arm-thread-tree";fs::create_directories(thread_tree/"process");fs::create_directories(thread_tree/"usr/lib");
        fs::create_directories(thread_tree/"empty");
        const auto thread_object=root/"arm-thread.o",thread_main=thread_tree/"process/main",thread_dyld=thread_tree/"usr/lib/dyld";
        Write(args_source,Read(args_source)+"\n#if defined(__aarch64__)\n"
            "__asm__(\".text\\n.p2align 2\\n.globl _threadEntry\\n_threadEntry:\\nmov x0,sp\\nmov x16,#65535\\nsvc #0x80\\nb .\\n"
            ".globl _bsdthreadCtlDirectEntry\\n_bsdthreadCtlDirectEntry:\\nmov x0,#0x4000\\nmov x1,#0\\nmov x2,#0\\nmov x3,#0\\nmov x16,#478\\nsvc #0x80\\nb.cc 1f\\ncmp x0,#45\\nb.ne 1f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n1: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _bsdthreadCtlIndirectEntry\\n_bsdthreadCtlIndirectEntry:\\nmov x0,#478\\nmov x1,#0x4000\\nmov x2,#0\\nmov x3,#0\\nmov x4,#0\\nmov x16,#0\\nsvc #0x80\\nb.cc 1f\\ncmp x0,#45\\nb.ne 1f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n1: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _kasInfoUnsupportedEntry\\n_kasInfoUnsupportedEntry:\\nmov x0,#0x4000\\nmov x16,#439\\nsvc #0x80\\nb .\\n"
            ".globl _memoryEntry\\n_memoryEntry:\\nmov x0,#0\\nldr x1,[x0]\\nb .\\n"
            ".globl _loopEntry\\n_loopEntry:\\nb .\\n"
            ".globl _capabilityEntry\\n_capabilityEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\n"
            "ldrb w0,[x2,#0x90]\\nldrb w1,[x2,#0x91]\\norr w0,w0,w1\\ncbnz w0,1f\\nmov x16,#65535\\nsvc #0x80\\n1: b .\\n"
            ".globl _ditPolicyEntry\\n_ditPolicyEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldr x9,[x2,#0x10]\\ntbnz x9,#57,1f\\nmov x0,#1\\nmov x16,#65535\\nsvc #0x80\\nb .\\n1:\\n.inst 0xd53b42a9\\nb .\\n"
            ".globl _bootTimeEntry\\n_bootTimeEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldr x0,[x2,#0xa0]\\nldr x1,[x2,#0xa0]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n"
            ".globl _crossBootTimeEntry\\n_crossBootTimeEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldur x0,[x2,#0xa4]\\nb .\\n"
            ".globl _unknownCommpageEntry\\n_unknownCommpageEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldr x0,[x2,#0xa8]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n"
            ".globl _crossCommpageEntry\\n_crossCommpageEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldr w0,[x2,#0x90]\\nb .\\n"
            ".globl _writeCommpageEntry\\n_writeCommpageEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nstrb w0,[x2,#0x90]\\nb .\\n"
            ".globl _fetchCommpageEntry\\n_fetchCommpageEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nbr x2\\n"
            ".globl _clockEntry\\n_clockEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\n"
            "3: ldr x19,[x2,#0x98]\\nmov w16,#-3\\nsvc #0x80\\nmov x20,x0\\nmov w16,#-3\\nsvc #0x80\\ncmp x0,x20\\nb.lo 2f\\n"
            "ldr x21,[x2,#0x98]\\ncmp x19,x21\\nb.ne 3b\\nadd x20,x0,x21\\nmov w16,#-4\\nsvc #0x80\\ncmp x0,x20\\nb.lo 2f\\n"
            "mov x16,#-3\\nsvc #0x80\\nmov x16,#65535\\nsvc #0x80\\nb .\\n2: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _wrongClockSvcEntry\\n_wrongClockSvcEntry:\\nmov w16,#-3\\nsvc #0x81\\nb .\\n"
            ".globl _wrongClockHighEntry\\n_wrongClockHighEntry:\\nmov w16,#-3\\nmovk x16,#1,lsl #32\\nsvc #0x80\\nb .\\n"
            ".globl _clockBreakEntry\\n_clockBreakEntry:\\nmov w16,#-3\\nbrk #0x80\\nb .\\n"
            ".globl _kdebugEntry\\n_kdebugEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldr w0,[x2,#0x100]\\ncbnz w0,4f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n4: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _crossKdebugEntry\\n_crossKdebugEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldr x0,[x2,#0x100]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n"
            ".globl _writeKdebugEntry\\n_writeKdebugEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nstr w0,[x2,#0x100]\\nb .\\n"
            ".globl _taskEntry\\n_taskEntry:\\nmov w16,#-28\\nsvc #0x80\\ncbz x0,5f\\nmov x19,x0\\nmov x16,#-28\\nsvc #0x80\\ncmp x0,x19\\nb.ne 5f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n5: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _wrongTaskSvcEntry\\n_wrongTaskSvcEntry:\\nmov w16,#-28\\nsvc #0x81\\nb .\\n"
            ".globl _portEntry\\n_portEntry:\\nmov w16,#-26\\nsvc #0x80\\ncbz x0,7f\\nmov x19,x0\\nmov x16,#-26\\nsvc #0x80\\ncbz x0,7f\\ncmp x0,x19\\nb.eq 7f\\nmov x20,x0\\nmov w16,#-27\\nsvc #0x80\\ncbz x0,7f\\ncmp x0,x19\\nb.eq 7f\\ncmp x0,x20\\nb.eq 7f\\nmov x21,x0\\nmov x16,#-27\\nsvc #0x80\\ncmp x0,x21\\nb.ne 7f\\nmov w16,#-50\\nsvc #0x80\\ncbz x0,7f\\nmov x22,x0\\nmov x16,#-50\\nsvc #0x80\\ncbz x0,7f\\ncmp x0,x22\\nb.eq 7f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n7: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _wrongPortSvcEntry\\n_wrongPortSvcEntry:\\nmov w16,#-26\\nsvc #0x81\\nb .\\n"
            ".globl _geometryEntry\\n_geometryEntry:\\nmov x2,#0x4000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldrb w19,[x2,#0x37]\\nldrb w20,[x2,#0x25]\\ncmp w19,w20\\nb.ne 8f\\nmov x3,#0xc000\\nmovk x3,#0xffff,lsl #16\\nmovk x3,#0xf,lsl #32\\nldrb w21,[x3,#0x37]\\nldrb w22,[x3,#0x25]\\ncmp w19,w21\\nb.ne 8f\\ncmp w19,w22\\nb.ne 8f\\ncbz w19,8f\\nmov x0,#1\\nlsl x0,x0,x19\\nmov x16,#65535\\nsvc #0x80\\nb .\\n8: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _crossGeometryEntry\\n_crossGeometryEntry:\\nmov x2,#0x4000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldrh w0,[x2,#0x37]\\nb .\\n.globl _unknownGeometryEntry\\n_unknownGeometryEntry:\\nmov x2,#0x4000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldrb w0,[x2,#0x36]\\nb .\\n.globl _writeGeometryEntry\\n_writeGeometryEntry:\\nmov x2,#0x4000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nstrb w0,[x2,#0x37]\\nb .\\n.globl _fetchGeometryEntry\\n_fetchGeometryEntry:\\nmov x2,#0x4000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nbr x2\\n"
            ".globl _taskLoopEntry\\n_taskLoopEntry:\\nmov w16,#-28\\n6: svc #0x80\\nsvc #0x80\\nsvc #0x80\\nb 6b\\n"
            ".globl _machRightsEntry\\n_machRightsEntry:\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nmov x16,#-27\\nsvc #0x80\\nmov x20,x0\\nmov x0,x19\\nmov x1,x20\\nmov x2,#0\\nmov w3,#0\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-18\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x20\\nb.ne 99f\\ncmp x0,#0\\nb.ne 99f\\nmov x16,#-27\\nsvc #0x80\\ncbz x0,99f\\ncmp x0,x20\\nb.eq 99f\\nmov x20,x0\\nmov x16,#-26\\nsvc #0x80\\nmov x22,x0\\nmov x0,x19\\nmov x1,x22\\nmov x2,#1\\nmov w3,#0\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-19\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x22\\nb.ne 99f\\ncmp x0,#0\\nb.ne 99f\\nmov x0,x19\\nmov x1,x22\\nmov x2,#1\\nmov w3,#1\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-19\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x22\\nb.ne 99f\\ncmp x0,#18\\nb.ne 99f\\nmov x0,x19\\nmov x1,x22\\nmov x2,#2\\nmov w3,#0\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-19\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x22\\nb.ne 99f\\ncmp x0,#17\\nb.ne 99f\\nmov x0,x19\\nmov x1,x22\\nmov x2,#5\\nmov w3,#0\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-19\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x22\\nb.ne 99f\\ncmp x0,#18\\nb.ne 99f\\nmov x0,x19\\nmov x1,x22\\nmov x2,#0\\nmov w3,#0\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-18\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x22\\nb.ne 99f\\ncmp x0,#17\\nb.ne 99f\\nmov x0,x19\\nmov x1,x22\\nmov x2,#1\\nmov w3,#-1\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-19\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x22\\nb.ne 99f\\ncmp x0,#0\\nb.ne 99f\\nmov x16,#-50\\nsvc #0x80\\nmov x23,x0\\nmov x0,x19\\nmov x1,x23\\nmov x2,#1\\nmov w3,#-1\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-19\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x23\\nb.ne 99f\\ncmp x0,#0\\nb.ne 99f\\nmov x0,x19\\nmov x1,x23\\nmov x2,#4\\nmov w3,#0\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-19\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x23\\nb.ne 99f\\ncmp x0,#0\\nb.ne 99f\\nmov x0,x19\\nmov x1,x23\\nmov x2,#0\\nmov w3,#0\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-18\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x23\\nb.ne 99f\\ncmp x0,#0\\nb.ne 99f\\nmov x0,x19\\nmov x1,#0\\nmov x2,#0\\nmov w3,#-1\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-19\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,#0\\nb.ne 99f\\ncmp x0,#0\\nb.ne 99f\\nmov x0,x19\\nmov x1,#0\\nmov x2,#0\\nmov w3,#0\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-18\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,#0\\nb.ne 99f\\ncmp x0,#0\\nb.ne 99f\\nmov x0,x19\\nmov x1,x20\\nmov x2,#0\\nmov w3,#65534\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-19\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x20\\nb.ne 99f\\ncmp x0,#0\\nb.ne 99f\\nmov x0,x19\\nmov x1,x20\\nmov x2,#0\\nmov w3,#0\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-18\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x20\\nb.ne 99f\\ncmp x0,#0\\nb.ne 99f\\nmov x0,x19\\nmov x1,x20\\nmov x2,#0\\nmov w3,#-65535\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#-19\\nsvc #0x80\\nmrs x26,nzcv\\ncmp x26,x25\\nb.ne 99f\\ncmp x1,x20\\nb.ne 99f\\ncmp x0,#0\\nb.ne 99f\\nmov x16,#-27\\nsvc #0x80\\ncbz x0,99f\\ncmp x0,x20\\nb.eq 99f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n99: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _machPinnedEntry\\n_machPinnedEntry:\\nmov x16,#-28\\nsvc #0x80\\nmov x1,x0\\nmov x2,#0\\nmov w3,#-2\\nmov x16,#-19\\nsvc #0x80\\nb .\\n"
            ".globl _machBadTargetEntry\\n_machBadTargetEntry:\\nmov x0,#0\\nmov x1,#0\\nmov x16,#-18\\nsvc #0x80\\nmov x2,#3\\nmovk x2,#0x1000,lsl #16\\ncmp x0,x2\\nb.ne 99f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n99: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _machWrongSvcEntry\\n_machWrongSvcEntry:\\nmov x16,#-19\\nsvc #0x81\\nb .\\n"
            ".globl _machHighSelectorEntry\\n_machHighSelectorEntry:\\nmov w16,#0xffed\\nmovk x16,#0xffff,lsl #16\\nmovk x16,#1,lsl #32\\nsvc #0x80\\nb .\\n"
            ".globl _threadIdentityEntry\\n_threadIdentityEntry:\\nmov x21,#0xd0000000\\nmov x22,#0xf0000000\\nmsr nzcv,x22\\nmov x1,#99\\nmov w16,#372\\nsvc #0x80\\nmrs x23,nzcv\\ncmp x23,x21\\nb.ne 99f\\ncbnz x1,99f\\ncbz x0,99f\\nmov x19,x0\\nmsr nzcv,x22\\nmov x1,#99\\nmov x16,#372\\nsvc #0x80\\ncmp x0,x19\\nb.ne 99f\\ncbnz x1,99f\\nmov x0,#372\\nmov x16,#0\\nsvc #0x80\\ncmp x0,x19\\nb.ne 99f\\ncbnz x1,99f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n99: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _tlsContextEntry\\n_tlsContextEntry:\\nmov x19,#0x9000\\nmsr tpidr_el0,x19\\nmov x20,sp\\nmov x21,#0xf0000000\\nmsr nzcv,x21\\nmov x0,x20\\nmov x1,#11\\nmov x3,#2\\nmovz x16,#0x8000,lsl #16\\nsvc #0x80\\nmrs x22,nzcv\\ncmp x22,x21\\nb.ne 99f\\ncmp x1,#11\\nb.ne 99f\\nmrs x22,tpidrro_el0\\ncmp x22,x20\\nb.ne 99f\\nmrs x22,tpidr_el0\\ncmp x22,x19\\nb.ne 99f\\nmsr nzcv,x21\\nmov x0,#0\\nmov x3,#3\\nmovz x16,#0x8000,lsl #16\\nsvc #0x80\\nmrs x22,nzcv\\ncmp x22,x21\\nb.ne 99f\\ncmp x0,x20\\nb.ne 99f\\nmov x0,#7\\nmov x3,#0\\nmovz x16,#0x8000,lsl #16\\nsvc #0x80\\ncmp x0,#7\\nb.ne 99f\\nmov x0,#7\\nmov x3,#1\\nmovz x16,#0x8000,lsl #16\\nsvc #0x80\\ncmp x0,#7\\nb.ne 99f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n99: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _crossarchContextEntry\\n_crossarchContextEntry:\\nmov x19,#0xd0000000\\nmov x20,#0xf0000000\\nmsr nzcv,x19\\nmov x0,#0\\nmov x1,#99\\nmov x16,#38\\nsvc #0x80\\nmrs x21,nzcv\\ncmp x21,x20\\nb.ne 99f\\ncmp x0,#45\\nb.ne 99f\\ncbnz x1,99f\\nmov x0,#1\\nmov x16,#38\\nsvc #0x80\\nb.cc 99f\\ncmp x0,#22\\nb.ne 99f\\nmov x0,#0x100000000\\nmov x16,#38\\nsvc #0x80\\nb.cc 99f\\ncmp x0,#45\\nb.ne 99f\\nmov x0,#38\\nmov x1,#1\\nmov x16,#0\\nsvc #0x80\\nb.cc 99f\\ncmp x0,#22\\nb.ne 99f\\ncbnz x1,99f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n99: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _wrongIdentitySvcEntry\\n_wrongIdentitySvcEntry:\\nmov x16,#372\\nsvc #0x81\\nb .\\n"
            ".globl _wrongIdentityHighEntry\\n_wrongIdentityHighEntry:\\nmov x16,#372\\nmovk x16,#1,lsl #32\\nsvc #0x80\\nb .\\n"
            ".globl _unalignedTsdEntry\\n_unalignedTsdEntry:\\nmov x0,#0x1001\\nmov x3,#2\\nmovz x16,#0x8000,lsl #16\\nsvc #0x80\\nmrs x19,tpidrro_el0\\nmov x20,#0x1001\\ncmp x19,x20\\nb.ne 99f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n99: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _invalidTsdRangeEntry\\n_invalidTsdRangeEntry:\\nmov x0,#0x1000000000000\\nmov x3,#2\\nmovz x16,#0x8000,lsl #16\\nsvc #0x80\\nmrs x19,tpidrro_el0\\ncbnz x19,99f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n99: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _unknownPlatformEntry\\n_unknownPlatformEntry:\\nmov x3,#4\\nmovz x16,#0x8000,lsl #16\\nsvc #0x80\\nb .\\n"
            ".globl _wrongPlatformSvcEntry\\n_wrongPlatformSvcEntry:\\nmov x3,#2\\nmovz x16,#0x8000,lsl #16\\nsvc #0x81\\nb .\\n"
            ".globl _dyldFlagsEntry\\n_dyldFlagsEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldr x0,[x2,#0x160]\\ncbnz x0,99f\\nldrb w0,[x2,#0x162]\\ncbnz w0,99f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n99: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _crossDyldFlagsEntry\\n_crossDyldFlagsEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nadd x3,x2,#0x164\\nldr x0,[x3]\\nb .\\n"
            ".globl _writeDyldFlagsEntry\\n_writeDyldFlagsEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nstr x0,[x2,#0x160]\\nb .\\n"
            ".globl _csrctlCheckEntry\\n_csrctlCheckEntry:\\nsub sp,sp,#32\\nmov w0,#16\\nstr w0,[sp]\\nmov x0,#0\\nmov x1,sp\\nmov x2,#4\\nmov x16,#483\\nsvc #0x80\\nb.cc 13f\\ncmp x0,#1\\nb.ne 13f\\nmov w0,#0\\nstr w0,[sp]\\nmov x0,#0\\nmov x1,sp\\nmov x2,#4\\nmov x16,#483\\nsvc #0x80\\nb.cs 13f\\ncbnz x0,13f\\nmov w0,#0xff\\nstr w0,[sp]\\nmov x0,#1\\nmov x1,sp\\nmov x2,#4\\nmov x16,#483\\nsvc #0x80\\nb.cs 13f\\ncbnz x0,13f\\nldr w0,[sp]\\ncbnz w0,13f\\nadd sp,sp,#32\\nmov x16,#65535\\nsvc #0x80\\nb .\\n13: add sp,sp,#32\\nmov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _sharedRegionCheckEntry\\n_sharedRegionCheckEntry:\\nsub sp,sp,#32\\nmov x0,sp\\nmov x16,#294\\nsvc #0x80\\nb.cc 14f\\ncmp x0,#22\\nb.ne 14f\\nmov x0,#0\\nmov x16,#294\\nsvc #0x80\\nb.cc 14f\\ncmp x0,#22\\nb.ne 14f\\nadd sp,sp,#32\\nmov x16,#65535\\nsvc #0x80\\nb .\\n14: add sp,sp,#32\\nmov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _csrFaultEntry\\n_csrFaultEntry:\\nmov x0,#0\\nmov x1,#1\\nmov x2,#4\\nmov x16,#483\\nsvc #0x80\\nb.cc 99f\\ncmp x0,#14\\nb.ne 99f\\nmov x0,#1\\nmov x1,#1\\nmov x2,#4\\nmov x16,#483\\nsvc #0x80\\nb.cc 99f\\ncmp x0,#14\\nb.ne 99f\\nmov x0,#1\\nmov x1,#0xc000\\nmovk x1,#0xffff,lsl #16\\nmovk x1,#0xf,lsl #32\\nadd x1,x1,#0x160\\nmov x2,#4\\nmov x16,#483\\nsvc #0x80\\nb.cc 99f\\ncmp x0,#14\\nb.ne 99f\\nmov x0,#2\\nmov x1,#0\\nmov x2,#0\\nmov x16,#483\\nsvc #0x80\\nb.cc 99f\\ncmp x0,#78\\nb.ne 99f\\nmov x0,#0\\nmov x1,sp\\nmov x2,#3\\nmov x16,#483\\nsvc #0x80\\nb.cc 99f\\ncmp x0,#22\\nb.ne 99f\\nmov x0,#0\\nmov x1,#0\\nmov x2,#4\\nmov x16,#483\\nsvc #0x80\\nb.cc 99f\\ncmp x0,#22\\nb.ne 99f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n99: mov x16,#21\\nsvc #0x80\\nb .\\n"
            "\\n.globl _vmNoneEntry\\n_vmNoneEntry:\\nsub sp,sp,#32\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nstr xzr,[sp]\\nmov x1,sp\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#1\\nmov x5,#0\\nmov x16,#-15\\nsvc #0x80\\ncbnz x0,90f\\nldr x21,[sp]\\nstr xzr,[x21]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n90: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _vmReprotectEntry\\n_vmReprotectEntry:\\nsub sp,sp,#32\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nstr xzr,[sp]\\nmov x1,sp\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#1\\nmov x5,#1\\nmov x16,#-15\\nsvc #0x80\\ncbnz x0,91f\\nldr x21,[sp]\\nmov x0,x19\\nmov x1,x21\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#3\\nmov x16,#-14\\nsvc #0x80\\ncbnz x0,91f\\nmov x22,#42\\nstr x22,[x21]\\nldr x0,[x21]\\ncmp x0,x22\\nb.ne 91f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n91: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _migVmNoneEntry\\n_migVmNoneEntry:\\nsub sp,sp,#128\\nstp xzr,xzr,[sp]\\nstp xzr,xzr,[sp,#16]\\nstp xzr,xzr,[sp,#32]\\nstp xzr,xzr,[sp,#48]\\nstp xzr,xzr,[sp,#64]\\nstp xzr,xzr,[sp,#80]\\nstp xzr,xzr,[sp,#96]\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nstr w0,[sp,#8]\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nstr w0,[sp,#12]\\nmov w0,#0x1513\\nmovk w0,#0x8000,lsl #16\\nstr w0,[sp]\\nmov w0,#100\\nstr w0,[sp,#4]\\nmov w0,#4811\\nstr w0,[sp,#20]\\nmov w0,#1\\nstr w0,[sp,#24]\\nstr w0,[sp,#44]\\nstr w0,[sp,#72]\\nstr w0,[sp,#96]\\nmov w0,#19\\nstrb w0,[sp,#38]\\nmov x0,#0x4000\\nstr x0,[sp,#56]\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\nldr w2,[sp]\\nmov x9,#100\\norr x2,x2,x9,lsl #32\\norr x3,x19,x20,lsl #32\\nmov x4,#4811\\nlsl x4,x4,#32\\nmov x5,#1\\norr x5,x5,x20,lsl #32\\nmov x6,#52\\nmov x7,#0\\nmov x16,#-47\\nsvc #0x80\\ncbnz x0,92f\\nldr w0,[sp,#32]\\ncbnz x0,92f\\nldr x21,[sp,#36]\\nstr xzr,[x21]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n92: mov x16,#21\\nsvc #0x80\\nb .\\n"
            ".globl _migBadDestinationEntry\\n_migBadDestinationEntry:\\nsub sp,sp,#128\\nstp xzr,xzr,[sp]\\nstp xzr,xzr,[sp,#16]\\nstp xzr,xzr,[sp,#32]\\nstp xzr,xzr,[sp,#48]\\nstp xzr,xzr,[sp,#64]\\nstp xzr,xzr,[sp,#80]\\nstp xzr,xzr,[sp,#96]\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nstr w0,[sp,#8]\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nstr w0,[sp,#12]\\nmov w0,#0x1513\\nmovk w0,#0x8000,lsl #16\\nstr w0,[sp]\\nmov w0,#100\\nstr w0,[sp,#4]\\nmov w0,#4811\\nstr w0,[sp,#20]\\nmov w0,#1\\nstr w0,[sp,#24]\\nstr w0,[sp,#44]\\nstr w0,[sp,#72]\\nstr w0,[sp,#96]\\nmov w0,#19\\nstrb w0,[sp,#38]\\nmov x0,#0x4000\\nstr x0,[sp,#56]\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\nldr w2,[sp]\\nmov x9,#100\\norr x2,x2,x9,lsl #32\\nmov x3,#0\\norr x3,x3,x20,lsl #32\\nmov x4,#4811\\nlsl x4,x4,#32\\nmov x5,#1\\norr x5,x5,x20,lsl #32\\nmov x6,#52\\nmov x7,#0\\nmov x16,#-47\\nsvc #0x80\\nmov w9,#3\\nmovk w9,#0x1000,lsl #16\\ncmp x0,x9\\nb.ne 92f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n92: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _migMemoryObjectEntry\\n_migMemoryObjectEntry:\\nsub sp,sp,#128\\nstp xzr,xzr,[sp]\\nstp xzr,xzr,[sp,#16]\\nstp xzr,xzr,[sp,#32]\\nstp xzr,xzr,[sp,#48]\\nstp xzr,xzr,[sp,#64]\\nstp xzr,xzr,[sp,#80]\\nstp xzr,xzr,[sp,#96]\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nstr w0,[sp,#8]\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nstr w0,[sp,#12]\\nmov w0,#0x1513\\nmovk w0,#0x8000,lsl #16\\nstr w0,[sp]\\nmov w0,#100\\nstr w0,[sp,#4]\\nmov w0,#4811\\nstr w0,[sp,#20]\\nmov w0,#1\\nstr w0,[sp,#24]\\nstr w0,[sp,#44]\\nstr w0,[sp,#72]\\nstr w0,[sp,#96]\\nmov w0,#19\\nstrb w0,[sp,#38]\\nmov x0,#0x4000\\nstr x0,[sp,#56]\\nmov w9,#1\\nstr w9,[sp,#28]\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\nldr w2,[sp]\\nmov x9,#100\\norr x2,x2,x9,lsl #32\\norr x3,x19,x20,lsl #32\\nmov x4,#4811\\nlsl x4,x4,#32\\nmov x5,#1\\norr x5,x5,x20,lsl #32\\nmov x6,#52\\nmov x7,#0\\nmov x16,#-47\\nsvc #0x80\\ncbnz x0,92f\\nldr w0,[sp,#32]\\ncbnz x0,92f\\nldr x21,[sp,#36]\\nstr xzr,[x21]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n92: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _unsupportedOpenEntry\\n_unsupportedOpenEntry:\\nadr x0,93f\\nmov x1,#0\\nmov x2,#0\\nmov x16,#5\\nsvc #0x80\\nb.cc 94f\\ncmp x0,#2\\nb.ne 94f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n94: mov x16,#21\\nsvc #0x80\\nb .\\n93: .asciz \\\"/owned/guest-file\\\"\\n.p2align 2\\n"
            ".globl _sandboxEntry\\n_sandboxEntry:\\nsub sp,sp,#96\\nmov x16,#20\\nsvc #0x80\\nmov x19,x0\\nadd x8,sp,#64\\nstr x8,[sp]\\nstr x19,[sp,#8]\\nadr x8,Lof_sandbox_operation\\nstr x8,[sp,#16]\\nmov x8,#65\\nstr x8,[sp,#24]\\nmov x8,#550\\nstr x8,[sp,#32]\\nmov x8,#1\\nstr x8,[sp,#40]\\nmov x23,#20\\nLof_sandbox_loop:\\nmov x8,#1234\\nstr x8,[sp,#64]\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nadr x0,Lof_sandbox_policy\\nmov x1,#2\\nmov x2,sp\\nmov x16,#381\\nsvc #0x80\\nb.cs Lof_sandbox_fail\\ncbnz x0,Lof_sandbox_fail\\ncbnz x1,Lof_sandbox_fail\\nmrs x26,nzcv\\nmov x25,#0xd0000000\\ncmp x26,x25\\nb.ne Lof_sandbox_fail\\nldr x8,[sp,#64]\\ncbnz x8,Lof_sandbox_fail\\nsubs x23,x23,#1\\nb.ne Lof_sandbox_loop\\nadd x8,x19,#1\\nstr x8,[sp,#8]\\nmov x8,#1234\\nstr x8,[sp,#64]\\nadr x0,Lof_sandbox_policy\\nmov x1,#2\\nmov x2,sp\\nmov x16,#381\\nsvc #0x80\\nb.cc Lof_sandbox_fail\\ncmp x0,#3\\nb.ne Lof_sandbox_fail\\nldr x8,[sp,#64]\\ncmp x8,#1234\\nb.ne Lof_sandbox_fail\\nstr x19,[sp,#8]\\nadr x8,Lof_sandbox_policy\\nstr x8,[sp]\\nadr x0,Lof_sandbox_policy\\nmov x1,#2\\nmov x2,sp\\nmov x16,#381\\nsvc #0x80\\nb.cc Lof_sandbox_fail\\ncmp x0,#14\\nb.ne Lof_sandbox_fail\\nadr x0,Lof_sandbox_policy\\nmov x1,#2\\nmov x2,#1\\nmov x16,#381\\nsvc #0x80\\nb.cc Lof_sandbox_fail\\ncmp x0,#14\\nb.ne Lof_sandbox_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_sandbox_fail:\\nmov x16,#21\\nsvc #0x80\\nb .\\n.globl _sandboxUnknownEntry\\n_sandboxUnknownEntry:\\nsub sp,sp,#96\\nmov x16,#20\\nsvc #0x80\\nmov x19,x0\\nadd x8,sp,#64\\nstr x8,[sp]\\nstr x19,[sp,#8]\\nadr x8,Lof_sandbox_operation\\nstr x8,[sp,#16]\\nmov x8,#65\\nstr x8,[sp,#24]\\nmov x8,#550\\nstr x8,[sp,#32]\\nmov x8,#1\\nstr x8,[sp,#40]\\nadr x8,Lof_sandbox_unknown\\nstr x8,[sp,#16]\\nadr x0,Lof_sandbox_policy\\nmov x1,#2\\nmov x2,sp\\nmov x16,#381\\nsvc #0x80\\nb .\\n.globl _sandboxProfileEntry\\n_sandboxProfileEntry:\\nsub sp,sp,#96\\nmov x16,#20\\nsvc #0x80\\nmov x19,x0\\nadd x8,sp,#64\\nstr x8,[sp]\\nstr x19,[sp,#8]\\nadr x8,Lof_sandbox_operation\\nstr x8,[sp,#16]\\nmov x8,#65\\nstr x8,[sp,#24]\\nmov x8,#550\\nstr x8,[sp,#32]\\nmov x8,#1\\nstr x8,[sp,#40]\\nadr x0,Lof_sandbox_policy\\nmov x1,#0\\nmov x2,sp\\nmov x16,#381\\nsvc #0x80\\nb .\\n.globl _sandboxUnavailableEntry\\n_sandboxUnavailableEntry:\\nsub sp,sp,#96\\nmov x16,#20\\nsvc #0x80\\nmov x19,x0\\nadd x8,sp,#64\\nstr x8,[sp]\\nstr x19,[sp,#8]\\nadr x8,Lof_sandbox_operation\\nstr x8,[sp,#16]\\nmov x8,#65\\nstr x8,[sp,#24]\\nmov x8,#555\\nstr x8,[sp,#32]\\nmov x8,#1\\nstr x8,[sp,#40]\\nadr x0,Lof_sandbox_policy\\nmov x1,#2\\nmov x2,sp\\nmov x16,#381\\nsvc #0x80\\nb.cs Lof_sandbox_fail\\nmov x16,#555\\nsvc #0x80\\nb .\\nLof_sandbox_policy: .asciz \\\"Sandbox\\\"\\nLof_sandbox_operation: .asciz \\\"syscall-unix\\\"\\nLof_sandbox_unknown: .asciz \\\"unknown-operation\\\"\\n.p2align 2\\n"
            ".globl _sysctlEntry\\n_sysctlEntry:\\nsub sp,sp,#96\\nmov x8,#0x300000000\\nstr x8,[sp]\\nmov x23,#20\\nLof_sysctl_loop:\\nmov x8,#56\\nstr x8,[sp,#16]\\nmov x0,sp\\nmov x1,#2\\nadd x2,sp,#32\\nadd x3,sp,#16\\nadr x4,Lof_sysctl_pagesize_name\\nmov x5,#11\\nmov x16,#202\\nsvc #0x80\\nb.cs Lof_sysctl_fail\\ncbnz x0,Lof_sysctl_fail\\ncbnz x1,Lof_sysctl_fail\\nldr x8,[sp,#16]\\ncmp x8,#8\\nb.ne Lof_sysctl_fail\\nldr w8,[sp,#32]\\ncmp w8,#6\\nb.ne Lof_sysctl_fail\\nldr w8,[sp,#36]\\ncmp w8,#7\\nb.ne Lof_sysctl_fail\\nsubs x23,x23,#1\\nb.ne Lof_sysctl_loop\\nmov x8,#-1\\nstr x8,[sp,#16]\\nadd x0,sp,#32\\nmov x1,#2\\nadd x2,sp,#48\\nadd x3,sp,#16\\nmov x4,#0\\nmov x5,#0\\nmov x25,#0xf0000000\\nmsr nzcv,x25\\nmov x16,#202\\nsvc #0x80\\nb.cs Lof_sysctl_fail\\ncbnz x0,Lof_sysctl_fail\\ncbnz x1,Lof_sysctl_fail\\nmrs x26,nzcv\\nmov x25,#0xd0000000\\ncmp x26,x25\\nb.ne Lof_sysctl_fail\\nldr x8,[sp,#16]\\ncmp x8,#4\\nb.ne Lof_sysctl_fail\\nmov x8,#0x4000\\nmovk x8,#0xffff,lsl #16\\nmovk x8,#0xf,lsl #32\\nldrb w8,[x8,#0x37]\\nmov x9,#1\\nlsl x9,x9,x8\\nldr w8,[sp,#48]\\ncmp x8,x9\\nb.ne Lof_sysctl_fail\\nmov x8,#0\\nstr x8,[sp,#16]\\nadd x0,sp,#32\\nmov x1,#2\\nmov x2,#0\\nadd x3,sp,#16\\nmov x4,#0\\nmov x5,#0\\nmov x16,#202\\nsvc #0x80\\nb.cs Lof_sysctl_fail\\nldr x8,[sp,#16]\\ncmp x8,#4\\nb.ne Lof_sysctl_fail\\nmov x8,#3\\nstr x8,[sp,#16]\\nmov x8,#1234\\nstr x8,[sp,#48]\\nadd x0,sp,#32\\nmov x1,#2\\nadd x2,sp,#48\\nadd x3,sp,#16\\nmov x4,#0\\nmov x5,#0\\nmov x16,#202\\nsvc #0x80\\nb.cc Lof_sysctl_fail\\ncmp x0,#12\\nb.ne Lof_sysctl_fail\\nldr x8,[sp,#16]\\ncbnz x8,Lof_sysctl_fail\\nldr x8,[sp,#48]\\ncmp x8,#1234\\nb.ne Lof_sysctl_fail\\nmov x8,#56\\nstr x8,[sp,#16]\\nmov x0,sp\\nmov x1,#2\\nadd x2,sp,#48\\nadd x3,sp,#16\\nadr x4,Lof_sysctl_missing_name\\nmov x5,#32\\nmov x16,#202\\nsvc #0x80\\nb.cc Lof_sysctl_fail\\ncmp x0,#2\\nb.ne Lof_sysctl_fail\\nldr x8,[sp,#16]\\ncmp x8,#56\\nb.ne Lof_sysctl_fail\\nldr x8,[sp,#48]\\ncmp x8,#1234\\nb.ne Lof_sysctl_fail\\nadd x0,sp,#32\\nmov x1,#2\\nadd x2,sp,#48\\nadd x3,sp,#16\\nmov x4,sp\\nmov x5,#4\\nmov x16,#202\\nsvc #0x80\\nb.cc Lof_sysctl_fail\\ncmp x0,#1\\nb.ne Lof_sysctl_fail\\nmov x0,#1\\nmov x1,#2\\nmov x2,#0\\nmov x3,#0\\nmov x4,#0\\nmov x5,#0\\nmov x16,#202\\nsvc #0x80\\nb.cc Lof_sysctl_fail\\ncmp x0,#14\\nb.ne Lof_sysctl_fail\\nadd x0,sp,#32\\nmov x1,#2\\nmov x2,#0\\nmov x3,#1\\nmov x4,#0\\nmov x5,#0\\nmov x16,#202\\nsvc #0x80\\nb.cc Lof_sysctl_fail\\ncmp x0,#14\\nb.ne Lof_sysctl_fail\\nmov x0,#1\\nmov x1,#13\\nmov x16,#202\\nsvc #0x80\\nb.cc Lof_sysctl_fail\\ncmp x0,#22\\nb.ne Lof_sysctl_fail\\nmov x8,#4\\nstr x8,[sp,#16]\\nadd x0,sp,#32\\nmov x1,#2\\nadr x2,Lof_sysctl_pagesize_name\\nadd x3,sp,#16\\nmov x4,#0\\nmov x5,#0\\nmov x16,#202\\nsvc #0x80\\nb.cc Lof_sysctl_fail\\ncmp x0,#14\\nb.ne Lof_sysctl_fail\\nldr x8,[sp,#16]\\ncmp x8,#4\\nb.ne Lof_sysctl_fail\\nmov x0,#202\\nadd x1,sp,#32\\nmov x2,#2\\nadd x3,sp,#48\\nadd x4,sp,#16\\nmov x5,#0\\nmov x6,#0\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_sysctl_fail\\ncbnz x0,Lof_sysctl_fail\\ncbnz x1,Lof_sysctl_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_sysctl_fail:\\nmov x16,#21\\nsvc #0x80\\nb .\\nLof_sysctl_pagesize_name: .asciz \\\"hw.pagesize\\\"\\nLof_sysctl_missing_name: .asciz \\\"security.mac.lockdown_mode_state\\\"\\n.p2align 2\\n"
            ".globl _missingMacPolicyEntry\\n_missingMacPolicyEntry:\\nsub sp,sp,#32\\nmov x8,#1234\\nstr x8,[sp]\\nmov x23,#20\\nLof_missing_mac_loop:\\nadr x0,Lof_missing_mac_amfi\\nmov x1,#90\\nmov x2,#1\\nmov x25,#0xd0000000\\nmsr nzcv,x25\\nmov x16,#381\\nsvc #0x80\\nb.cc Lof_missing_mac_fail\\ncmp x0,#103\\nb.ne Lof_missing_mac_fail\\ncbnz x1,Lof_missing_mac_fail\\nsubs x23,x23,#1\\nb.ne Lof_missing_mac_loop\\nadr x0,Lof_missing_mac_other\\nmov x1,#999\\nmov x2,sp\\nmov x25,#0xd0000000\\nmsr nzcv,x25\\nmov x16,#381\\nsvc #0x80\\nmrs x26,nzcv\\nmov x25,#0xf0000000\\ncmp x26,x25\\nb.ne Lof_missing_mac_fail\\ncmp x0,#103\\nb.ne Lof_missing_mac_fail\\ncbnz x1,Lof_missing_mac_fail\\nldr x8,[sp]\\ncmp x8,#1234\\nb.ne Lof_missing_mac_fail\\nmov x0,#381\\nadr x1,Lof_missing_mac_other\\nmov x2,#999\\nmov x3,sp\\nmov x16,#0\\nsvc #0x80\\nb.cc Lof_missing_mac_fail\\ncmp x0,#103\\nb.ne Lof_missing_mac_fail\\nldr x8,[sp]\\ncmp x8,#1234\\nb.ne Lof_missing_mac_fail\\nadr x0,Lof_missing_mac_long\\nmov x1,#90\\nmov x2,#1\\nmov x16,#381\\nsvc #0x80\\nb.cc Lof_missing_mac_fail\\ncmp x0,#63\\nb.ne Lof_missing_mac_fail\\nmov x0,#1\\nmov x1,#90\\nmov x2,#1\\nmov x16,#381\\nsvc #0x80\\nb.cc Lof_missing_mac_fail\\ncmp x0,#14\\nb.ne Lof_missing_mac_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_missing_mac_fail:\\nmov x16,#21\\nsvc #0x80\\nb .\\nLof_missing_mac_amfi: .asciz \\\"OwnedMissingAmfi\\\"\\nLof_missing_mac_other: .asciz \\\"OwnedMissingPolicy\\\"\\nLof_missing_mac_long: .asciz \\\"01234567890123456789012345678901\\\"\\n.p2align 2\\n"
            ".globl _mmapGeometryEntry\\n_mmapGeometryEntry:\\nsub sp,sp,#192\\nadr x0,Lof_vm_tail_path\\nmov x1,#0\\nmov x16,#5\\nsvc #0x80\\nb.cs Lof_vm_tail_fail\\nmov x19,x0\\nmov x0,x19\\nmov x1,sp\\nmov x16,#339\\nsvc #0x80\\nb.cs Lof_vm_tail_fail\\nldr x26,[sp,#96]\\nmov x0,x19\\nmov x1,sp\\nmov x2,#2\\nmov x16,#3\\nsvc #0x80\\nb.cs Lof_vm_tail_fail\\ncmp x0,#2\\nb.ne Lof_vm_tail_fail\\nldrb w25,[sp,#1]\\nmov x2,#0x4000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldrb w8,[x2,#0x37]\\nmov x27,#1\\nlsl x27,x27,x8\\nsub x9,x27,#1\\nadd x23,x26,x9\\nbic x23,x23,x9\\ncmp x23,x26\\nb.eq Lof_vm_tail_fail\\nmov x0,#0\\nmov x1,x23\\nmov x2,#3\\nmov x3,#2\\nmovk x3,#4,lsl #16\\nmov x4,x19\\nmov x5,#0\\nmov x16,#197\\nsvc #0x80\\nb.cs Lof_vm_tail_fail\\nmov x24,x0\\nldrb w8,[x24,#1]\\ncmp w8,w25\\nb.ne Lof_vm_tail_fail\\nmov x9,x26\\nLof_vm_tail_zero:\\nldrb w8,[x24,x9]\\ncbnz w8,Lof_vm_tail_fail\\nadd x9,x9,#1\\ncmp x9,x23\\nb.lo Lof_vm_tail_zero\\nmov x16,#-28\\nsvc #0x80\\nmov x20,x0\\nstr xzr,[sp]\\nmov x1,sp\\nmov x2,x27\\nmov x3,#1\\nmov x16,#-10\\nsvc #0x80\\ncbnz x0,Lof_vm_tail_fail\\nldr x21,[sp]\\nadd x22,x21,#1\\nmov x0,x22\\nsub x1,x27,#1\\nmov x2,#3\\nmov x3,#0x12\\nmov x4,x19\\nmov x5,#1\\nmov x16,#197\\nsvc #0x80\\nb.cs Lof_vm_tail_fail\\ncmp x0,x22\\nb.ne Lof_vm_tail_fail\\nldrb w8,[x22]\\ncmp w8,w25\\nb.ne Lof_vm_tail_fail\\nadd x0,x22,#1\\nmov x1,#1\\nmov x2,#1\\nmov x3,#0x12\\nmov x4,x19\\nmov x5,#1\\nmov x16,#197\\nsvc #0x80\\nb.cc Lof_vm_tail_fail\\ncmp x0,#22\\nb.ne Lof_vm_tail_fail\\ncbnz x1,Lof_vm_tail_fail\\nldrb w8,[x22]\\ncmp w8,w25\\nb.ne Lof_vm_tail_fail\\nmov x0,x22\\nmov x1,#1\\nmov x2,#1\\nmov x3,#0x12\\nmovk x3,#4,lsl #16\\nmov x4,x19\\nmov x5,#1\\nmov x16,#197\\nsvc #0x80\\nb.cc Lof_vm_tail_fail\\ncmp x0,#22\\nb.ne Lof_vm_tail_fail\\nldrb w8,[x22]\\ncmp w8,w25\\nb.ne Lof_vm_tail_fail\\nmov x0,x19\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_vm_tail_fail\\nldrb w8,[x22]\\ncmp w8,w25\\nb.ne Lof_vm_tail_fail\\nmov x0,x24\\nmov x1,x23\\nmov x16,#73\\nsvc #0x80\\nb.cs Lof_vm_tail_fail\\nldrb w8,[x22]\\ncmp w8,w25\\nb.ne Lof_vm_tail_fail\\nmov x0,x21\\nmov x1,x27\\nmov x16,#73\\nsvc #0x80\\nb.cs Lof_vm_tail_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_vm_tail_fail:\\nmov x16,#65534\\nsvc #0x80\\nb .\\nLof_vm_tail_path: .asciz \\\"/process/vm-eof-source\\\"\\n.p2align 2\\n"
            ".globl _mmapConsumerEntry\\n_mmapConsumerEntry:\\nsub sp,sp,#192\\nadr x0,Lof_mmap_path\\nmov x1,#0\\nmov x16,#5\\nsvc #0x80\\nb.cs Lof_mmap_fail\\nmov x19,x0\\nmov x0,x19\\nmov x1,sp\\nmov x16,#339\\nsvc #0x80\\nb.cs Lof_mmap_fail\\nldr x26,[sp,#96]\\nmov x0,x19\\nmov x1,sp\\nmov x2,#8\\nmov x16,#3\\nsvc #0x80\\nb.cs Lof_mmap_fail\\ncmp x0,#8\\nb.ne Lof_mmap_fail\\nldr x25,[sp]\\nmov x2,#0x4000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldrb w8,[x2,#0x37]\\nmov x27,#1\\nlsl x27,x27,x8\\nadd x8,x27,x27\\ncmp x26,x8\\nb.ls Lof_mmap_fail\\nmov x0,#0\\nmov x1,x26\\nmov x2,#1\\nmov x3,#2\\nmovk x3,#4,lsl #16\\nmov x4,x19\\nmov x5,#0\\nmov x8,#0xb0000000\\nmsr nzcv,x8\\nmov x16,#197\\nsvc #0x80\\nb.cs Lof_mmap_fail\\nmrs x8,nzcv\\nmov x9,#0x90000000\\ncmp x8,x9\\nb.ne Lof_mmap_fail\\ncbnz x1,Lof_mmap_fail\\nmov x20,x0\\nldr x8,[x20]\\ncmp x8,x25\\nb.ne Lof_mmap_fail\\nmov x0,#197\\nmov x1,#0\\nmov x2,x26\\nmov x3,#3\\nmov x4,#2\\nmovk x4,#4,lsl #16\\nmov x5,x19\\nmov x6,#0\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_mmap_fail\\ncbnz x1,Lof_mmap_fail\\nmov x21,x0\\nldr x8,[x21]\\ncmp x8,x25\\nb.ne Lof_mmap_fail\\nldrb w8,[x21]\\neor w8,w8,#0xff\\nstrb w8,[x21]\\nldr x8,[x20]\\ncmp x8,x25\\nb.ne Lof_mmap_fail\\nmov x0,x19\\nmov x1,#0\\nmov x2,#1\\nmov x16,#199\\nsvc #0x80\\nb.cs Lof_mmap_fail\\ncmp x0,#8\\nb.ne Lof_mmap_fail\\nmov x0,x19\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_mmap_fail\\nldr x8,[x20]\\ncmp x8,x25\\nb.ne Lof_mmap_fail\\nadd x0,x20,x27\\nmov x1,x27\\nmov x16,#73\\nsvc #0x80\\nb.cs Lof_mmap_fail\\ncbnz x0,Lof_mmap_fail\\nldr x8,[x20]\\ncmp x8,x25\\nb.ne Lof_mmap_fail\\nsub x8,x26,#1\\nldrb w9,[x20,x8]\\nldrb w10,[x21,x8]\\ncmp w9,w10\\nb.ne Lof_mmap_fail\\nmov x0,x20\\nmov x1,x26\\nmov x16,#73\\nsvc #0x80\\nb.cs Lof_mmap_fail\\nmov x0,#73\\nmov x1,x21\\nmov x2,x26\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_mmap_fail\\ncbnz x0,Lof_mmap_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_mmap_fail:\\nmov x16,#65534\\nsvc #0x80\\nb .\\nLof_mmap_path: .asciz \\\"/process/main\\\"\\n.p2align 2\\n.globl _mmapWriteDeniedEntry\\n_mmapWriteDeniedEntry:\\nadr x0,Lof_mmap_path\\nmov x1,#0\\nmov x16,#5\\nsvc #0x80\\nmov x4,x0\\nmov x0,#0\\nmov x1,#8\\nmov x2,#9\\nmov x3,#2\\nmovk x3,#4,lsl #16\\nmov x5,#0\\nmov x16,#197\\nsvc #0x80\\nldr x8,[x0]\\nstrb wzr,[x0]\\nmov x16,#65534\\nsvc #0x80\\nb .\\n.space 65536\\n"
            ".globl _mmapErrorConsumerEntry\\n_mmapErrorConsumerEntry:\\nsub sp,sp,#160\\nadr x0,Lof_mmap_path\\nmov x1,#0\\nmov x16,#5\\nsvc #0x80\\nb.cs Lof_mmap_error_fail\\nmov x19,x0\\nmov x0,x19\\nmov x1,sp\\nmov x16,#339\\nsvc #0x80\\nb.cs Lof_mmap_error_fail\\nldr x26,[sp,#96]\\nmov x20,#20\\nLof_mmap_error_loop:\\nmov x0,#0\\nmov x1,#8\\nmov x2,#1\\nmov x3,#2\\nmovk x3,#4,lsl #16\\nmov x4,x19\\nmov x5,#0\\nmov x4,#999\\nmov x16,#197\\nsvc #0x80\\nb.cc Lof_mmap_error_fail\\ncmp x0,#9\\nb.ne Lof_mmap_error_fail\\ncbnz x1,Lof_mmap_error_fail\\nmov x0,#0\\nmov x1,#8\\nmov x2,#1\\nmov x3,#2\\nmovk x3,#4,lsl #16\\nmov x4,x19\\nmov x5,#0\\nmov x1,#0\\nmov x16,#197\\nsvc #0x80\\nb.cc Lof_mmap_error_fail\\ncmp x0,#22\\nb.ne Lof_mmap_error_fail\\ncbnz x1,Lof_mmap_error_fail\\nmov x0,#0\\nmov x1,#8\\nmov x2,#1\\nmov x3,#2\\nmovk x3,#4,lsl #16\\nmov x4,x19\\nmov x5,#0\\nmov x5,#1\\nmov x16,#197\\nsvc #0x80\\nb.cc Lof_mmap_error_fail\\ncmp x0,#22\\nb.ne Lof_mmap_error_fail\\ncbnz x1,Lof_mmap_error_fail\\nmov x0,#0\\nmov x1,#8\\nmov x2,#1\\nmov x3,#2\\nmovk x3,#4,lsl #16\\nmov x4,x19\\nmov x5,#0\\nmov x5,#-1\\nmov x16,#197\\nsvc #0x80\\nb.cc Lof_mmap_error_fail\\ncmp x0,#22\\nb.ne Lof_mmap_error_fail\\ncbnz x1,Lof_mmap_error_fail\\nmov x0,#0\\nmov x1,#8\\nmov x2,#1\\nmov x3,#2\\nmovk x3,#4,lsl #16\\nmov x4,x19\\nmov x5,#0\\nadd x1,x26,#0x4000\\nmov x16,#197\\nsvc #0x80\\nb.cc Lof_mmap_error_fail\\ncmp x0,#45\\nb.ne Lof_mmap_error_fail\\ncbnz x1,Lof_mmap_error_fail\\nmov x0,#0\\nmov x1,#8\\nmov x2,#1\\nmov x3,#2\\nmovk x3,#4,lsl #16\\nmov x4,x19\\nmov x5,#0\\nmov x3,#1\\nmov x16,#197\\nsvc #0x80\\nb.cc Lof_mmap_error_fail\\ncmp x0,#45\\nb.ne Lof_mmap_error_fail\\ncbnz x1,Lof_mmap_error_fail\\nsubs x20,x20,#1\\nb.ne Lof_mmap_error_loop\\nmov x0,x19\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_mmap_error_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_mmap_error_fail:\\nmov x16,#65534\\nsvc #0x80\\nb .\\n.globl _mmapPartialHoleEntry\\n_mmapPartialHoleEntry:\\nadr x0,Lof_mmap_path\\nmov x1,#0\\nmov x16,#5\\nsvc #0x80\\nmov x4,x0\\nmov x2,#0x4000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldrb w8,[x2,#0x37]\\nmov x27,#1\\nlsl x27,x27,x8\\nmov x0,#0\\nadd x1,x27,x27\\nadd x1,x1,x27\\nmov x2,#1\\nmov x3,#2\\nmovk x3,#4,lsl #16\\nmov x5,#0\\nmov x16,#197\\nsvc #0x80\\nb.cs Lof_mmap_error_fail\\nadd x19,x0,x27\\nmov x0,x19\\nmov x1,x27\\nmov x16,#73\\nsvc #0x80\\nb.cs Lof_mmap_error_fail\\nldr x8,[x19]\\nmov x16,#65534\\nsvc #0x80\\nb .\\n"
            ".globl _writeConsumerEntry\\n_writeConsumerEntry:\\nmov x20,#20\\nLof_write_loop:\\nmov x8,#0xb0000000\\nmsr nzcv,x8\\nmov x0,#2\\nadr x1,Lof_write_data\\nmov x2,#8\\nmov x16,#4\\nsvc #0x80\\nb.cs Lof_write_fail\\nmrs x8,nzcv\\nmov x9,#0x90000000\\ncmp x8,x9\\nb.ne Lof_write_fail\\ncmp x0,#8\\nb.ne Lof_write_fail\\ncbnz x1,Lof_write_fail\\nmov x0,#4\\nmov x1,#2\\nadr x2,Lof_write_data\\nmov x3,#8\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_write_fail\\ncmp x0,#8\\nb.ne Lof_write_fail\\ncbnz x1,Lof_write_fail\\nmov x0,#2\\nmov x1,#1\\nmov x2,#0\\nmov x16,#4\\nsvc #0x80\\nb.cs Lof_write_fail\\ncbnz x0,Lof_write_fail\\ncbnz x1,Lof_write_fail\\nmov x0,#2\\nmov x1,#1\\nmov x2,#8\\nmov x16,#4\\nsvc #0x80\\nb.cc Lof_write_fail\\ncmp x0,#14\\nb.ne Lof_write_fail\\ncbnz x1,Lof_write_fail\\nmov x0,#999\\nmov x1,#1\\nmov x2,#8\\nmov x16,#4\\nsvc #0x80\\nb.cc Lof_write_fail\\ncmp x0,#9\\nb.ne Lof_write_fail\\ncbnz x1,Lof_write_fail\\nmov x0,#2\\nmov x1,#1\\nmov x2,#-1\\nmov x16,#4\\nsvc #0x80\\nb.cc Lof_write_fail\\ncmp x0,#22\\nb.ne Lof_write_fail\\ncbnz x1,Lof_write_fail\\nsubs x20,x20,#1\\nb.ne Lof_write_loop\\nadr x0,Lof_write_path\\nmov x1,#0\\nmov x16,#5\\nsvc #0x80\\nb.cs Lof_write_fail\\nmov x19,x0\\nadr x1,Lof_write_data\\nmov x2,#8\\nmov x16,#4\\nsvc #0x80\\nb.cc Lof_write_fail\\ncmp x0,#9\\nb.ne Lof_write_fail\\nmov x0,x19\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_write_fail\\nmov x0,#2\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_write_fail\\nmov x0,#2\\nadr x1,Lof_write_data\\nmov x2,#8\\nmov x16,#4\\nsvc #0x80\\nb.cc Lof_write_fail\\ncmp x0,#9\\nb.ne Lof_write_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_write_fail:\\nmov x16,#65534\\nsvc #0x80\\nb .\\nLof_write_data: .ascii \\\"of-write\\\"\\nLof_write_path: .asciz \\\"/process/main\\\"\\n.p2align 2\\n"
            ".globl _signatureConsumerEntry\\n_signatureConsumerEntry:\\nsub sp,sp,#4096\\nadr x0,Lof_sig_path\\nmov x1,#0\\nmov x2,#0\\nmov x16,#5\\nsvc #0x80\\nb.cs Lof_sig_fail\\nmov x19,x0\\nadd x1,sp,#128\\nmov x2,#2048\\nmov x16,#3\\nsvc #0x80\\nb.cs Lof_sig_fail\\ncmp x0,#32\\nb.lo Lof_sig_fail\\nadd x8,sp,#128\\nldr w9,[x8,#16]\\nadd x8,x8,#32\\nLof_sig_commands:\\ncbz w9,Lof_sig_fail\\nldr w10,[x8]\\ncmp w10,#29\\nb.eq Lof_sig_found\\nldr w10,[x8,#4]\\nadd x8,x8,x10\\nsub w9,w9,#1\\nb Lof_sig_commands\\nLof_sig_found:\\nldr w22,[x8,#8]\\nldr w23,[x8,#12]\\nmov x24,#4095\\nadd x24,x22,x24\\nand x24,x24,#0xfffffffffffff000\\nmov x20,#20\\nLof_sig_loop:\\nstr xzr,[sp]\\nstr x22,[sp,#8]\\nstr x23,[sp,#16]\\nmov x8,#0x5a\\nstr x8,[sp,#24]\\nmov x8,#0xb0000000\\nmsr nzcv,x8\\nmov x0,x19\\nmov x1,#97\\nmov x2,sp\\nmov x16,#92\\nsvc #0x80\\nb.cs Lof_sig_fail\\nmrs x8,nzcv\\nmov x9,#0x90000000\\ncmp x8,x9\\nb.ne Lof_sig_fail\\ncbnz x0,Lof_sig_fail\\ncbnz x1,Lof_sig_fail\\nldr x8,[sp]\\ncmp x8,x24\\nb.ne Lof_sig_fail\\nldr x8,[sp,#8]\\ncmp x8,x22\\nb.ne Lof_sig_fail\\nldr x8,[sp,#16]\\ncmp x8,x23\\nb.ne Lof_sig_fail\\nldr x8,[sp,#24]\\ncmp x8,#0x5a\\nb.ne Lof_sig_fail\\nstr xzr,[sp]\\nmov x0,#92\\nmov x1,x19\\nmov x2,#97\\nmov x3,sp\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_sig_fail\\ncbnz x0,Lof_sig_fail\\ncbnz x1,Lof_sig_fail\\nldr x8,[sp]\\ncmp x8,x24\\nb.ne Lof_sig_fail\\nldr x8,[sp,#24]\\ncmp x8,#0x5a\\nb.ne Lof_sig_fail\\nmov x0,x19\\nmov x1,#97\\nmov x2,#1\\nmov x16,#92\\nsvc #0x80\\nb.cc Lof_sig_fail\\ncmp x0,#14\\nb.ne Lof_sig_fail\\nmov x0,#-1\\nmov x1,#97\\nmov x2,#1\\nmov x16,#92\\nsvc #0x80\\nb.cc Lof_sig_fail\\ncmp x0,#9\\nb.ne Lof_sig_fail\\nstr xzr,[sp]\\nsub x8,x23,#1\\nstr x8,[sp,#16]\\nmov x0,x19\\nmov x1,#97\\nmov x2,sp\\nmov x16,#92\\nsvc #0x80\\nb.cc Lof_sig_fail\\ncmp x0,#80\\nb.ne Lof_sig_fail\\nldr x8,[sp]\\ncbnz x8,Lof_sig_fail\\nstr x23,[sp,#16]\\nmov x8,#1\\nstr x8,[sp]\\nmov x0,x19\\nmov x1,#97\\nmov x2,sp\\nmov x16,#92\\nsvc #0x80\\nb.cc Lof_sig_fail\\ncmp x0,#45\\nb.ne Lof_sig_fail\\nldr x8,[sp]\\ncmp x8,#1\\nb.ne Lof_sig_fail\\nstr xzr,[sp]\\nmov x16,#-28\\nsvc #0x80\\nmov x27,x0\\nmov x1,sp\\nmov x2,#24\\nmov x3,#0\\nmov x4,#1\\nmov x16,#-14\\nsvc #0x80\\ncbnz x0,Lof_sig_fail\\nmov x0,x19\\nmov x1,#97\\nmov x2,sp\\nmov x16,#92\\nsvc #0x80\\nb.cc Lof_sig_fail\\ncmp x0,#14\\nb.ne Lof_sig_fail\\nldr x8,[sp]\\ncbnz x8,Lof_sig_fail\\nldr x8,[sp,#24]\\ncmp x8,#0x5a\\nb.ne Lof_sig_fail\\nmov x0,x27\\nmov x1,sp\\nmov x2,#24\\nmov x3,#0\\nmov x4,#3\\nmov x16,#-14\\nsvc #0x80\\ncbnz x0,Lof_sig_fail\\nstr xzr,[sp]\\nmov x8,#512\\nstr x8,[sp,#8]\\nmov x8,#1\\nstr x8,[sp,#16]\\nmov x0,x19\\nmov x1,#98\\nmov x2,sp\\nmov x16,#92\\nsvc #0x80\\nb.cs Lof_sig_fail\\ncbnz x0,Lof_sig_fail\\ncbnz x1,Lof_sig_fail\\nldr x8,[sp]\\ncbnz x8,Lof_sig_fail\\nldr x8,[sp,#8]\\ncmp x8,#512\\nb.ne Lof_sig_fail\\nldr x8,[sp,#16]\\ncmp x8,#1\\nb.ne Lof_sig_fail\\nmov x0,#92\\nmov x1,x19\\nmov x2,#98\\nmov x3,sp\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_sig_fail\\ncbnz x0,Lof_sig_fail\\ncbnz x1,Lof_sig_fail\\nmov x0,x19\\nmov x1,#98\\nmov x2,#1\\nmov x16,#92\\nsvc #0x80\\nb.cc Lof_sig_fail\\ncmp x0,#14\\nb.ne Lof_sig_fail\\nmov x0,#-1\\nmov x1,#98\\nmov x2,#1\\nmov x16,#92\\nsvc #0x80\\nb.cc Lof_sig_fail\\ncmp x0,#9\\nb.ne Lof_sig_fail\\nmov x8,#1\\nstr x8,[sp]\\nmov x8,#16\\nstr x8,[sp,#8]\\nadd x8,sp,#64\\nstr x8,[sp,#16]\\nmov x8,#0x5a\\nstr x8,[sp,#80]\\nmov x0,x19\\nmov x1,#98\\nmov x2,sp\\nmov x16,#92\\nsvc #0x80\\nb.cc Lof_sig_fail\\ncmp x0,#45\\nb.ne Lof_sig_fail\\nldrb w8,[sp,#64]\\ncmp w8,#78\\nb.ne Lof_sig_fail\\nldrb w8,[sp,#79]\\ncbnz w8,Lof_sig_fail\\nldr x8,[sp,#80]\\ncmp x8,#0x5a\\nb.ne Lof_sig_fail\\nmov x8,#1\\nstr x8,[sp,#16]\\nmov x0,x19\\nmov x1,#98\\nmov x2,sp\\nmov x16,#92\\nsvc #0x80\\nb.cc Lof_sig_fail\\ncmp x0,#14\\nb.ne Lof_sig_fail\\nldr x8,[sp]\\ncmp x8,#1\\nb.ne Lof_sig_fail\\nmov x8,#0x5a\\nstr x8,[sp,#152]\\nmov x0,#0\\nmov x1,#5\\nadd x2,sp,#128\\nmov x3,#20\\nmov x16,#169\\nsvc #0x80\\nb.cs Lof_sig_fail\\ncbnz x0,Lof_sig_fail\\nldr x8,[sp,#152]\\ncmp x8,#0x5a\\nb.ne Lof_sig_fail\\nmov x0,#169\\nmov x1,#0\\nmov x2,#5\\nadd x3,sp,#160\\nmov x4,#20\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_sig_fail\\nldr x8,[sp,#128]\\nldr x9,[sp,#160]\\ncmp x8,x9\\nb.ne Lof_sig_fail\\nldr x10,[sp,#136]\\nldr x9,[sp,#168]\\ncmp x10,x9\\nb.ne Lof_sig_fail\\nldr w11,[sp,#144]\\nldr w9,[sp,#176]\\ncmp w11,w9\\nb.ne Lof_sig_fail\\norr x8,x8,x10\\norr x8,x8,x11\\ncbz x8,Lof_sig_fail\\nsubs x20,x20,#1\\nb.ne Lof_sig_loop\\nmov x0,x19\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_sig_fail\\nmov x0,x19\\nmov x1,#98\\nmov x2,#1\\nmov x16,#92\\nsvc #0x80\\nb.cc Lof_sig_fail\\ncmp x0,#9\\nb.ne Lof_sig_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_sig_fail:\\nmov x16,#65534\\nsvc #0x80\\nb .\\nLof_sig_path: .asciz \\\"/process/main\\\"\\n.p2align 2\\n"
            ".globl _loaderPolicyConsumerEntry\\n_loaderPolicyConsumerEntry:\\nsub sp,sp,#64\\nadd x19,sp,#32\\nmov x20,#20\\nLof_lp_loop:\\nstr xzr,[sp]\\nstr x19,[sp,#8]\\nmov x8,#0xfeed\\nstr x8,[sp,#32]\\nmov x8,#0x5a\\nstr x8,[sp,#40]\\nmov x8,#0xb0000000\\nmsr nzcv,x8\\nadr x0,Lof_lp_name\\nmov x1,#90\\nmov x2,sp\\nmov x16,#381\\nsvc #0x80\\nb.cs Lof_lp_fail\\nmrs x8,nzcv\\nmov x9,#0x90000000\\ncmp x8,x9\\nb.ne Lof_lp_fail\\ncbnz x0,Lof_lp_fail\\ncbnz x1,Lof_lp_fail\\nldr x8,[sp,#32]\\ncmp x8,#1\\nb.ne Lof_lp_fail\\nldr x8,[sp,#40]\\ncmp x8,#0x5a\\nb.ne Lof_lp_fail\\nmov x8,#0xfeed\\nstr x8,[sp,#32]\\nmov x0,#381\\nadr x1,Lof_lp_name\\nmov x2,#90\\nmov x3,sp\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_lp_fail\\ncbnz x0,Lof_lp_fail\\ncbnz x1,Lof_lp_fail\\nldr x8,[sp,#32]\\ncmp x8,#1\\nb.ne Lof_lp_fail\\nldr x8,[sp,#40]\\ncmp x8,#0x5a\\nb.ne Lof_lp_fail\\nmov x8,#0xfeed\\nstr x8,[sp,#32]\\nmov x8,#1\\nstr x8,[sp]\\nadr x0,Lof_lp_name\\nmov x1,#90\\nmov x2,sp\\nmov x16,#381\\nsvc #0x80\\nb.cc Lof_lp_fail\\ncmp x0,#45\\nb.ne Lof_lp_fail\\nldr x8,[sp,#32]\\nmov x9,#0xfeed\\ncmp x8,x9\\nb.ne Lof_lp_fail\\nstr xzr,[sp]\\nadr x0,Lof_lp_name\\nmov x1,#90\\nmov x2,#1\\nmov x16,#381\\nsvc #0x80\\nb.cc Lof_lp_fail\\ncmp x0,#14\\nb.ne Lof_lp_fail\\nmov x8,#1\\nstr x8,[sp,#8]\\nadr x0,Lof_lp_name\\nmov x1,#90\\nmov x2,sp\\nmov x16,#381\\nsvc #0x80\\nb.cc Lof_lp_fail\\ncmp x0,#14\\nb.ne Lof_lp_fail\\nadr x8,Lof_lp_name\\nstr x8,[sp,#8]\\nadr x0,Lof_lp_name\\nmov x1,#90\\nmov x2,sp\\nmov x16,#381\\nsvc #0x80\\nb.cc Lof_lp_fail\\ncmp x0,#14\\nb.ne Lof_lp_fail\\nsubs x20,x20,#1\\nb.ne Lof_lp_loop\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_lp_fail:\\nmov x16,#65534\\nsvc #0x80\\nb .\\nLof_lp_name: .asciz \\\"AMFI\\\"\\n.p2align 2\\n.globl _loaderPolicyMutationEntry\\n_loaderPolicyMutationEntry:\\nadr x0,Lof_lp_name\\nmov x1,#91\\nmov x2,#1\\nmov x16,#381\\nsvc #0x80\\nmov x16,#65534\\nsvc #0x80\\nb .\\n"
            ".globl _metadataConsumerEntry\\n_metadataConsumerEntry:\\nsub sp,sp,#320\\nadr x0,Lof_meta_path\\nmov x1,#0\\nmov x16,#5\\nsvc #0x80\\nb.cs Lof_meta_fail\\nmov x19,x0\\nmov x20,#20\\nLof_meta_loop:\\nmov x8,#0xa5\\nstr x8,[sp,#144]\\nmov x8,#0xb0000000\\nmsr nzcv,x8\\nadr x0,Lof_meta_path\\nmov x1,sp\\nmov x16,#338\\nsvc #0x80\\nb.cs Lof_meta_fail\\nmrs x8,nzcv\\nmov x9,#0x90000000\\ncmp x8,x9\\nb.ne Lof_meta_fail\\ncbnz x0,Lof_meta_fail\\ncbnz x1,Lof_meta_fail\\nldr x8,[sp,#144]\\ncmp x8,#0xa5\\nb.ne Lof_meta_fail\\nldr x8,[sp,#8]\\ncbz x8,Lof_meta_fail\\nldr x8,[sp,#96]\\ncbz x8,Lof_meta_fail\\nldrh w8,[sp,#4]\\nand w9,w8,#0xf000\\nmov w10,#0x8000\\ncmp w9,w10\\nb.ne Lof_meta_fail\\nmov w9,#0x92\\nand w8,w8,w9\\ncbnz w8,Lof_meta_fail\\nmov x0,#339\\nmov x1,x19\\nadd x2,sp,#160\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_meta_fail\\ncbnz x0,Lof_meta_fail\\ncbnz x1,Lof_meta_fail\\nmov x21,#0\\nLof_meta_compare:\\nadd x22,sp,#160\\nldr x8,[sp,x21]\\nldr x9,[x22,x21]\\ncmp x8,x9\\nb.ne Lof_meta_fail\\nadd x21,x21,#8\\ncmp x21,#144\\nb.ne Lof_meta_compare\\nmov x8,#0xfeed\\nstr x8,[sp]\\nadr x0,Lof_meta_missing\\nmov x1,sp\\nmov x16,#338\\nsvc #0x80\\nb.cc Lof_meta_fail\\ncmp x0,#2\\nb.ne Lof_meta_fail\\ncbnz x1,Lof_meta_fail\\nldr x8,[sp]\\nmov x9,#0xfeed\\ncmp x8,x9\\nb.ne Lof_meta_fail\\nmov x8,#0xfeed\\nstr x8,[sp]\\nmov x0,#1\\nmov x1,sp\\nmov x16,#338\\nsvc #0x80\\nb.cc Lof_meta_fail\\ncmp x0,#14\\nb.ne Lof_meta_fail\\ncbnz x1,Lof_meta_fail\\nldr x8,[sp]\\nmov x9,#0xfeed\\ncmp x8,x9\\nb.ne Lof_meta_fail\\nmov x8,#0xfeed\\nstr x8,[sp]\\nadr x0,Lof_meta_path\\nadr x1,Lof_meta_path\\nmov x16,#338\\nsvc #0x80\\nb.cc Lof_meta_fail\\ncmp x0,#14\\nb.ne Lof_meta_fail\\ncbnz x1,Lof_meta_fail\\nldr x8,[sp]\\nmov x9,#0xfeed\\ncmp x8,x9\\nb.ne Lof_meta_fail\\nmov x8,#0xfeed\\nstr x8,[sp]\\nmov x0,#999\\nmov x1,sp\\nmov x16,#339\\nsvc #0x80\\nb.cc Lof_meta_fail\\ncmp x0,#9\\nb.ne Lof_meta_fail\\ncbnz x1,Lof_meta_fail\\nldr x8,[sp]\\nmov x9,#0xfeed\\ncmp x8,x9\\nb.ne Lof_meta_fail\\nmov x8,#0xfeed\\nstr x8,[sp]\\nadr x0,Lof_meta_root\\nmov x1,sp\\nmov x16,#338\\nsvc #0x80\\nb.cc Lof_meta_fail\\ncmp x0,#45\\nb.ne Lof_meta_fail\\ncbnz x1,Lof_meta_fail\\nldr x8,[sp]\\nmov x9,#0xfeed\\ncmp x8,x9\\nb.ne Lof_meta_fail\\nmov x8,#0xfeed\\nstr x8,[sp,#8]\\nmov x0,#338\\nadr x1,Lof_meta_path\\nmov x2,sp\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_meta_fail\\ncbnz x0,Lof_meta_fail\\nldr x8,[sp,#8]\\nmov x9,#0xfeed\\ncmp x8,x9\\nb.eq Lof_meta_fail\\nldr x8,[sp,#144]\\ncmp x8,#0xa5\\nb.ne Lof_meta_fail\\nsubs x20,x20,#1\\nb.ne Lof_meta_loop\\nmov x0,x19\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_meta_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_meta_fail:\\nmov x16,#65534\\nsvc #0x80\\nb .\\nLof_meta_path: .asciz \\\"/process/main\\\"\\nLof_meta_missing: .asciz \\\"/process/missing\\\"\\nLof_meta_root: .asciz \\\"/\\\"\\n.p2align 2\\n"
            "\\n.globl _codeSignConsumerEntry\\n_codeSignConsumerEntry:\\nsub sp,sp,#32\\nmov x16,#20\\nsvc #0x80\\nmov x19,x0\\nmov x20,#20\\nLof_cs_loop:\\nmov w8,#0xffff\\nmovk w8,#0xffff,lsl #16\\nstr w8,[sp]\\nmov w8,#0xa5\\nstr w8,[sp,#4]\\nmov x8,#0xb0000000\\nmsr nzcv,x8\\nmov x0,#0\\nmov x1,#0\\nmov x2,sp\\nmov x3,#4\\nmov x16,#169\\nsvc #0x80\\nb.cs Lof_cs_fail\\nmrs x8,nzcv\\nmov x9,#0x90000000\\ncmp x8,x9\\nb.ne Lof_cs_fail\\ncbnz x0,Lof_cs_fail\\ncbnz x1,Lof_cs_fail\\nldr w8,[sp]\\ncbnz w8,Lof_cs_fail\\nldr w8,[sp,#4]\\ncmp w8,#0xa5\\nb.ne Lof_cs_fail\\nmov w8,#0xffff\\nmovk w8,#0xffff,lsl #16\\nstr w8,[sp]\\nmov x0,#169\\nmov x1,x19\\nmov x2,#0\\nmov x3,sp\\nmov x4,#0\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_cs_fail\\ncbnz x0,Lof_cs_fail\\ncbnz x1,Lof_cs_fail\\nldr w8,[sp]\\ncbnz w8,Lof_cs_fail\\nldr w8,[sp,#4]\\ncmp w8,#0xa5\\nb.ne Lof_cs_fail\\nmov x0,x19\\nmov x1,#0\\nmov x2,sp\\nmov x3,#-1\\nmov x16,#169\\nsvc #0x80\\nb.cs Lof_cs_fail\\nmov x0,#0\\nmov x1,#0\\nmov x2,#0\\nmov x3,#0\\nmov x16,#169\\nsvc #0x80\\nb.cs Lof_cs_fail\\nmov w8,#0xa5\\nstr w8,[sp]\\nadd x0,x19,#1\\nmov x1,#0\\nmov x2,sp\\nmov x3,#4\\nmov x16,#169\\nsvc #0x80\\nb.cc Lof_cs_fail\\ncmp x0,#3\\nb.ne Lof_cs_fail\\nldr w8,[sp]\\ncmp w8,#0xa5\\nb.ne Lof_cs_fail\\nmov x0,#-1\\nmov x1,#0\\nmov x2,#1\\nmov x3,#4\\nmov x16,#169\\nsvc #0x80\\nb.cc Lof_cs_fail\\ncmp x0,#3\\nb.ne Lof_cs_fail\\nmov x0,#0\\nmov x1,#0\\nmov x2,#1\\nmov x3,#4\\nmov x16,#169\\nsvc #0x80\\nb.cc Lof_cs_fail\\ncmp x0,#14\\nb.ne Lof_cs_fail\\nmov x0,#0\\nmov x1,#0\\nadr x2,Lof_cs_ro\\nmov x3,#4\\nmov x16,#169\\nsvc #0x80\\nb.cc Lof_cs_fail\\ncmp x0,#14\\nb.ne Lof_cs_fail\\nsubs x20,x20,#1\\nb.ne Lof_cs_loop\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_cs_fail:\\nmov x16,#65534\\nsvc #0x80\\nb .\\nLof_cs_ro: .long 0\\n.globl _codeSignMutationEntry\\n_codeSignMutationEntry:\\nmov x0,#0\\nmov x1,#1\\nmov x2,#0\\nmov x3,#0\\nmov x16,#169\\nsvc #0x80\\nb .\\n.p2align 2\\n"
            "\\n.globl _identityPathConsumerEntry\\n_identityPathConsumerEntry:\\nsub sp,sp,#32\\nstp xzr,xzr,[sp]\\nmov x20,#20\\nLof_identity_loop:\\nmov w8,#0x1234\\nstr w8,[sp,#16]\\nmov x0,sp\\nmov x1,#1024\\nadd x2,sp,#8\\nmov x3,#1\\nmov x16,#427\\nsvc #0x80\\nb.cc Lof_identity_failure\\ncmp x0,#2\\nb.ne Lof_identity_failure\\nldr w8,[sp,#16]\\nmov w9,#0x1234\\ncmp w8,w9\\nb.ne Lof_identity_failure\\nmov x0,#427\\nmov x1,sp\\nmov x2,#8192\\nadd x3,sp,#8\\nmov x4,#1\\nmov x16,#0\\nsvc #0x80\\nb.cc Lof_identity_failure\\ncmp x0,#2\\nb.ne Lof_identity_failure\\nmov x0,sp\\nmov x1,#8193\\nadd x2,sp,#8\\nmov x3,#1\\nmov x16,#427\\nsvc #0x80\\nb.cc Lof_identity_failure\\ncmp x0,#22\\nb.ne Lof_identity_failure\\nmov x0,sp\\nmov x1,#0\\nmov x2,#1\\nmov x16,#427\\nsvc #0x80\\nb.cc Lof_identity_failure\\ncmp x0,#14\\nb.ne Lof_identity_failure\\nmov x0,sp\\nmov x1,#0\\nadd x2,sp,#8\\nmov x16,#427\\nsvc #0x80\\nb.cc Lof_identity_failure\\ncmp x0,#22\\nb.ne Lof_identity_failure\\nsubs x20,x20,#1\\nb.ne Lof_identity_loop\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_identity_failure:\\nmov x16,#65534\\nsvc #0x80\\nb .\\n.p2align 2\\n"
            ".globl _openAtConsumerEntry\\n_openAtConsumerEntry:\\nsub sp,sp,#32\\nadr x0,Lof_openat_root\\nmov x1,#0x100000\\nmov x2,#0\\nmov x16,#5\\nsvc #0x80\\nb.cs Lof_openat_failure\\nmov x19,x0\\nmov x20,#20\\nLof_openat_loop:\\nmov x0,x19\\nadr x1,Lof_openat_main\\nmov x2,#0\\nmov x3,#0\\nmov x16,#463\\nsvc #0x80\\nb.cs Lof_openat_failure\\nmov x21,x0\\nmov x1,sp\\nmov x2,#4\\nmov x16,#3\\nsvc #0x80\\nb.cs Lof_openat_failure\\ncmp x0,#4\\nb.ne Lof_openat_failure\\nldr w8,[sp]\\nmov w9,#0xfacf\\nmovk w9,#0xfeed,lsl #16\\ncmp w8,w9\\nb.ne Lof_openat_failure\\nmov x0,x21\\nadr x1,Lof_openat_main\\nmov x2,#0\\nmov x3,#0\\nmov x16,#463\\nsvc #0x80\\nb.cc Lof_openat_failure\\ncmp x0,#20\\nb.ne Lof_openat_failure\\nmov x0,x21\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_openat_failure\\nmov x0,#463\\nmov x1,x19\\nadr x2,Lof_openat_main\\nmov x3,#0\\nmov x4,#0\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_openat_failure\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_openat_failure\\nsubs x20,x20,#1\\nb.ne Lof_openat_loop\\nmov x0,#999\\nadr x1,Lof_openat_absolute\\nmov x2,#0\\nmov x3,#0\\nmov x16,#463\\nsvc #0x80\\nb.cs Lof_openat_failure\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_openat_failure\\nmov x0,#-2\\nadr x1,Lof_openat_main\\nmov x2,#0\\nmov x3,#0\\nmov x16,#463\\nsvc #0x80\\nb.cs Lof_openat_failure\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_openat_failure\\nmov x0,#999\\nadr x1,Lof_openat_main\\nmov x2,#0\\nmov x3,#0\\nmov x16,#463\\nsvc #0x80\\nb.cc Lof_openat_failure\\ncmp x0,#9\\nb.ne Lof_openat_failure\\nmov x0,x19\\nadr x1,Lof_openat_missing\\nmov x2,#0\\nmov x3,#0\\nmov x16,#463\\nsvc #0x80\\nb.cc Lof_openat_failure\\ncmp x0,#2\\nb.ne Lof_openat_failure\\nmov x0,x19\\nmov x1,#1\\nmov x2,#0\\nmov x16,#463\\nsvc #0x80\\nb.cc Lof_openat_failure\\ncmp x0,#14\\nb.ne Lof_openat_failure\\nmov x0,x19\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_openat_failure\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_openat_failure:\\nmov x16,#65534\\nsvc #0x80\\nb .\\nLof_openat_root: .asciz \\\"/\\\"\\nLof_openat_main: .asciz \\\"process/main\\\"\\nLof_openat_absolute: .asciz \\\"/process/main\\\"\\nLof_openat_missing: .asciz \\\"empty/missing\\\"\\n.p2align 2\\n"
            ".globl _directoryConsumerEntry\\n_directoryConsumerEntry:\\nsub sp,sp,#32\\nmov x20,#20\\nLof_directory_loop:\\nmov x0,#5\\nadr x1,Lof_directory_root\\nmov x2,#0x21100000\\nmov x3,#0\\nmov x16,#0\\nsvc #0x80\\nb.cs Lof_directory_failure\\nmov x19,x0\\nmov x1,#1\\nmov x2,#0\\nmov x16,#92\\nsvc #0x80\\nb.cs Lof_directory_failure\\ncmp x0,#1\\nb.ne Lof_directory_failure\\nmov x0,x19\\nmov x1,#3\\nmov x16,#92\\nsvc #0x80\\nb.cs Lof_directory_failure\\ncbnz x0,Lof_directory_failure\\nmov x0,x19\\nmov x1,#50\\nmov x2,sp\\nmov x16,#92\\nsvc #0x80\\nb.cs Lof_directory_failure\\nldrb w8,[sp]\\ncmp w8,#47\\nb.ne Lof_directory_failure\\nldrb w8,[sp,#1]\\ncbnz w8,Lof_directory_failure\\nmov x0,x19\\nmov x1,sp\\nmov x2,#1\\nmov x16,#3\\nsvc #0x80\\nb.cc Lof_directory_failure\\ncmp x0,#21\\nb.ne Lof_directory_failure\\nldrb w8,[sp]\\ncmp w8,#47\\nb.ne Lof_directory_failure\\nmov x0,x19\\nmov x16,#6\\nsvc #0x80\\nb.cs Lof_directory_failure\\nsubs x20,x20,#1\\nb.ne Lof_directory_loop\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_directory_failure:\\nmov x16,#65534\\nsvc #0x80\\nb .\\nLof_directory_root: .asciz \\\"/\\\"\\n.p2align 2\\n"
            ".globl _debuggerCapabilityEntry\\n_debuggerCapabilityEntry:\\nmov x19,#20\\nmov x20,#0xfffff0000\\nmovk x20,#0x4084\\nmov x21,#0xfffff0000\\nmovk x21,#0xc084\\nLof_debugger_loop:\\nldr w8,[x20]\\ncbnz w8,Lof_debugger_failure\\nldr w8,[x21]\\ncbnz w8,Lof_debugger_failure\\nldrh w8,[x20,#2]\\ncbnz w8,Lof_debugger_failure\\nldrb w8,[x20,#3]\\ncbnz w8,Lof_debugger_failure\\nsubs x19,x19,#1\\nb.ne Lof_debugger_loop\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_debugger_failure:\\nmov x16,#65534\\nsvc #0x80\\nb .\\n.globl _DebuggerCrossROEntry\\n_DebuggerCrossROEntry:\\nmov x20,#0xfffff0000\\nmovk x20,#16516\\nmov w8,#1\\nldr x8,[x20]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n.globl _DebuggerCrossLegacyEntry\\n_DebuggerCrossLegacyEntry:\\nmov x20,#0xfffff0000\\nmovk x20,#49284\\nmov w8,#1\\nldr x8,[x20]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n.globl _DebuggerAdjacentEntry\\n_DebuggerAdjacentEntry:\\nmov x20,#0xfffff0000\\nmovk x20,#16520\\nmov w8,#1\\nldr w8,[x20]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n.globl _DebuggerWriteROEntry\\n_DebuggerWriteROEntry:\\nmov x20,#0xfffff0000\\nmovk x20,#16516\\nmov w8,#1\\nstr w8,[x20]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n.globl _DebuggerWriteLegacyEntry\\n_DebuggerWriteLegacyEntry:\\nmov x20,#0xfffff0000\\nmovk x20,#49284\\nmov w8,#1\\nstr w8,[x20]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n"
            ".globl _fatalObservationEntry\\n_fatalObservationEntry:\\nmov x0,#35\\nmov x1,#0\\nadr x2,Lof_fatal_reason\\nmov x3,#0\\nbl _abort_with_reason\\nb .\\n.globl _fatalPayloadEntry\\n_fatalPayloadEntry:\\nmov x0,#35\\nmov x1,#1\\nmov x2,#0\\nmov x3,#0\\nadr x4,Lof_fatal_reason\\nmov x5,#0\\nbl _abort_with_payload\\nb .\\n.globl _fatalBadPointerEntry\\n_fatalBadPointerEntry:\\nmov x0,#35\\nmov x1,#0\\nmov x2,#1\\nmov x3,#0\\nbl _abort_with_reason\\nb .\\n.globl _abort_with_reason\\n_abort_with_reason:\\nmov x16,#65535\\nsvc #0x80\\nb .\\n.globl _abort_with_payload\\n_abort_with_payload:\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_fatal_reason: .asciz \\\"Owned fatal reason observation\\\"\\n.p2align 2\\n"
            "\\n.globl _fileConsumerEntry\\n_fileConsumerEntry:\\nsub sp,sp,#32\\nadr x0,95f\\nmov x1,#0\\nmov x2,#0\\nmov x16,#5\\nsvc #0x80\\nb.cs 96f\\nmov x19,x0\\nmov x1,#50\\nmov x2,sp\\nmov x16,#92\\nsvc #0x80\\nb.cs 96f\\ncbnz x0,96f\\nldrb w0,[sp]\\ncmp w0,#47\\nb.ne 96f\\nmov x0,x19\\nmov x1,sp\\nmov x2,#4\\nmov x16,#3\\nsvc #0x80\\nb.cs 96f\\ncmp x0,#4\\nb.ne 96f\\nldr w0,[sp]\\nmov w9,#0xfacf\\nmovk w9,#0xfeed,lsl #16\\ncmp w0,w9\\nb.ne 96f\\nmov x0,x19\\nmov x1,sp\\nmov x2,#4\\nmov x3,#0\\nmov x16,#153\\nsvc #0x80\\nb.cs 96f\\ncmp x0,#4\\nb.ne 96f\\nmov x0,x19\\nmov x1,#0\\nmov x2,#1\\nmov x16,#199\\nsvc #0x80\\nb.cs 96f\\ncmp x0,#4\\nb.ne 96f\\nmov x0,x19\\nmov x1,#0\\nmov x2,#2\\nmov x16,#199\\nsvc #0x80\\nb.cs 96f\\nmov x0,x19\\nmov x1,#1\\nmov x2,#4\\nmov x16,#3\\nsvc #0x80\\nb.cs 96f\\ncbnz x0,96f\\nmov x0,x19\\nmov x16,#6\\nsvc #0x80\\nb.cs 96f\\ncbnz x0,96f\\nmov x0,x19\\nmov x1,sp\\nmov x2,#1\\nmov x16,#3\\nsvc #0x80\\nb.cc 96f\\ncmp x0,#9\\nb.ne 96f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n96: mov x16,#21\\nsvc #0x80\\nb .\\n95: .asciz \\\"/process/main\\\"\\n.p2align 2\\n"
            "\");\n#endif\n");
        std::string calendar_assembly=".text\\n.p2align 2\\n.globl _calendarConsumerEntry\\n_calendarConsumerEntry:\\nsub sp,sp,#64\\nmov x19,#0\\nmov x22,#0x1234\\n";
        const std::array<std::array<int,3>,7> calendar_arguments{{{2,0,2},{2,0,2},{1,0,2},{0,0,0},{2,1,2},{2,0,1},{0,0,2}}};
        for(unsigned n=0;n<calendar_arguments.size();++n){
            const bool indirect=n==1;const int expected=n==2||n==5?14:n==4?45:0;
            calendar_assembly+="stp x22,x22,[sp]\\nstr x22,[sp,#16]\\nstr x22,[sp,#32]\\nstr x22,[sp,#40]\\nmov x10,#0xe0000000\\nmsr nzcv,x10\\n";
            for(unsigned a=0;a<3;++a){const auto reg=std::to_string(a+(indirect?1:0));const auto input=calendar_arguments[n][a];
                calendar_assembly+=input==2?(a==2?"add x"+reg+",sp,#32\\n":"mov x"+reg+",sp\\n"):"mov x"+reg+",#"+std::to_string(input)+"\\n";}
            calendar_assembly+=indirect?"mov x0,#116\\nmov x16,#0\\n":"mov x16,#116\\n";
            calendar_assembly+="svc #0x80\\nmrs x11,nzcv\\nmov x12,#"+std::to_string(expected?0xe0000000ULL:0xc0000000ULL)+"\\ncmp x11,x12\\nb.ne 8f\\ncmp x0,#"+std::to_string(expected)+"\\nb.ne 8f\\ncbnz x1,8f\\nldr x10,[sp,#16]\\ncmp x10,x22\\nb.ne 8f\\nldr x10,[sp,#40]\\ncmp x10,x22\\nb.ne 8f\\n";
            if(calendar_arguments[n][0]==2)calendar_assembly+="ldr x10,[sp]\\ncbz x10,8f\\nldr w10,[sp,#12]\\ncbnz w10,8f\\nldr w10,[sp,#8]\\nmov w11,#0x4240\\nmovk w11,#0xf,lsl #16\\ncmp x10,x11\\nb.hs 8f\\n";
            if(!expected&&calendar_arguments[n][2]==2)calendar_assembly+="ldr x10,[sp,#32]\\ncmp x10,x22\\nb.eq 8f\\n";
            else calendar_assembly+="ldr x10,[sp,#32]\\ncmp x10,x22\\nb.ne 8f\\n";
            calendar_assembly+="add x19,x19,#1\\n";
        }
        calendar_assembly+="mov x0,x19\\nmov x16,#65535\\nsvc #0x80\\nb .\\n8: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _calendarSnapshotEntry\\n_calendarSnapshotEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nldr x0,[x2,#0x120]\\nldr x3,[x2,#0x128]\\nldr x4,[x2,#0x130]\\nldr x5,[x2,#0x138]\\nldr x6,[x2,#0x140]\\nldr x7,[x2,#0x120]\\norr x0,x0,x3\\norr x0,x0,x4\\norr x0,x0,x5\\norr x0,x0,x6\\norr x0,x0,x7\\nmov x16,#65535\\nsvc #0x80\\nb .\\n.globl _calendarCrossEntry\\n_calendarCrossEntry:\\nmov x2,#0xc000\\nmovk x2,#0xffff,lsl #16\\nmovk x2,#0xf,lsl #32\\nadd x2,x2,#0x120\\nldur x0,[x2,#4]\\nb .\\n";
        calendar_assembly+=".globl _entropyConsumerEntry\\n_entropyConsumerEntry:\\nsub sp,sp,#544\\nmov x22,#0x1234\\nstr x22,[sp,#512]\\nstr x22,[sp,#520]\\nmov x19,#0\\n";
        const std::array<std::uint64_t,9> entropy_sizes{256,256,0,257,0x100000000ULL,32,16,32,1};
        for(unsigned n=0;n<entropy_sizes.size();++n){
            const int expected=n==3||n==4?22:n==5||n==6||n==7?14:0;
            calendar_assembly+="mov x10,#0xe0000000\\nmsr nzcv,x10\\n";
            const auto address=n==0?"mov x0,sp\\n":n==1?"add x0,sp,#256\\n":n==5?"mov x0,#1\\n":n==6?"mov x0,#-8\\n":n==7?"adr x0,_entropyConsumerEntry\\n":n==2?"mov x0,#0\\n":"mov x0,sp\\n";
            calendar_assembly+=address;
            calendar_assembly+="mov x1,#"+std::to_string(entropy_sizes[n])+"\\n";
            calendar_assembly+=n==1?"mov x2,x1\\nmov x1,x0\\nmov x0,#500\\nmov x16,#0\\n":"mov x16,#500\\n";
            calendar_assembly+="svc #0x80\\nmrs x11,nzcv\\nmov x12,#"+std::to_string(expected?0xe0000000ULL:0xc0000000ULL)+"\\ncmp x11,x12\\nb.ne 7f\\ncmp x0,#"+std::to_string(expected)+"\\nb.ne 7f\\ncbnz x1,7f\\nldr x10,[sp,#512]\\ncmp x10,x22\\nb.ne 7f\\nldr x10,[sp,#520]\\ncmp x10,x22\\nb.ne 7f\\nadd x19,x19,#1\\n";
            if(n==1)calendar_assembly+="mov x3,#0\\nmov x4,#0\\n6: add x5,sp,x3\\nldr x6,[x5]\\nldr x7,[x5,#256]\\neor x6,x6,x7\\norr x4,x4,x6\\nadd x3,x3,#8\\ncmp x3,#256\\nb.lo 6b\\ncbz x4,7f\\n";
        }
        calendar_assembly+="mov x0,x19\\nmov x16,#65535\\nsvc #0x80\\nb .\\n7: mov x16,#21\\nsvc #0x80\\nb .\\n";
        calendar_assembly+=".globl _machNameOwnerEntry\\n_machNameOwnerEntry:\\nsub sp,sp,#32\\nstr wzr,[sp]\\nmov x16,#-27\\nsvc #0x80\\nmov w19,w0\\nand w8,w19,#3\\ncmp w8,#3\\nb.ne 5f\\nlsr w8,w19,#8\\ncbz w8,5f\\nmov w8,#0\\nmov w3,w19\\nmov x2,sp\\ncasal w8,w3,[x2]\\ncbnz w8,5f\\nldr w0,[sp]\\norr w9,w0,#1\\ncmp w9,w19\\nb.ne 5f\\nstr wzr,[sp]\\nmov x16,#-28\\nsvc #0x80\\nand w8,w0,#3\\ncmp w8,#3\\nb.ne 5f\\nmov x16,#-29\\nsvc #0x80\\nand w8,w0,#3\\ncmp w8,#3\\nb.ne 5f\\nmov x16,#-26\\nsvc #0x80\\nand w8,w0,#3\\ncmp w8,#3\\nb.ne 5f\\nmov x0,x19\\nmov x16,#65535\\nsvc #0x80\\nb .\\n5: mov x16,#21\\nsvc #0x80\\nb .\\n";
        calendar_assembly+=".globl _vmTaggedNoneEntry\\n_vmTaggedNoneEntry:\\nsub sp,sp,#128\\nstp xzr,xzr,[sp]\\nstp xzr,xzr,[sp,#16]\\nstp xzr,xzr,[sp,#32]\\nstp xzr,xzr,[sp,#48]\\nstp xzr,xzr,[sp,#64]\\nstp xzr,xzr,[sp,#80]\\nstp xzr,xzr,[sp,#96]\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nstr w0,[sp,#8]\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nstr w0,[sp,#12]\\nmov w0,#0x1513\\nmovk w0,#0x8000,lsl #16\\nstr w0,[sp]\\nmov w0,#100\\nstr w0,[sp,#4]\\nmov w0,#4811\\nstr w0,[sp,#20]\\nmov w0,#1\\nstr w0,[sp,#24]\\nstr w0,[sp,#44]\\nmov w9,#1\\nmovk w9,#0x100,lsl #16\\nstr w9,[sp,#72]\\nstr w0,[sp,#96]\\nmov w0,#19\\nstrb w0,[sp,#38]\\nmov x0,#0x4000\\nstr x0,[sp,#56]\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\nldr w2,[sp]\\nmov x9,#100\\norr x2,x2,x9,lsl #32\\norr x3,x19,x20,lsl #32\\nmov x4,#4811\\nlsl x4,x4,#32\\nmov x5,#1\\norr x5,x5,x20,lsl #32\\nmov x6,#52\\nmov x7,#0\\nmov x16,#-47\\nsvc #0x80\\ncbnz x0,92f\\nldr w0,[sp,#32]\\ncbnz x0,92f\\nldr x21,[sp,#36]\\nmov x0,x19\\nmov x1,x21\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#1\\nmov x16,#-14\\nsvc #0x80\\ncmp x0,#2\\nb.ne 92f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n92: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _vmTaggedSlicesEntry\\n_vmTaggedSlicesEntry:\\nsub sp,sp,#128\\nstp xzr,xzr,[sp]\\nstp xzr,xzr,[sp,#16]\\nstp xzr,xzr,[sp,#32]\\nstp xzr,xzr,[sp,#48]\\nstp xzr,xzr,[sp,#64]\\nstp xzr,xzr,[sp,#80]\\nstp xzr,xzr,[sp,#96]\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nstr w0,[sp,#8]\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nstr w0,[sp,#12]\\nmov w0,#0x1513\\nmovk w0,#0x8000,lsl #16\\nstr w0,[sp]\\nmov w0,#100\\nstr w0,[sp,#4]\\nmov w0,#4811\\nstr w0,[sp,#20]\\nmov w0,#1\\nstr w0,[sp,#24]\\nstr w0,[sp,#44]\\nmov w9,#1\\nmovk w9,#0x100,lsl #16\\nstr w9,[sp,#72]\\nstr w0,[sp,#96]\\nmov w0,#19\\nstrb w0,[sp,#38]\\nmov w9,#3\\nstr w9,[sp,#88]\\nstr w9,[sp,#92]\\nmov x0,#0xc000\\nstr x0,[sp,#56]\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\nldr w2,[sp]\\nmov x9,#100\\norr x2,x2,x9,lsl #32\\norr x3,x19,x20,lsl #32\\nmov x4,#4811\\nlsl x4,x4,#32\\nmov x5,#1\\norr x5,x5,x20,lsl #32\\nmov x6,#52\\nmov x7,#0\\nmov x16,#-47\\nsvc #0x80\\ncbnz x0,92f\\nldr w0,[sp,#32]\\ncbnz x0,92f\\nldr x21,[sp,#36]\\nmov x22,#0x1234\\nstr x22,[x21]\\nadd x23,x21,#8,lsl #12\\nstr x22,[x23]\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x3,#1\\nmov x4,#1\\nmov x16,#-14\\nsvc #0x80\\ncbnz x0,92f\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#2\\nmov x16,#-14\\nsvc #0x80\\ncmp x0,#2\\nb.ne 92f\\nadd x0,x21,#4,lsl #12\\nmov x1,#0x4000\\nmov x2,#2\\nmov x16,#74\\nsvc #0x80\\nb.cc 92f\\ncmp x0,#13\\nb.ne 92f\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x16,#-12\\nsvc #0x80\\ncbnz x0,92f\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#1\\nmov x16,#-14\\nsvc #0x80\\ncmp x0,#1\\nb.ne 92f\\nldr x9,[x21]\\ncmp x9,x22\\nb.ne 92f\\nldr x9,[x23]\\ncmp x9,x22\\nb.ne 92f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n92: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _vmTaggedReleaseEntry\\n_vmTaggedReleaseEntry:\\nsub sp,sp,#128\\nstp xzr,xzr,[sp]\\nstp xzr,xzr,[sp,#16]\\nstp xzr,xzr,[sp,#32]\\nstp xzr,xzr,[sp,#48]\\nstp xzr,xzr,[sp,#64]\\nstp xzr,xzr,[sp,#80]\\nstp xzr,xzr,[sp,#96]\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nstr w0,[sp,#8]\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nstr w0,[sp,#12]\\nmov w0,#0x1513\\nmovk w0,#0x8000,lsl #16\\nstr w0,[sp]\\nmov w0,#100\\nstr w0,[sp,#4]\\nmov w0,#4811\\nstr w0,[sp,#20]\\nmov w0,#1\\nstr w0,[sp,#24]\\nstr w0,[sp,#44]\\nmov w9,#1\\nmovk w9,#0x100,lsl #16\\nstr w9,[sp,#72]\\nstr w0,[sp,#96]\\nmov w0,#19\\nstrb w0,[sp,#38]\\nmov w9,#3\\nstr w9,[sp,#88]\\nstr w9,[sp,#92]\\nmov x0,#0xc000\\nstr x0,[sp,#56]\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\nldr w2,[sp]\\nmov x9,#100\\norr x2,x2,x9,lsl #32\\norr x3,x19,x20,lsl #32\\nmov x4,#4811\\nlsl x4,x4,#32\\nmov x5,#1\\norr x5,x5,x20,lsl #32\\nmov x6,#52\\nmov x7,#0\\nmov x16,#-47\\nsvc #0x80\\ncbnz x0,92f\\nldr w0,[sp,#32]\\ncbnz x0,92f\\nldr x21,[sp,#36]\\nmov x22,#0x1234\\nstr x22,[x21]\\nadd x23,x21,#8,lsl #12\\nstr x22,[x23]\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x3,#1\\nmov x4,#1\\nmov x16,#-14\\nsvc #0x80\\ncbnz x0,92f\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#2\\nmov x16,#-14\\nsvc #0x80\\ncmp x0,#2\\nb.ne 92f\\nadd x0,x21,#4,lsl #12\\nmov x1,#0x4000\\nmov x2,#2\\nmov x16,#74\\nsvc #0x80\\nb.cc 92f\\ncmp x0,#13\\nb.ne 92f\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x16,#-12\\nsvc #0x80\\ncbnz x0,92f\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#1\\nmov x16,#-14\\nsvc #0x80\\ncmp x0,#1\\nb.ne 92f\\nldr x9,[x21]\\ncmp x9,x22\\nb.ne 92f\\nldr x9,[x23]\\ncmp x9,x22\\nb.ne 92f\\nmov x0,x19\\nmov x1,x21\\nmov x2,#0x4000\\nmov x16,#-12\\nsvc #0x80\\ncbnz x0,92f\\nmov x0,x19\\nmov x1,x23\\nmov x2,#0x4000\\nmov x16,#-12\\nsvc #0x80\\ncbnz x0,92f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n92: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _vmTaggedHoleEntry\\n_vmTaggedHoleEntry:\\nsub sp,sp,#128\\nstp xzr,xzr,[sp]\\nstp xzr,xzr,[sp,#16]\\nstp xzr,xzr,[sp,#32]\\nstp xzr,xzr,[sp,#48]\\nstp xzr,xzr,[sp,#64]\\nstp xzr,xzr,[sp,#80]\\nstp xzr,xzr,[sp,#96]\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nstr w0,[sp,#8]\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nstr w0,[sp,#12]\\nmov w0,#0x1513\\nmovk w0,#0x8000,lsl #16\\nstr w0,[sp]\\nmov w0,#100\\nstr w0,[sp,#4]\\nmov w0,#4811\\nstr w0,[sp,#20]\\nmov w0,#1\\nstr w0,[sp,#24]\\nstr w0,[sp,#44]\\nmov w9,#1\\nmovk w9,#0x100,lsl #16\\nstr w9,[sp,#72]\\nstr w0,[sp,#96]\\nmov w0,#19\\nstrb w0,[sp,#38]\\nmov w9,#3\\nstr w9,[sp,#88]\\nstr w9,[sp,#92]\\nmov x0,#0xc000\\nstr x0,[sp,#56]\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\nldr w2,[sp]\\nmov x9,#100\\norr x2,x2,x9,lsl #32\\norr x3,x19,x20,lsl #32\\nmov x4,#4811\\nlsl x4,x4,#32\\nmov x5,#1\\norr x5,x5,x20,lsl #32\\nmov x6,#52\\nmov x7,#0\\nmov x16,#-47\\nsvc #0x80\\ncbnz x0,92f\\nldr w0,[sp,#32]\\ncbnz x0,92f\\nldr x21,[sp,#36]\\nmov x22,#0x1234\\nstr x22,[x21]\\nadd x23,x21,#8,lsl #12\\nstr x22,[x23]\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x3,#1\\nmov x4,#1\\nmov x16,#-14\\nsvc #0x80\\ncbnz x0,92f\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#2\\nmov x16,#-14\\nsvc #0x80\\ncmp x0,#2\\nb.ne 92f\\nadd x0,x21,#4,lsl #12\\nmov x1,#0x4000\\nmov x2,#2\\nmov x16,#74\\nsvc #0x80\\nb.cc 92f\\ncmp x0,#13\\nb.ne 92f\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x16,#-12\\nsvc #0x80\\ncbnz x0,92f\\nmov x0,x19\\nadd x1,x21,#4,lsl #12\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#1\\nmov x16,#-14\\nsvc #0x80\\ncmp x0,#1\\nb.ne 92f\\nldr x9,[x21]\\ncmp x9,x22\\nb.ne 92f\\nldr x9,[x23]\\ncmp x9,x22\\nb.ne 92f\\nadd x9,x21,#4,lsl #12\\nldr x0,[x9]\\nmov x16,#65535\\nsvc #0x80\\nb .\\n92: mov x16,#21\\nsvc #0x80\\nb .\\n";
        calendar_assembly+=".globl _vmOverwriteEntry\\n_vmOverwriteEntry:\\nsub sp,sp,#128\\nstp xzr,xzr,[sp]\\nstp xzr,xzr,[sp,#16]\\nstp xzr,xzr,[sp,#32]\\nstp xzr,xzr,[sp,#48]\\nstp xzr,xzr,[sp,#64]\\nstp xzr,xzr,[sp,#80]\\nstp xzr,xzr,[sp,#96]\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nstr w0,[sp,#8]\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nstr w0,[sp,#12]\\nmov w0,#0x1513\\nmovk w0,#0x8000,lsl #16\\nstr w0,[sp]\\nmov w0,#100\\nstr w0,[sp,#4]\\nmov w0,#4811\\nstr w0,[sp,#20]\\nmov w0,#1\\nstr w0,[sp,#24]\\nstr w0,[sp,#44]\\nmov w9,#1\\nmovk w9,#0x100,lsl #16\\nstr w9,[sp,#72]\\nstr w0,[sp,#96]\\nmov w0,#19\\nstrb w0,[sp,#38]\\nmov w9,#3\\nstr w9,[sp,#88]\\nstr w9,[sp,#92]\\nmov x0,#0xc000\\nstr x0,[sp,#56]\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\nldr w2,[sp]\\nmov x9,#100\\norr x2,x2,x9,lsl #32\\norr x3,x19,x20,lsl #32\\nmov x4,#4811\\nlsl x4,x4,#32\\nmov x5,#1\\norr x5,x5,x20,lsl #32\\nmov x6,#52\\nmov x7,#0\\nmov x16,#-47\\nsvc #0x80\\ncbnz x0,92f\\nldr w0,[sp,#32]\\ncbnz x0,92f\\nldr x21,[sp,#36]\\nmov x22,#0x1234\\nstr x22,[x21]\\nadd x23,x21,#8,lsl #12\\nstr x22,[x23]\\nadd x24,x21,#4,lsl #12\\nstr x22,[x24]\\nstr x24,[sp]\\nmov x0,x19\\nmov x1,sp\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#0x7000000\\nmov x5,#3\\nmov x16,#-15\\nsvc #0x80\\ncmp x0,#3\\nb.ne 92f\\nldr x9,[x24]\\ncmp x9,x22\\nb.ne 92f\\nmov x0,x19\\nmov x1,sp\\nmov x2,#0x4000\\nmov x3,#0\\nmov x4,#0x4000\\nmovk x4,#0x700,lsl #16\\nmov x5,#3\\nmov x16,#-15\\nsvc #0x80\\ncbnz x0,92f\\nldr x9,[sp]\\ncmp x9,x24\\nb.ne 92f\\nldr x9,[x24]\\ncbnz x9,92f\\nldr x9,[x21]\\ncmp x9,x22\\nb.ne 92f\\nldr x9,[x23]\\ncmp x9,x22\\nb.ne 92f\\nstr x22,[x24]\\nldr x9,[x24]\\ncmp x9,x22\\nb.ne 92f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n92: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _vmFixedFileEntry\\n_vmFixedFileEntry:\\nsub sp,sp,#128\\nstp xzr,xzr,[sp]\\nstp xzr,xzr,[sp,#16]\\nstp xzr,xzr,[sp,#32]\\nstp xzr,xzr,[sp,#48]\\nstp xzr,xzr,[sp,#64]\\nstp xzr,xzr,[sp,#80]\\nstp xzr,xzr,[sp,#96]\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nstr w0,[sp,#8]\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nstr w0,[sp,#12]\\nmov w0,#0x1513\\nmovk w0,#0x8000,lsl #16\\nstr w0,[sp]\\nmov w0,#100\\nstr w0,[sp,#4]\\nmov w0,#4811\\nstr w0,[sp,#20]\\nmov w0,#1\\nstr w0,[sp,#24]\\nstr w0,[sp,#44]\\nmov w9,#1\\nmovk w9,#0x100,lsl #16\\nstr w9,[sp,#72]\\nstr w0,[sp,#96]\\nmov w0,#19\\nstrb w0,[sp,#38]\\nmov w9,#3\\nstr w9,[sp,#88]\\nstr w9,[sp,#92]\\nmov x0,#0xc000\\nstr x0,[sp,#56]\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\nldr w2,[sp]\\nmov x9,#100\\norr x2,x2,x9,lsl #32\\norr x3,x19,x20,lsl #32\\nmov x4,#4811\\nlsl x4,x4,#32\\nmov x5,#1\\norr x5,x5,x20,lsl #32\\nmov x6,#52\\nmov x7,#0\\nmov x16,#-47\\nsvc #0x80\\ncbnz x0,92f\\nldr w0,[sp,#32]\\ncbnz x0,92f\\nldr x21,[sp,#36]\\nmov x22,#0x1234\\nstr x22,[x21]\\nadd x23,x21,#8,lsl #12\\nstr x22,[x23]\\nadd x24,x21,#4,lsl #12\\nstr x22,[x24]\\nadr x0,Lof_mmap_path\\nmov x1,#0\\nmov x16,#5\\nsvc #0x80\\nb.cs 92f\\nmov x25,x0\\nmov x0,x25\\nadd x1,sp,#112\\nmov x2,#8\\nmov x16,#3\\nsvc #0x80\\nb.cs 92f\\ncmp x0,#8\\nb.ne 92f\\nldr x26,[sp,#112]\\nmov x0,x24\\nmov x1,#0x4000\\nmov x2,#1\\nmov x3,#0x12\\nmovk x3,#4,lsl #16\\nmov x4,x25\\nmov x5,#0\\nmov x16,#197\\nsvc #0x80\\nb.cs 92f\\ncmp x0,x24\\nb.ne 92f\\nldr x9,[x24]\\ncmp x9,x26\\nb.ne 92f\\nldr x9,[x21]\\ncmp x9,x22\\nb.ne 92f\\nldr x9,[x23]\\ncmp x9,x22\\nb.ne 92f\\nmov x0,x25\\nmov x16,#6\\nsvc #0x80\\nb.cs 92f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n92: mov x16,#21\\nsvc #0x80\\nb .\\n";
        calendar_assembly+=".text\\n.p2align 2\\n.globl _timebaseConsumerEntry\\n_timebaseConsumerEntry:\\nsub sp,sp,#32\\nmov x22,#0x1234\\nstr x22,[sp]\\nstr x22,[sp,#8]\\nstr x22,[sp,#16]\\nmov x16,#-3\\nsvc #0x80\\nmov x19,x0\\nadd x0,sp,#8\\nmov x1,#0x9876\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#-89\\nsvc #0x80\\ncbnz x0,4f\\nmrs x8,nzcv\\nmov x9,#0xe0000000\\ncmp x8,x9\\nb.ne 4f\\nmov x9,#0x9876\\ncmp x1,x9\\nb.ne 4f\\nldr w20,[sp,#8]\\nldr w21,[sp,#12]\\ncmp w20,#100\\nb.ne 4f\\ncmp w21,#1\\nb.ne 4f\\nldr x8,[sp]\\ncmp x8,x22\\nb.ne 4f\\nldr x8,[sp,#16]\\ncmp x8,x22\\nb.ne 4f\\nmov x16,#-3\\nsvc #0x80\\ncmp x0,x19\\nb.lo 4f\\nsub x0,x0,x19\\nmul x0,x0,x20\\nudiv x0,x0,x21\\nmov x16,#65535\\nsvc #0x80\\nb .\\n4: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _timebaseInvalidEntry\\n_timebaseInvalidEntry:\\nsub sp,sp,#32\\nmov x22,#0x1234\\nstr x22,[sp]\\nmov x0,#0\\nmov x16,#-89\\nsvc #0x80\\ncbnz x0,4f\\nadr x0,Lof_timebase_readonly\\nmov x16,#-89\\nsvc #0x80\\ncbnz x0,4f\\nmov x0,#-4\\nmov x16,#-89\\nsvc #0x80\\ncbnz x0,4f\\nldr x8,[sp]\\ncmp x8,x22\\nb.ne 4f\\nadr x8,Lof_timebase_readonly\\nldr x8,[x8]\\nmov x9,#0x5678\\ncmp x8,x9\\nb.ne 4f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n4: mov x16,#21\\nsvc #0x80\\nb .\\n.p2align 3\\nLof_timebase_readonly: .quad 0x5678\\n";
        calendar_assembly+="\\n.text\\n.p2align 2\\n.globl _codesignQueriesEntry\\n_codesignQueriesEntry:\\nsub sp,sp,#32\\nmov x20,#0x5a\\nstp x20,x20,[sp]\\nstp x20,x20,[sp,#16]\\nmov x0,#0\\nmov x1,#6\\nmov x2,sp\\nmov x3,#0\\nmov x16,#169\\nsvc #0x80\\nb.cs 91f\\ncbnz x0,91f\\nldr x8,[sp]\\ncbnz x8,91f\\nldr x8,[sp,#8]\\ncmp x8,x20\\nb.ne 91f\\nmov x0,#0\\nmov x1,#5\\nmov x2,sp\\nmov x3,#19\\nmov x16,#169\\nsvc #0x80\\nb.cc 91f\\ncmp x0,#22\\nb.ne 91f\\nmov x0,#0\\nmov x1,#5\\nmov x2,sp\\nmov x3,#20\\nmov x16,#169\\nsvc #0x80\\nb.cc 91f\\ncmp x0,#80\\nb.ne 91f\\nmov x0,#0\\nmov x1,#11\\nmov x2,sp\\nmov x3,#8\\nmov x16,#169\\nsvc #0x80\\nb.cc 91f\\ncmp x0,#22\\nb.ne 91f\\nmov x0,#0\\nmov x1,#16\\nmov x2,sp\\nmov x3,#20\\nmov x16,#169\\nsvc #0x80\\nb.cc 91f\\ncmp x0,#22\\nb.ne 91f\\nldr x8,[sp,#8]\\ncmp x8,x20\\nb.ne 91f\\nmov x0,#0\\nmov x1,#6\\nmov x2,#1\\nmov x16,#169\\nsvc #0x80\\nb.cc 91f\\ncmp x0,#14\\nb.ne 91f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n91: mov x16,#21\\nsvc #0x80\\nb .\\n.globl _unsupportedWaitEntry\\n_unsupportedWaitEntry:\\nmov x0,#0\\nmov x1,#1\\nmov x2,#0\\nmov x3,#0\\nmov x16,#515\\nsvc #0x80\\nmov x16,#65535\\nsvc #0x80\\nb .\\n.globl _pacFailureEntry\\n_pacFailureEntry:\\nmov x0,#0x1234\\nmovk x0,#0x8000,lsl #48\\nmov x16,#0x4321\\nmovk x16,#0x8000,lsl #48\\nbrk #0xc470\\nmov x16,#65535\\nsvc #0x80\\nb .\\n";
        calendar_assembly+="\\n.text\\n.p2align 2\\n.globl _credentialQueriesEntry\\n_credentialQueriesEntry:\\nsub sp,sp,#256\\nmov x16,#24\\nsvc #0x80\\nb.cs 91f\\nmov x19,x0\\nmov x16,#25\\nsvc #0x80\\nb.cs 91f\\ncmp x0,x19\\nb.ne 91f\\ncbz x0,91f\\nmov x16,#47\\nsvc #0x80\\nb.cs 91f\\nmov x20,x0\\nmov x16,#43\\nsvc #0x80\\nb.cs 91f\\ncmp x0,x20\\nb.ne 91f\\nmov x0,#0\\nmov x1,#1\\nmov x16,#79\\nsvc #0x80\\nb.cs 91f\\ncbz x0,91f\\ncmp x0,#48\\nb.hi 91f\\nmov x21,x0\\nmov x8,#0x5a\\nstr x8,[sp,#192]\\nmov x0,#48\\nmov x1,sp\\nmov x16,#79\\nsvc #0x80\\nb.cs 91f\\ncmp x0,x21\\nb.ne 91f\\nldr w8,[sp]\\ncmp x8,x20\\nb.ne 91f\\nldr x8,[sp,#192]\\ncmp x8,#0x5a\\nb.ne 91f\\nmov x0,#-1\\nmov x1,sp\\nmov x16,#79\\nsvc #0x80\\nb.cc 91f\\ncmp x0,#22\\nb.ne 91f\\nmov x0,#79\\nmov x1,#48\\nmov x2,#1\\nmov x16,#0\\nsvc #0x80\\nb.cc 91f\\ncmp x0,#14\\nb.ne 91f\\nmov x16,#327\\nsvc #0x80\\nb.cs 91f\\ncbnz x0,91f\\nmov x16,#65535\\nsvc #0x80\\nb .\\n91: mov x16,#21\\nsvc #0x80\\nb .\\n";
        calendar_assembly+="\\n.text\\n.p2align 2\\n.globl _restartableConsumerEntry\\n_restartableConsumerEntry:\\nsub sp,sp,#2048\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nmov x8,#0x5a\\nstr x8,[sp,#1024]\\nmov x22,#8001\\nmov x23,#0\\nmov x24,#24\\nbl Lrr_send\\nldr w0,[sp,#32]\\ncmp w0,#0\\nb.ne Lrr_fail\\nmov x22,#8000\\nmov x24,#36\\nbl Lrr_send\\nldr w0,[sp,#32]\\ncmp w0,#4\\nb.ne Lrr_fail\\nmov x8,#0x1000\\nstr x8,[sp,#36]\\nmov w8,#16\\nstrh w8,[sp,#44]\\nstrh w8,[sp,#46]\\nmov w8,#1\\nstr w8,[sp,#48]\\nmov x23,#1\\nmov x24,#52\\nbl Lrr_send\\nldr w0,[sp,#32]\\ncmp w0,#4\\nb.ne Lrr_fail\\nstr wzr,[sp,#48]\\nmov w8,#4097\\nstrh w8,[sp,#44]\\nbl Lrr_send\\nldr w0,[sp,#32]\\ncmp w0,#4\\nb.ne Lrr_fail\\nmov w8,#16\\nstrh w8,[sp,#44]\\nmov w8,#4097\\nstrh w8,[sp,#46]\\nbl Lrr_send\\nldr w0,[sp,#32]\\ncmp w0,#4\\nb.ne Lrr_fail\\nmov w8,#16\\nstrh w8,[sp,#46]\\nmov x8,#-8\\nstr x8,[sp,#36]\\nbl Lrr_send\\nldr w0,[sp,#32]\\ncmp w0,#4\\nb.ne Lrr_fail\\nmov x8,#0x1000\\nstr x8,[sp,#36]\\nadd x8,x8,#8\\nstr x8,[sp,#52]\\nmov w8,#16\\nstrh w8,[sp,#60]\\nstrh w8,[sp,#62]\\nstr wzr,[sp,#64]\\nmov x23,#2\\nmov x24,#68\\nbl Lrr_send\\nldr w0,[sp,#32]\\ncmp w0,#4\\nb.ne Lrr_fail\\nmov x8,#0x2000\\nstr x8,[sp,#36]\\nmov x8,#0x1000\\nstr x8,[sp,#52]\\nmov w8,#4096\\nstrh w8,[sp,#60]\\nstrh w8,[sp,#62]\\nbl Lrr_send\\nldr w0,[sp,#32]\\ncmp w0,#0\\nb.ne Lrr_fail\\n\\nbl Lrr_send\\nldr w0,[sp,#32]\\ncmp w0,#46\\nb.ne Lrr_fail\\nmov x22,#8001\\nmov x24,#24\\nbl Lrr_send\\nldr w0,[sp,#32]\\ncmp w0,#0\\nb.ne Lrr_fail\\nldr x8,[sp,#1024]\\ncmp x8,#0x5a\\nb.ne Lrr_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLrr_send:\\nldr x25,[sp,#36]\\nmov w8,#0x1513\\nstr w8,[sp]\\nstr w24,[sp,#4]\\nstr w19,[sp,#8]\\nstr w20,[sp,#12]\\nstr wzr,[sp,#16]\\nstr w22,[sp,#20]\\nstr wzr,[sp,#24]\\nmov w8,#1\\nstr w8,[sp,#28]\\nstr w23,[sp,#32]\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\nldr w2,[sp]\\norr x2,x2,x24,lsl #32\\norr x3,x19,x20,lsl #32\\nlsl x4,x22,#32\\nlsl x5,x20,#32\\nmov x6,#44\\nmov x7,#0\\nmov x8,#0xa0000000\\nmsr nzcv,x8\\nmov x16,#-47\\nsvc #0x80\\ncbnz x0,Lrr_fail\\nmrs x8,nzcv\\nmov x9,#0xa0000000\\ncmp x8,x9\\nb.ne Lrr_fail\\nldr w8,[sp,#4]\\ncmp w8,#36\\nb.ne Lrr_fail\\nldr w8,[sp,#20]\\nadd w9,w22,#100\\ncmp w8,w9\\nb.ne Lrr_fail\\nldr w8,[sp]\\nmov w9,#0x1200\\ncmp w8,w9\\nb.ne Lrr_fail\\nldr w8,[sp,#12]\\ncmp w8,w20\\nb.ne Lrr_fail\\nldr w8,[sp,#36]\\ncbnz w8,Lrr_fail\\nldr w8,[sp,#40]\\ncmp w8,#8\\nb.ne Lrr_fail\\nstr x25,[sp,#36]\\nret\\nLrr_fail:\\nmov x16,#21\\nsvc #0x80\\nb .\\n";
        calendar_assembly+="\\n.text\\n.p2align 2\\n.globl _pthreadRegistrationPrepareEntry\\n_pthreadRegistrationPrepareEntry:\\nsub sp,sp,#128\\nstp xzr,xzr,[sp]\\nstp xzr,xzr,[sp,#16]\\nstp xzr,xzr,[sp,#32]\\nstp xzr,xzr,[sp,#48]\\nmov x8,#60\\nstr x8,[sp]\\nmov x8,#48\\nstr x8,[sp,#8]\\nmov w8,#16\\nstr w8,[sp,#24]\\nmov w8,#40\\nstr w8,[sp,#28]\\nmov w8,#41\\nstr w8,[sp,#32]\\nmov x8,#0x5a\\nstr x8,[sp,#56]\\nadr x0,Lof_pthread_registered_target\\nmov x9,#0\\n.inst 0xdac10120\\nmov x1,x0\\nmov x2,#64\\nmov x3,sp\\nmov x4,#60\\nmov x5,#999\\nmov x8,#0xa0000000\\nmsr nzcv,x8\\nmov x16,#366\\nsvc #0x80\\nb.cs Lof_pthread_feature_fail\\ncbnz x1,Lof_pthread_feature_fail\\nmrs x8,nzcv\\nmov x9,#0x80000000\\ncmp x8,x9\\nb.ne Lof_pthread_feature_fail\\nmov x8,#0xde\\nmovk x8,#0x4000,lsl #16\\ncmp x0,x8\\nb.ne Lof_pthread_feature_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_pthread_feature_fail:\\nmov x16,#21\\nsvc #0x80\\nb .\\nLof_pthread_registered_target:\\nnop\\nret\\n.globl _pthreadRegistrationErrorsEntry\\n_pthreadRegistrationErrorsEntry:\\nsub sp,sp,#128\\nmov x0,#0x1234\\nmov x1,#0x5678\\nmov x2,#-1\\nmov x3,#1\\nmov x4,#60\\nmov x5,#0\\nmov x16,#366\\nsvc #0x80\\nb.cc Lpreg_fail\\ncmp x0,#22\\nb.ne Lpreg_fail\\nmov x0,#366\\nmov x1,#0x1234\\nmov x2,#0x5678\\nmov x3,#64\\nmov x4,#1\\nmov x5,#60\\nmov x6,#0\\nmov x16,#0\\nsvc #0x80\\nb.cc Lpreg_fail\\ncmp x0,#14\\nb.ne Lpreg_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLpreg_fail:\\nmov x16,#21\\nsvc #0x80\\nb .\\n";
        calendar_assembly+="\\n.text\\n.p2align 2\\n.globl _runQueueQuantumEntry\\n_runQueueQuantumEntry:\\nmov x0,#0\\nmov x1,#30000\\nLrun_queue_count:\\nadd x0,x0,#1\\nsubs x1,x1,#1\\nb.ne Lrun_queue_count\\nmov x16,#65535\\nsvc #0x80\\nb .\\n";
        calendar_assembly+="\\n.text\\n.p2align 2\\n.globl _specialPortsConsumerEntry\\n_specialPortsConsumerEntry:\\nsub sp,sp,#512\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nmov x16,#-29\\nsvc #0x80\\nmov x21,x0\\nmov x28,#0\\nmov x24,#0\\nmov x25,#0\\nmov x22,#1\\nmov x23,#3409\\nmov x26,x19\\nbl Lsp_send\\nmov x22,#2\\nmov x23,#3409\\nmov x26,x21\\nbl Lsp_send\\nmov x22,#4\\nmov x23,#3409\\nmov x26,xzr\\nbl Lsp_send\\nmov x22,#9\\nmov x23,#3409\\nmov x26,xzr\\nbl Lsp_send\\nmov x22,#10\\nmov x23,#3409\\nmov x26,xzr\\nbl Lsp_send\\nmov x22,#0\\nmov x25,#4\\nmov x23,#3409\\nbl Lsp_send\\nmov x22,#7\\nmov x25,#4\\nmov x23,#3409\\nbl Lsp_send\\nmov x22,#8\\nmov x25,#4\\nmov x23,#3409\\nbl Lsp_send\\nmov x22,#12\\nmov x25,#4\\nmov x23,#3409\\nbl Lsp_send\\nmov x22,#-1\\nmov x25,#4\\nmov x23,#3409\\nbl Lsp_send\\nmov x22,#4\\nmov x25,#0\\nmov x23,#3410\\nbl Lsp_send\\nmov x22,#9\\nmov x25,#0\\nmov x23,#3410\\nbl Lsp_send\\nmov x22,#10\\nmov x25,#0\\nmov x23,#3410\\nbl Lsp_send\\nmov x22,#1\\nmov x25,#8\\nmov x23,#3410\\nbl Lsp_send\\nmov x22,#2\\nmov x25,#8\\nmov x23,#3410\\nbl Lsp_send\\nmov x22,#7\\nmov x25,#4\\nmov x23,#3410\\nbl Lsp_send\\nmov x22,#3\\nmov x25,#4\\nmov x23,#3410\\nbl Lsp_send\\nmov x22,#7\\nmov x25,#4\\nmov x23,#3410\\nmov x28,#4\\nbl Lsp_send\\nmov x22,#1\\nmov x25,#8\\nmov x23,#3410\\nmov x28,#4\\nbl Lsp_send\\nmov x22,#2\\nmov x25,#8\\nmov x23,#3410\\nmov x28,#4\\nbl Lsp_send\\nmov x28,#0\\nmov x23,#3409\\nmov x22,#4\\nmov x28,#1\\nmov x24,#0x10\\nmovk x24,#0x1000,lsl #16\\nbl Lsp_send\\nmov x23,#3409\\nmov x22,#4\\nmov x28,#2\\nmov x24,#0x10\\nmovk x24,#0x1000,lsl #16\\nbl Lsp_send\\nmov x23,#3410\\nmov x22,#4\\nmov x28,#1\\nmov x24,#0x10\\nmovk x24,#0x1000,lsl #16\\nbl Lsp_send\\nmov x23,#3410\\nmov x22,#4\\nmov x28,#2\\nmov x24,#0x10\\nmovk x24,#0x1000,lsl #16\\nbl Lsp_send\\nmov x23,#3410\\nmov x22,#4\\nmov x28,#3\\nmov x24,#0x10\\nmovk x24,#0x1000,lsl #16\\nbl Lsp_send\\n\\nmov x16,#65535\\nsvc #0x80\\nb .\\n.globl _specialPortsFlavorEntry\\n_specialPortsFlavorEntry:\\nsub sp,sp,#512\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nmov x23,#3409\\nmov x22,#3\\nmov x28,#0\\nbl Lsp_send\\nb Lsp_fail\\n.globl _specialPortsRetentionEntry\\n_specialPortsRetentionEntry:\\nsub sp,sp,#512\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nmov x23,#3410\\nmov x22,#4\\nmov x28,#4\\nbl Lsp_send\\nb Lsp_fail\\nLsp_send:\\nmov x8,#0x5a\\nstr x8,[sp,#80]\\nmov w8,#0x1513\\nmov x9,#36\\nmov x5,#0\\ncmp x23,#3409\\nb.eq Lsp_get_request\\nmovk w8,#0x8000,lsl #16\\nmov x9,#52\\nmov x5,#1\\nstr w5,[sp,#24]\\nstr wzr,[sp,#28]\\nstr wzr,[sp,#32]\\nmov w10,#19\\nstrh w10,[sp,#38]\\nstr wzr,[sp,#40]\\nmov w10,#1\\nstr w10,[sp,#44]\\nstr w22,[sp,#48]\\ncmp x28,#4\\nb.ne Lsp_descriptor\\nstr w19,[sp,#28]\\nLsp_descriptor:\\ncmp x28,#3\\nb.ne Lsp_header\\nmov w10,#17\\nstrb w10,[sp,#38]\\nb Lsp_header\\nLsp_get_request:\\nstr wzr,[sp,#24]\\nmov w10,#1\\nstr w10,[sp,#28]\\nstr w22,[sp,#32]\\nLsp_header:\\nstr w8,[sp]\\nstr w9,[sp,#4]\\nstr w19,[sp,#8]\\nstr w20,[sp,#12]\\nstr wzr,[sp,#16]\\nstr w23,[sp,#20]\\ncmp x28,#1\\nb.ne Lsp_ndr\\nstr wzr,[sp,#8]\\nLsp_ndr:\\ncmp x28,#2\\nb.ne Lsp_trap\\ncmp x23,#3409\\nb.ne Lsp_set_ndr\\nstr wzr,[sp,#28]\\nb Lsp_trap\\nLsp_set_ndr:\\nstr wzr,[sp,#44]\\nLsp_trap:\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\norr x2,x8,x9,lsl #32\\norr x3,x19,x20,lsl #32\\nlsl x4,x23,#32\\norr x5,x5,x20,lsl #32\\nmov x6,#80\\nmov x7,#0\\nmov x8,#0xa0000000\\nmsr nzcv,x8\\nmov x16,#-47\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xa0000000\\ncmp x8,x9\\nb.ne Lsp_fail\\ncmp x0,x24\\nb.ne Lsp_fail\\nldr x8,[sp,#80]\\ncmp x8,#0x5a\\nb.ne Lsp_fail\\ncbnz x24,Lsp_return\\nldr w8,[sp,#20]\\nadd w9,w23,#100\\ncmp w8,w9\\nb.ne Lsp_fail\\nldr w8,[sp,#12]\\ncmp w8,w20\\nb.ne Lsp_fail\\nldr w8,[sp,#8]\\ncbnz w8,Lsp_fail\\ncmp x23,#3409\\nb.ne Lsp_error_reply\\ncbnz x25,Lsp_error_reply\\nldr w8,[sp]\\nmov w9,#0x1200\\nmovk w9,#0x8000,lsl #16\\ncmp w8,w9\\nb.ne Lsp_fail\\nldr w8,[sp,#4]\\ncmp w8,#40\\nb.ne Lsp_fail\\nldr w8,[sp,#24]\\ncmp w8,#1\\nb.ne Lsp_fail\\nldr w8,[sp,#28]\\ncmp w8,w26\\nb.ne Lsp_fail\\nldrb w8,[sp,#38]\\ncmp w8,#17\\nb.ne Lsp_fail\\nldrb w8,[sp,#39]\\ncbnz w8,Lsp_fail\\nldr w8,[sp,#40]\\ncbnz w8,Lsp_fail\\nldr w8,[sp,#44]\\ncmp w8,#8\\nb.ne Lsp_fail\\nb Lsp_return\\nLsp_error_reply:\\nldr w8,[sp]\\nmov w9,#0x1200\\ncmp w8,w9\\nb.ne Lsp_fail\\nldr w8,[sp,#4]\\ncmp w8,#36\\nb.ne Lsp_fail\\nldr w8,[sp,#32]\\ncmp w8,w25\\nb.ne Lsp_fail\\nldr w8,[sp,#36]\\ncbnz w8,Lsp_fail\\nldr w8,[sp,#40]\\ncmp w8,#8\\nb.ne Lsp_fail\\nLsp_return:\\nret\\nLsp_fail:\\nmov x16,#21\\nsvc #0x80\\nb .\\n";
        calendar_assembly+=".text\\n.p2align 2\\n.globl _descriptorAliasesConsumerEntry\\n_descriptorAliasesConsumerEntry:\\nsub sp,sp,#32\\nadr x0,Lof_descriptors_path\\nmov x1,#0x1000000\\nmov x2,#0\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#5\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\nmov x19,x0\\nmov x0,x19\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#41\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,x19\\nb.eq Lof_descriptors_failure\\nmov x20,x0\\nmov x0,x19\\nmov x1,#1\\nmov x2,#0\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#92\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#1\\nb.ne Lof_descriptors_failure\\nmov x0,x20\\nmov x1,#1\\nmov x2,#0\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#92\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#0\\nb.ne Lof_descriptors_failure\\nmov x0,x20\\nmov x1,#2\\nmov x2,#1\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#92\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#0\\nb.ne Lof_descriptors_failure\\nmov x0,x19\\nmov x1,#2\\nmov x2,#0\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#92\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#0\\nb.ne Lof_descriptors_failure\\nmov x0,x20\\nmov x1,#1\\nmov x2,#0\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#92\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#1\\nb.ne Lof_descriptors_failure\\nadr x0,Lof_descriptors_path\\nmov x1,#0\\nmov x2,#0\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#5\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\nmov x21,x0\\nmov x1,x20\\nmov x2,x21\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x0,#90\\nmov x16,#0\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,x21\\nb.ne Lof_descriptors_failure\\nmov x0,x21\\nmov x1,#1\\nmov x2,#0\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#92\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#0\\nb.ne Lof_descriptors_failure\\nmov x0,x20\\nmov x1,x20\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#90\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,x20\\nb.ne Lof_descriptors_failure\\nmov x0,x20\\nmov x1,#1\\nmov x2,#0\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#92\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#1\\nb.ne Lof_descriptors_failure\\nmov x0,#999\\nmov x1,x21\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#90\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xe0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#9\\nb.ne Lof_descriptors_failure\\nmov x0,x21\\nmov x1,#1\\nmov x2,#0\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#92\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#0\\nb.ne Lof_descriptors_failure\\nmov x0,x19\\nmov x1,sp\\nmov x2,#8\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#3\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#8\\nb.ne Lof_descriptors_failure\\nldr w23,[sp]\\nldr w24,[sp,#4]\\nmov x0,x20\\nmov x1,#0\\nmov x2,#0\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#199\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#0\\nb.ne Lof_descriptors_failure\\nmov x0,x21\\nmov x1,sp\\nmov x2,#4\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#3\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#4\\nb.ne Lof_descriptors_failure\\nldr w8,[sp]\\ncmp w8,w23\\nb.ne Lof_descriptors_failure\\nmov x0,x20\\nmov x1,sp\\nmov x2,#4\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#3\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#4\\nb.ne Lof_descriptors_failure\\nldr w8,[sp]\\ncmp w8,w24\\nb.ne Lof_descriptors_failure\\nmov x0,x19\\nmov x1,#0\\nmov x2,#1\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#199\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#8\\nb.ne Lof_descriptors_failure\\nmov x0,x19\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#6\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#0\\nb.ne Lof_descriptors_failure\\nmov x1,x19\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x0,#41\\nmov x16,#0\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xe0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#9\\nb.ne Lof_descriptors_failure\\nmov x0,x19\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#41\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xe0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#9\\nb.ne Lof_descriptors_failure\\nmov x1,x19\\nmov x2,x21\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x0,#90\\nmov x16,#0\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xe0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#9\\nb.ne Lof_descriptors_failure\\nmov x0,x21\\nmov x1,#0\\nmov x2,#0\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#199\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#0\\nb.ne Lof_descriptors_failure\\nmov x0,x20\\nmov x1,sp\\nmov x2,#4\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#3\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#4\\nb.ne Lof_descriptors_failure\\nldr w8,[sp]\\ncmp w8,w23\\nb.ne Lof_descriptors_failure\\nmov x1,x21\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x0,#41\\nmov x16,#0\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\nmov x22,x0\\nmov x0,x22\\nmov x1,#0\\nmov x2,#1\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#199\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#4\\nb.ne Lof_descriptors_failure\\nmov x0,x20\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#6\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#0\\nb.ne Lof_descriptors_failure\\nmov x0,x21\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#6\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#0\\nb.ne Lof_descriptors_failure\\nmov x0,x22\\nmov x8,#0xe0000000\\nmsr nzcv,x8\\nmov x16,#6\\nsvc #0x80\\nmrs x8,nzcv\\nmov x9,#0xc0000000\\ncmp x8,x9\\nb.ne Lof_descriptors_failure\\ncbnz x1,Lof_descriptors_failure\\ncmp x0,#0\\nb.ne Lof_descriptors_failure\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLof_descriptors_failure:\\nmov x16,#65534\\nsvc #0x80\\nb .\\nLof_descriptors_path: .asciz \\\"/process/main\\\"\\n.p2align 2\\n";
        calendar_assembly+="\\n.text\\n.p2align 2\\n.globl _machPeerConsumerEntry\\n_machPeerConsumerEntry:\\nmov x29,#0\\nb Lmp_setup\\n.globl _machPeerBadPacEntry\\n_machPeerBadPacEntry:\\nmov x29,#1\\nb Lmp_setup\\n.globl _machPeerNoPauthEntry\\n_machPeerNoPauthEntry:\\nmov x29,#2\\nLmp_setup:\\nsub sp,sp,#2,lsl #12\\nmov x16,#-28\\nsvc #0x80\\nmov x19,x0\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nmov x16,#-27\\nsvc #0x80\\nmov x21,x0\\nmov x16,#372\\nsvc #0x80\\nmov x26,x0\\nmov x8,#0\\nLmp_zero:\\nstr xzr,[sp,x8]\\nadd x8,x8,#8\\ncmp x8,#512\\nb.lo Lmp_zero\\nadd x8,sp,#400\\nstr x8,[sp,#40]\\nstr x21,[sp,#48]\\nadr x0,Lmp_peer\\nmov x1,#29825\\n.inst 0xdac10020\\nstr x0,[sp,#296]\\nadd x0,sp,#1,lsl #12\\nmov x1,#52205\\n.inst 0xdac10820\\nstr x0,[sp,#288]\\nmov x23,#3412\\nmov x24,x19\\nmov x25,#4\\nstr wzr,[sp,#32]\\nmov w8,#68\\nstr w8,[sp,#36]\\nbl Lmp_send\\nmov w8,#6\\nstr w8,[sp,#32]\\nmov w8,#68\\nstr w8,[sp,#36]\\nadd x8,sp,#400\\nstr x8,[sp,#40]\\ncbz x29,Lmp_valid_state\\nldr x8,[sp,#296]\\nmov x9,#0x0001000000000000\\neor x8,x8,x9\\nstr x8,[sp,#296]\\ncmp x29,#2\\nb.ne Lmp_valid_state\\nmov w8,#1\\nstr w8,[sp,#308]\\nLmp_valid_state:\\nmov x25,#0\\nbl Lmp_send\\nldr w22,[sp,#28]\\ncbz x22,Lmp_fail\\ncbz x29,Lmp_suspend_group\\nmov x23,#3605\\nmov x24,x21\\nbl Lmp_send\\nb Lmp_fail\\nLmp_suspend_group:\\nmov x23,#3605\\nmov x24,x22\\nbl Lmp_send\\nbl Lmp_send\\nmov x23,#3606\\nbl Lmp_send\\nmov x8,#40000\\nLmp_delay:\\nsubs x8,x8,#1\\nb.ne Lmp_delay\\nldr x8,[sp,#400]\\ncbnz x8,Lmp_fail\\nmov x8,#1\\nadd x9,sp,#440\\nstlr x8,[x9]\\nbl Lmp_send\\nmov x23,#3605\\nmov x24,x21\\nbl Lmp_send\\nldr x8,[sp,#400]\\ncbz x8,Lmp_fail\\ncmp x8,x26\\nb.eq Lmp_fail\\nldr x8,[sp,#408]\\ncmp w8,w22\\nb.ne Lmp_fail\\nldr x8,[sp,#416]\\nadd x9,sp,#432\\ncmp x8,x9\\nb.ne Lmp_fail\\nldr x8,[sp,#424]\\ncbnz x8,Lmp_fail\\nmov x0,x19\\nmov x1,x22\\nmov x2,#4\\nmov x3,#-2\\nmov x16,#-19\\nsvc #0x80\\ncbnz x0,Lmp_fail\\nmov x0,x19\\nmov x1,x22\\nmov x2,#4\\nmov x3,#-1\\nmov x16,#-19\\nsvc #0x80\\ncmp x0,#15\\nb.ne Lmp_fail\\nmov x16,#65535\\nsvc #0x80\\nb .\\nLmp_peer:\\nmov x28,x0\\nmov x27,x1\\nadd x9,x28,#40\\nLmp_wait_release:\\nldar x8,[x9]\\ncbz x8,Lmp_wait_release\\nmrs x8,tpidrro_el0\\ncbnz x8,Lmp_fail\\nmov x16,#372\\nsvc #0x80\\nstr x0,[x28]\\nmov x16,#-27\\nsvc #0x80\\nmov x22,x0\\nstr x0,[x28,#8]\\nadd x0,x28,#32\\nmov x3,#2\\nmov x16,#0x80000000\\nsvc #0x80\\nmrs x8,tpidrro_el0\\nstr x8,[x28,#16]\\nmov x16,#-26\\nsvc #0x80\\nmov x20,x0\\nsub sp,sp,#512\\nmov x23,#3606\\nmov x24,x27\\nmov x25,#-1\\nLmp_resume_parent:\\nbl Lmp_send\\nldr w8,[sp,#32]\\ncmp w8,#5\\nb.eq Lmp_resume_parent\\ncbnz w8,Lmp_fail\\nmov x25,#0\\nmov x23,#3600\\nmov x24,x22\\nbl Lmp_send\\nmov x8,#1\\nstr x8,[x28,#24]\\nb Lmp_fail\\nLmp_send:\\nmov w8,#0x1513\\nstr w8,[sp]\\nmov x9,#24\\ncmp x23,#3412\\nb.ne Lmp_header\\nmov x9,#312\\nstr wzr,[sp,#24]\\nmov w8,#1\\nstr w8,[sp,#28]\\nLmp_header:\\nstr w9,[sp,#4]\\nstr w24,[sp,#8]\\nstr w20,[sp,#12]\\nstr wzr,[sp,#16]\\nstr w23,[sp,#20]\\nmov x0,sp\\nmov x1,#3\\nmovk x1,#2,lsl #32\\nldr w2,[sp]\\norr x2,x2,x9,lsl #32\\norr x3,x24,x20,lsl #32\\nlsl x4,x23,#32\\nlsl x5,x20,#32\\nmov x6,#80\\nmov x7,#0\\nmov x16,#-47\\nsvc #0x80\\ncbnz x0,Lmp_fail\\nldr w8,[sp,#20]\\nadd w9,w23,#100\\ncmp w8,w9\\nb.ne Lmp_fail\\nldr w8,[sp,#12]\\ncmp w8,w20\\nb.ne Lmp_fail\\ncmp x23,#3412\\nb.ne Lmp_error\\ncbnz x25,Lmp_error\\nldr w8,[sp,#4]\\ncmp w8,#40\\nb.ne Lmp_fail\\nldr w8,[sp,#24]\\ncmp w8,#1\\nb.ne Lmp_fail\\nldrb w8,[sp,#38]\\ncmp w8,#17\\nb.ne Lmp_fail\\nldr w8,[sp,#44]\\ncmp w8,#8\\nb.ne Lmp_fail\\nret\\nLmp_error:\\nldr w8,[sp,#32]\\ncmn x25,#1\\nb.eq Lmp_status_checked\\ncmp w8,w25\\nb.ne Lmp_fail\\nLmp_status_checked:\\nldr w8,[sp,#4]\\ncmp w8,#36\\nb.ne Lmp_fail\\nldr w8,[sp,#40]\\ncmp w8,#8\\nb.ne Lmp_fail\\nret\\nLmp_fail:\\nmov x16,#21\\nsvc #0x80\\nb .\\n";
        const std::string registration_failures=R"(
.text
.p2align 2
.globl _pthreadRegistrationReadOnlyEntry
_pthreadRegistrationReadOnlyEntry:
mov x19,#2
Lpreg_readonly_repeat:
adr x0,Lpreg_readonly_target
mov x9,#0
.inst 0xdac10120
cmp x19,#1
b.ne Lpreg_readonly_signed
mov x8,#0x0001000000000000
eor x0,x0,x8
Lpreg_readonly_signed:
mov x1,x0
mov x2,#64
adr x3,Lpreg_readonly_data
mov x4,#60
mov x5,#999
mov x16,#366
svc #0x80
b.cc Lpreg_readonly_fail
cmp x0,#22
b.ne Lpreg_readonly_fail
subs x19,x19,#1
b.ne Lpreg_readonly_repeat
adr x8,Lpreg_readonly_data
ldr x8,[x8]
cmp x8,#60
b.ne Lpreg_readonly_fail
mov x16,#65535
svc #0x80
b .
Lpreg_readonly_fail:
mov x16,#21
svc #0x80
b .
Lpreg_readonly_target:
nop
ret
.p2align 3
Lpreg_readonly_data:
.quad 60,48,0
.long 16,40,41
.quad 0
.long 0,1024,0
.long 0x5a5a5a5a
.p2align 2
.globl _pthreadRegistrationLegacyEntry
_pthreadRegistrationLegacyEntry:
adr x0,Lpreg_readonly_target
mov x9,#0
.inst 0xdac10120
mov x1,x0
mov x2,#64
mov x3,#0
mov x4,#65535
mov x5,#48
mov x16,#366
svc #0x80
b.cs Lpreg_legacy_fail
cbnz x1,Lpreg_legacy_fail
mov x8,#0xde
movk x8,#0x4000,lsl #16
cmp x0,x8
b.ne Lpreg_legacy_fail
mov x16,#65535
svc #0x80
b .
Lpreg_legacy_fail:
mov x16,#21
svc #0x80
b .
)";
        const std::string atm_assembly=R"(
.text
.p2align 2
.macro OF_ATM_BASE
mov x19,#0xc000
movk x19,#0xffff,lsl #16
movk x19,#0xf,lsl #32
.endmacro
.globl _atmPolicyEntry
_atmPolicyEntry:
OF_ATM_BASE
mov x10,#0x90000000
msr nzcv,x10
ldr w8,[x19,#0x104]
mrs x11,nzcv
cmp x10,x11
b.ne Lof_atm_fail
cmp w8,#0x100
b.ne Lof_atm_fail
// Same decision as original libsystem_trace: bit8 disables new logging.
tbnz w8,#8,Lof_atm_disabled
b Lof_atm_fail
Lof_atm_disabled:
ldrb w8,[x19,#0x104]
cbnz w8,Lof_atm_fail
ldrb w8,[x19,#0x105]
cmp w8,#1
b.ne Lof_atm_fail
ldrb w8,[x19,#0x106]
cbnz w8,Lof_atm_fail
ldrb w8,[x19,#0x107]
cbnz w8,Lof_atm_fail
ldrh w8,[x19,#0x104]
cmp w8,#0x100
b.ne Lof_atm_fail
ldrh w8,[x19,#0x106]
cbnz w8,Lof_atm_fail
add x20,x19,#0x104
ldurh w8,[x20,#1]
cmp w8,#1
b.ne Lof_atm_fail
mov x21,#20
Lof_atm_repeat:
ldr w8,[x19,#0x104]
cmp w8,#0x100
b.ne Lof_atm_fail
subs x21,x21,#1
b.ne Lof_atm_repeat
ldr w8,[x19,#0x100]
cbnz w8,Lof_atm_fail
ldr w8,[x19,#0x108]
cbnz w8,Lof_atm_fail
mov x16,#65535
svc #0x80
b .
Lof_atm_fail:
mov x16,#65534
svc #0x80
b .
.globl _atmCrossReadEntry
_atmCrossReadEntry:
OF_ATM_BASE
add x19,x19,#0x104
ldr x0,[x19]
b Lof_atm_fail
.globl _atmLeftCrossEntry
_atmLeftCrossEntry:
OF_ATM_BASE
add x19,x19,#0x102
ldr w0,[x19]
b Lof_atm_fail
.globl _atmRightCrossEntry
_atmRightCrossEntry:
OF_ATM_BASE
add x19,x19,#0x107
ldrh w0,[x19]
b Lof_atm_fail
.globl _atmRoAliasEntry
_atmRoAliasEntry:
OF_ATM_BASE
sub x19,x19,#8,lsl #12
ldr w0,[x19,#0x104]
b Lof_atm_fail
.globl _atmUnknownEntry
_atmUnknownEntry:
OF_ATM_BASE
ldr w0,[x19,#0x110]
b Lof_atm_fail
.globl _atmWriteEntry
_atmWriteEntry:
OF_ATM_BASE
str wzr,[x19,#0x104]
b Lof_atm_fail
.globl _atmFetchEntry
_atmFetchEntry:
OF_ATM_BASE
add x19,x19,#0x104
br x19
)";
        const std::string clock_capabilities_assembly=R"(
.text
.p2align 2
.macro OF_CLOCK_BASE
mov x19,#0xc000
movk x19,#0xffff,lsl #16
movk x19,#0xf,lsl #32
.endmacro
.globl _clockFallbackEntry
_clockFallbackEntry:
sub sp,sp,#32
OF_CLOCK_BASE
ldrb w8,[x19,#0x90]
cbnz w8,Lof_clock_fail
ldrb w8,[x19,#0x91]
cbnz w8,Lof_clock_fail
ldrb w8,[x19,#0xc8]
cbnz w8,Lof_clock_fail
mov x0,sp
mov x16,#-89
svc #0x80
cbnz x0,Lof_clock_fail
ldp w8,w9,[sp]
cmp w8,#100
b.ne Lof_clock_fail
cmp w9,#1
b.ne Lof_clock_fail
bl Lof_clock_approximate
cbz x0,Lof_clock_fail
mov x21,x0
mov x22,#20
Lof_clock_repeat:
bl Lof_clock_approximate
cmp x0,x21
b.lo Lof_clock_fail
mov x21,x0
subs x22,x22,#1
b.ne Lof_clock_repeat
bl Lof_clock_continuous_approximate
cbz x0,Lof_clock_fail
mov x23,x0
mov w16,#-4
svc #0x80
cbz x0,Lof_clock_fail
mov x24,x0
cmp x24,x21
b.lo Lof_clock_fail
mov x16,#65535
svc #0x80
b .
// Source-shaped wrappers exercise real fallback traps and actual timebase.
Lof_clock_approximate:
mov x8,#0xc000
movk x8,#0xffff,lsl #16
movk x8,#0xf,lsl #32
ldrb w9,[x8,#0xc8]
cbz w9,Lof_clock_absolute
ldr x0,[x8,#0xc0]
ret
Lof_clock_absolute:
mov x3,#0xc000
movk x3,#0xffff,lsl #16
movk x3,#0xf,lsl #32
ldrb w2,[x3,#0x90]
cbnz w2,Lof_clock_fail
mov w16,#-3
svc #0x80
ret
Lof_clock_continuous_approximate:
stp x19,x30,[sp,#-16]!
mov x8,#0xc098
movk x8,#0xffff,lsl #16
movk x8,#0xf,lsl #32
ldr x19,[x8]
bl Lof_clock_approximate
add x0,x0,x19
ldp x19,x30,[sp],#16
ret
Lof_clock_fail:
mov x16,#65534
svc #0x80
b .
.globl _clockCapWideEntry
_clockCapWideEntry:
OF_CLOCK_BASE
ldrh w0,[x19,#0xc8]
b Lof_clock_fail
.globl _clockCapRoEntry
_clockCapRoEntry:
OF_CLOCK_BASE
sub x19,x19,#8,lsl #12
ldrb w0,[x19,#0xc8]
b Lof_clock_fail
.globl _clockRawApproxEntry
_clockRawApproxEntry:
OF_CLOCK_BASE
ldr x0,[x19,#0xc0]
b Lof_clock_fail
.globl _clockRawHardwareEntry
_clockRawHardwareEntry:
OF_CLOCK_BASE
ldr x0,[x19,#0xa8]
b Lof_clock_fail
.globl _clockRawTimebaseEntry
_clockRawTimebaseEntry:
OF_CLOCK_BASE
ldr x0,[x19,#0x88]
b Lof_clock_fail
.globl _clockCapNextEntry
_clockCapNextEntry:
OF_CLOCK_BASE
ldrb w0,[x19,#0xc9]
b Lof_clock_fail
.globl _clockCapWriteEntry
_clockCapWriteEntry:
OF_CLOCK_BASE
strb wzr,[x19,#0xc8]
b Lof_clock_fail
.globl _clockCapFetchEntry
_clockCapFetchEntry:
OF_CLOCK_BASE
add x19,x19,#0xc8
br x19
)";
        for(const auto c:clock_capabilities_assembly)if(c=='\n')calendar_assembly+="\\n";else calendar_assembly+=c;
        for(const auto c:atm_assembly)if(c=='\n')calendar_assembly+="\\n";else calendar_assembly+=c;
        for(const auto c:registration_failures)if(c=='\n')calendar_assembly+="\\n";else calendar_assembly+=c;
        Write(args_source,Read(args_source)+"\n#if defined(__aarch64__)\n__asm__(\""+calendar_assembly+"\");\n#endif\n");
        DiagnosticStage("arm64 compiling thread_object");
        Run(clang,{L"-target",L"arm64-apple-macos11.0",L"-c",args_source.wstring(),L"-o",thread_object.wstring()});
        DiagnosticStage("arm64 linking thread_main");
        Run(linker,{L"-arch",L"arm64",L"-platform_version",L"macos",L"11.0",L"26.0",L"-fixup_chains",L"-e",L"_main",L"-o",thread_main.wstring(),thread_object.wstring()});
        const auto signed_arm64_main=Read(thread_main);
        auto owned_main_abi=signed_arm64_main;Little32(owned_main_abi,8,2);Write(thread_main,owned_main_abi);
        DiagnosticStage("arm64 linking thread_dyld");
        Run(linker,{L"-dylib",L"-arch",L"arm64",L"-platform_version",L"macos",L"11.0",L"26.0",L"-headerpad",L"1000",L"-fixup_chains",L"-install_name",L"/usr/lib/dyld",L"-o",thread_dyld.wstring(),thread_object.wstring()});
        DiagnosticStage("arm64 inspecting thread_dyld");
        auto thread_bytes=Read(thread_dyld);DarwinImage interpreter_metadata;
        Require(InspectDarwinImage(thread_bytes,0x0100000c,interpreter_metadata,error),"Owned ARM64 interpreter geometry invalid: "+error);
        const auto text_section=std::find_if(interpreter_metadata.sections.begin(),interpreter_metadata.sections.end(),[](const auto& section){return section.name=="__text";});
        Require(text_section!=interpreter_metadata.sections.end(),"Owned interpreter text section absent");
        const auto interpreter_header=std::find_if(interpreter_metadata.segments.begin(),interpreter_metadata.segments.end(),[](const auto& segment){return !segment.file_offset&&segment.file_size;});
        Require(interpreter_header!=interpreter_metadata.segments.end(),"Owned interpreter header segment absent");
        const auto entry_address=[&](const std::string& name){const auto symbol=std::find_if(interpreter_metadata.exports.begin(),interpreter_metadata.exports.end(),[&](const auto& value){return value.symbol==name;});
            Require(symbol!=interpreter_metadata.exports.end(),"Owned entry export absent");return interpreter_header->address+symbol->value;};
        const auto thread_entry=entry_address("_threadEntry");
        std::string context(288,'\0');Little32(context,0,5);Little32(context,4,288);Little32(context,8,6);Little32(context,12,68);
        Little32(context,16,0x12345678);Little32(context,20,0x89abcdef);Little32(context,16+28*8,0x98765432);
        std::memcpy(context.data()+16+32*8,&thread_entry,8);Little32(context,16+66*4,0x60000000);
        const auto context_offset=32+Little32(thread_bytes,20);
        Require(context_offset+context.size()<=text_section->file_offset,"Owned ARM64 thread header padding absent");
        std::memcpy(thread_bytes.data()+context_offset,context.data(),context.size());Little32(thread_bytes,12,7);
        Little32(thread_bytes,16,Little32(thread_bytes,16)+1);Little32(thread_bytes,20,Little32(thread_bytes,20)+288);Write(thread_dyld,thread_bytes);
        DiagnosticStage("arm64 MapDarwinArm64Images /process/main");
        const auto prepared_thread=MapDarwinArm64Images("/process/main",{thread_tree},{},{},true);
        Require(prepared_thread.mapped&&prepared_thread.process_thread.Get("owner")->StringValue()=="/usr/lib/dyld"
            &&prepared_thread.process_thread.Get("register_readback_agrees")->Bool(),"Original owned ARM64 thread not prepared: "+prepared_thread.diagnostic);
        const auto& read_registers=prepared_thread.process_thread.Get("general_register_readback")->ArrayItems();
        Require(read_registers.size()==31&&read_registers[0].Serialize()==std::to_string(0x89abcdef12345678ULL)
            &&read_registers[28].Serialize()==std::to_string(0x98765432ULL)&&read_registers[1].Serialize()=="0"
            &&read_registers[29].Serialize()=="0"&&read_registers[30].Serialize()=="0"
            &&prepared_thread.process_thread.Get("pstate_readback")->Serialize()==std::to_string(0x60000000u)
            &&prepared_thread.process_thread.Get("sp_readback")->Serialize()==prepared_thread.process_stack.Get("kernel_sp")->Serialize(),
            "Initial thread register/SP/status source propagation differs");
        auto unsupported_status=thread_bytes;Little32(unsupported_status,context_offset+16+66*4,5);Write(thread_dyld,unsupported_status);
        Require(!MapDarwinArm64Images("/process/main",{thread_tree},{},{},true).mapped,"Privileged initial CPU state accepted");
        auto unsupported_flags=thread_bytes;Little32(unsupported_flags,context_offset+16+67*4,1);Write(thread_dyld,unsupported_flags);
        Require(!MapDarwinArm64Images("/process/main",{thread_tree},{},{},true).mapped,"Unsupported authenticated thread-state flags accepted");
        Write(thread_dyld,thread_bytes);
        const auto syscall_bootstrap=MapDarwinArm64Images("/process/main",{thread_tree},{},{},false,true);
        Require(syscall_bootstrap.mapped&&syscall_bootstrap.bootstrap.Get("entered")->Bool()
            &&syscall_bootstrap.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&syscall_bootstrap.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&syscall_bootstrap.bootstrap.Get("instruction_callbacks")->Serialize()=="3"
            &&!syscall_bootstrap.bootstrap.Get("execution_validated")->Bool(),"Bootstrap syscall observation returned fake success: "+syscall_bootstrap.diagnostic);
        auto memory_bootstrap_bytes=thread_bytes;const auto memory_entry=entry_address("_memoryEntry");
        std::memcpy(memory_bootstrap_bytes.data()+context_offset+16+32*8,&memory_entry,8);Write(thread_dyld,memory_bootstrap_bytes);
        const auto memory_bootstrap=MapDarwinArm64Images("/process/main",{thread_tree},{},{},false,true);
        Require(memory_bootstrap.mapped&&memory_bootstrap.bootstrap.GetString("stop_reason")=="unsupported_memory_access"
            &&memory_bootstrap.bootstrap.Get("memory_address")->Serialize()=="0"
            &&memory_bootstrap.bootstrap.Get("instruction_callbacks")->Serialize()=="2","Bootstrap memory fault was hidden or resumed");
        const auto& memory_trace=memory_bootstrap.bootstrap.Get("last_instructions")->ArrayItems();
        Require(!memory_trace.empty()&&memory_trace.back().Get("register_snapshot_before_instruction")->Bool()
            &&memory_trace.back().Get("registers")->ArrayItems().size()==32
            &&memory_trace.back().Get("registers")->ArrayItems()[0].Serialize()=="0"
            &&!memory_trace.back().Get("load_observed")->Bool(),"Fault trace fabricated a null memory load");
        auto loop_bootstrap_bytes=thread_bytes;const auto loop_entry=entry_address("_loopEntry");
        std::memcpy(loop_bootstrap_bytes.data()+context_offset+16+32*8,&loop_entry,8);Write(thread_dyld,loop_bootstrap_bytes);
        const auto loop_bootstrap=MapDarwinArm64Images("/process/main",{thread_tree},{},{},false,true);
        Require(loop_bootstrap.mapped&&(loop_bootstrap.bootstrap.GetString("stop_reason")=="instruction_budget"
            ||loop_bootstrap.bootstrap.GetString("stop_reason")=="timeout"),"Bootstrap loop escaped execution budget");
        // Large diagnostic budgets must retain host controls even if detailed
        // per-instruction snapshots are disabled. This guest loops without SVC.
        DarwinClosureOptions large_loop_options;
        large_loop_options.instruction_limit=20000001;
        large_loop_options.deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        const auto large_loop=MapDarwinArm64Images("/process/main",{thread_tree},large_loop_options,{},false,true);
        const auto large_stop=large_loop.bootstrap.GetString("stop_reason");
        Require(large_loop.mapped&&(large_stop=="deadline"||large_stop=="instruction_budget"),
            "Large-budget pure guest loop escaped deadline/instruction controls: "+large_loop.bootstrap.Serialize());
        const auto callbacks=large_loop.bootstrap.Get("instruction_callbacks");
        Require(callbacks&&callbacks->Int()>0&&callbacks->Int()<=20000001,
            "Large-budget loop lost real instruction accounting");
        Write(thread_dyld,thread_bytes);
        const auto commpage_probe=[&](const std::string& symbol){DiagnosticStage(symbol.c_str());auto bytes=thread_bytes;const auto pc=entry_address(symbol);
            std::memcpy(bytes.data()+context_offset+16+32*8,&pc,8);Write(thread_dyld,bytes);
            auto result=MapDarwinArm64Images("/process/main",{thread_tree},{},{},false,true);DiagnosticStage("owned ARM64 probe complete");return result;};
        for (const auto* symbol : {"_bsdthreadCtlDirectEntry", "_bsdthreadCtlIndirectEntry"}) {
            const auto ctl=commpage_probe(symbol);
            Require(ctl.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
                &&ctl.bootstrap.Get("syscall_selector")->Int()==65535
                &&ctl.bootstrap.Get("registers")->ArrayItems()[0].Int()==45,
                "BSD478 routing failed for "+std::string(symbol)+": "+ctl.diagnostic+"\n"+ctl.bootstrap.Serialize(true));
        }
        const auto kas_info=commpage_probe("_kasInfoUnsupportedEntry");
        Require(kas_info.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&kas_info.bootstrap.Get("syscall_selector")->Int()==439,
            "Unimplemented kas_info439 routed through unrelated pthread policy handler");
        const auto quantum_consumer=commpage_probe("_runQueueQuantumEntry");
        Require(quantum_consumer.bootstrap.Get("syscall_selector")->Int()==65535
            &&quantum_consumer.bootstrap.Get("registers")->ArrayItems()[0].Int()==30000
            &&quantum_consumer.bootstrap.Get("instruction_callbacks")->Int()==90004
            &&quantum_consumer.bootstrap.Get("thread_context")->Get("run_queue_dispatches")->Int()==2,
            "Quantum dispatch lost instruction/NZCV continuation or guest loop output");
        DarwinClosureOptions quantum_budget;quantum_budget.instruction_limit=70000;
        const auto budget_consumer=MapDarwinArm64Images("/process/main",{thread_tree},quantum_budget,{},false,true);
        Require(budget_consumer.bootstrap.GetString("stop_reason")=="instruction_budget"
            &&budget_consumer.bootstrap.Get("instruction_callbacks")->Int()==70000
            &&budget_consumer.bootstrap.Get("thread_context")->Get("run_queue_dispatches")->Int()==2,
            "Instruction budget restarted at a quantum boundary");
        const auto capabilities=commpage_probe("_capabilityEntry");
        const auto dit=commpage_probe("_ditPolicyEntry");
        Require(dit.mapped&&dit.bootstrap.Get("interrupt")->Int()==2
            &&dit.bootstrap.Get("syscall_selector")->Int()==65535
            &&dit.bootstrap.Get("registers")->ArrayItems()[0].Int()==1
            &&!dit.bootstrap.Get("commpage")->Get("dit_supported")->Bool(),
            "Unsupported DIT capability selected MRS DIT instead of original fallback");
        Require(capabilities.mapped&&capabilities.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&capabilities.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&capabilities.bootstrap.Get("commpage")->Get("validated_reads")->Serialize()=="2",
            "Clock capabilities did not propagate as explicit negative capabilities");
        const auto boot=commpage_probe("_bootTimeEntry");const auto* boot_epoch=boot.bootstrap.Get("boot_clock_epoch");
        const auto mach_owner=commpage_probe("_machNameOwnerEntry");
        Require(mach_owner.mapped&&mach_owner.bootstrap.Get("syscall_selector")->Int()==65535
            &&(mach_owner.bootstrap.Get("registers")->ArrayItems()[0].Int()&3)==3,
            "Generated Mach names do not satisfy original same-thread lock ownership ABI: "+mach_owner.bootstrap.Serialize());
        for(const auto* symbol:{"_vmTaggedNoneEntry","_vmTaggedSlicesEntry","_vmTaggedReleaseEntry"}) {
            const auto vm=commpage_probe(symbol);
            Require(vm.mapped&&vm.bootstrap.Get("syscall_selector")->Int()==65535,
                std::string("Tagged VM protection/partial lifecycle consumer failed: ")+symbol+" "+vm.bootstrap.Serialize());
            const auto* regions=vm.bootstrap.Get("vm_regions");const auto& calls=regions->Get("mig_call_prefix")->ArrayItems();
            Require(calls.size()==1&&calls[0].Get("tag")->Int()==1&&calls[0].Get("result")->Int()==0,"MIG tag identity/result lost");
            const bool none=std::string(symbol)=="_vmTaggedNoneEntry",release=std::string(symbol)=="_vmTaggedReleaseEntry";
            Require(regions->Get("region_count")->Int()==(release?0:none?1:2),"Partial VM release discarded surviving lease or retained released region");
            if(!release){const auto& rows=regions->Get("region_prefix")->ArrayItems();
                for(const auto& row:rows)Require(row.Get("tag")->Int()==1&&row.Get("maximum_protection")->Int()==(none?0:3)&&row.Get("current_protection")->Int()==(none?0:3)&&row.Get("anonymous_backing_lease")->Bool(),"VM slice protection/tag/backing metadata lost");
                if(!none)Require(rows[1].Get("backing_offset")->Int()==0x8000,"Surviving right slice backing offset lost");}
        }
        const auto vm_hole=commpage_probe("_vmTaggedHoleEntry");
        Require(vm_hole.bootstrap.GetString("stop_reason")=="unsupported_memory_access"&&vm_hole.bootstrap.Get("memory_type")->Int()==19,"Partial deallocation left the middle guest page accessible");
        for(const auto* symbol:{"_vmOverwriteEntry","_vmFixedFileEntry"}) {
            const auto vm=commpage_probe(symbol);Require(vm.mapped&&vm.bootstrap.Get("syscall_selector")->Int()==65535,std::string("Fixed replacement guest consumer failed: ")+symbol+" "+vm.bootstrap.Serialize());
            const auto* regions=vm.bootstrap.Get("vm_regions");Require(regions->Get("region_count")->Int()==3,"Fixed replacement retained obsolete overlapping region");
            const auto& rows=regions->Get("region_prefix")->ArrayItems();unsigned replacement=0;
            for(unsigned n=0;n<rows.size();++n){const auto begin=std::stoull(rows[n].Get("address")->Serialize()),end=begin+std::stoull(rows[n].Get("size")->Serialize());
                for(unsigned k=n+1;k<rows.size();++k){const auto other=std::stoull(rows[k].Get("address")->Serialize()),limit=other+std::stoull(rows[k].Get("size")->Serialize());Require(end<=other||limit<=begin,"Overlapping logical VM ownership survived replacement");}
                const bool file=std::string(symbol)=="_vmFixedFileEntry";
                if(file?rows[n].Get("file_backing_lease")->Bool():rows[n].Get("tag")->Int()==7){++replacement;Require(rows[n].Get("backing_offset")->Int()==0&&rows[n].Get("maximum_protection")->Int()==7&&rows[n].Get("current_protection")->Int()==(file?1:3),"Replacement inherited stale backing/protection metadata");}
            }
            Require(replacement==1&&regions->Get("overlap_count")->Int()==0,"Fixed replacement missing its actual new ownership or full overlap audit");
            if(std::string(symbol)=="_vmOverwriteEntry")Require(vm.bootstrap.Get("mach_task")->Get("vm_map_last")->Get("flags")->Int()==0x07004000&&vm.bootstrap.Get("mach_task")->Get("vm_map_last")->Get("result")->Int()==0,"Last actual VM operation lost outside prefix");
        }
        const auto special_ports=commpage_probe("_specialPortsConsumerEntry");
        Require(special_ports.bootstrap.Get("syscall_selector")->Int()==65535,
            "Special port actual identities, null slots, selector errors, wire/trailer or canary failed: "+special_ports.bootstrap.Serialize());
        Require(commpage_probe("_specialPortsFlavorEntry").bootstrap.GetString("stop_reason")=="unsupported_task_special_port_flavor",
            "Known task flavor was replaced with a manufactured control right");
        Require(commpage_probe("_specialPortsRetentionEntry").bootstrap.GetString("stop_reason")=="unsupported_task_special_port_send_retention",
            "Non-null special port was acknowledged without independently retained kernel storage");
        const auto mach_peer=commpage_probe("_machPeerConsumerEntry");
        auto no_jop_main=Read(thread_main);Little32(no_jop_main,8,0);Write(thread_main,no_jop_main);
        const auto no_jop_peer=commpage_probe("_machPeerConsumerEntry");
        Require(no_jop_peer.mapped&&no_jop_peer.bootstrap.Get("syscall_selector")
            &&no_jop_peer.bootstrap.Get("syscall_selector")->Int()==65535
            &&!no_jop_peer.bootstrap.Get("pointer_authentication_policy")->Get("jop_enabled")->Bool()
            &&no_jop_peer.bootstrap.Get("pointer_authentication_policy")->Get("ib_enabled")->Bool(),
            "NOJOP Mach thread-state conversion/admission did not reach its real guest peer: "+no_jop_peer.bootstrap.Serialize());
        Little32(no_jop_main,8,2);Write(thread_main,no_jop_main);
        Require(mach_peer.bootstrap.Get("syscall_selector")->Int()==65535,
            "Actual Mach peer signed-state identity/TSD, counted suspend/resume, dead names or no-return termination failed: "+mach_peer.bootstrap.Serialize());
        // VA48 with TBI stores PAC in bits48..54. The fixture flips bit48,
        // never a top-byte tag: changing a tag recomputes a seven-bit MAC and
        // can accidentally authenticate under random task keys (1/128).
        for(const auto* entry:{"_machPeerBadPacEntry","_machPeerNoPauthEntry"}){
            const auto bad_peer=commpage_probe(entry);
            const auto bad_reason=bad_peer.bootstrap.GetString("stop_reason");
            Require((bad_reason=="unsupported_memory_access"||bad_reason=="guest_prefetch_abort")
                &&bad_peer.bootstrap.Get("thread_context")->Get("guest_thread_count")->Int()==2,
                "Invalid Mach state PAC was stripped, bypassed or replaced with a fake kernel error: "+bad_peer.bootstrap.Serialize());
        }
        const auto restartable=commpage_probe("_restartableConsumerEntry");
        Require(restartable.bootstrap.Get("syscall_selector")->Int()==65535,"Restartable range MIG validation or reply ABI failed: "+restartable.bootstrap.Serialize());
        const auto* rr=restartable.bootstrap.Get("restartable_ranges");
        Require(rr&&rr->Get("register_calls")->Int()==8&&rr->Get("synchronize_calls")->Int()==2
            &&!rr->Get("multithread_synchronization_supported")->Bool(),"Restartable state/single-thread boundary lost");
        const auto& rr_ranges=rr->Get("ranges")->ArrayItems();
        Require(rr_ranges.size()==2&&rr_ranges[0].Get("location")->Int()==0x1000&&rr_ranges[1].Get("location")->Int()==0x2000&&rr_ranges[0].Get("length")->Int()==4096&&rr_ranges[0].Get("recovery_offset")->Int()==4096,
            "Registration was not sorted/preserved or rejected requests published state");
        const auto pthread_prepare=commpage_probe("_pthreadRegistrationPrepareEntry");
        const auto* saved_context=pthread_prepare.bootstrap.Get("thread_context");
        Require(saved_context&&saved_context->Get("saved")->Bool()&&saved_context->Get("captures")->Int()==3
            &&saved_context->Get("guest_thread_count")->Int()==1&&!saved_context->Get("multithread_scheduler_available")->Bool(),
            "Main guest context capture or honest scheduler availability failed");
        Require(saved_context->Get("run_queue_threads")->Int()==1&&saved_context->Get("run_queue_dispatches")->Int()==2
            &&saved_context->Get("instruction_quantum")->Int()==65536,"Main guest did not execute through the actual run queue");
        Require(pthread_prepare.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&pthread_prepare.bootstrap.Get("syscall_selector")->Int()==65535,"Pthread registration did not resume the original caller after feature return");
        const auto* preg=pthread_prepare.bootstrap.Get("pthread_registration");
        Require(preg&&preg->Get("input_decoded")->Bool()&&preg->Get("input_version")->Int()==60&&preg->Get("copyin_bytes")->Int()==56
            &&preg->Get("unknown_tail_bytes")->Int()==4&&preg->Get("registration_committed")->Bool()&&preg->Get("output_copied")->Bool()
            &&preg->Get("output_readback_verified")->Bool()&&preg->Get("feature_return_completed")->Bool()
            &&preg->Get("capabilities_available")->Int()==0x400000de,"Pthread registration/copyout or live-provider capability return failed");
        const auto& wire=preg->Get("output_wire_prefix")->ArrayItems();
        const auto wire_value=[&](std::size_t at,unsigned bytes){std::uint64_t value=0;
            for(unsigned n=0;n<bytes;++n)value|=static_cast<std::uint64_t>(wire.at(at+n).Int())<<(8*n);return value;};
        Require(wire.size()==56&&wire_value(0,8)==56&&wire_value(16,8)==0x8ff&&wire_value(44,4)==0
            &&wire_value(24,4)==16&&wire_value(8,8)==0&&wire_value(28,4)==40&&wire_value(32,4)==0,
            "Pthread reply did not reach actual guest memory with negotiated ABI/default policy/normalized offsets");
        Require(preg->Get("normalized_offsets")->Get("tsd")->Int()==16&&preg->Get("normalized_offsets")->Get("dispatch_queue")->Int()==0
            &&pthread_prepare.bootstrap.Get("registers")->ArrayItems()[0].Int()==0x400000de
            &&preg->Get("entries_converted")->Bool()&&!preg->Get("conversion_certifies_authentication")->Bool(),
            "Normalized input, converted entry or actual feature return register failed");
        const auto pthread_errors=commpage_probe("_pthreadRegistrationErrorsEntry");
        Require(pthread_errors.bootstrap.Get("syscall_selector")->Int()==65535&&pthread_errors.bootstrap.Get("pthread_registration")->Get("calls")->Int()==2
            &&pthread_errors.bootstrap.Get("pthread_registration")->Get("decode_errno")->Int()==14,"Direct/indirect pthread registration error ABI failed");
        Require(!pthread_errors.bootstrap.Get("pthread_registration")->Get("registration_committed")->Bool(),
            "Rejected registration input published owner state");
        const auto readonly_registration=commpage_probe("_pthreadRegistrationReadOnlyEntry");
        const auto* readonly_reply=readonly_registration.bootstrap.Get("pthread_registration");
        Require(readonly_registration.bootstrap.Get("syscall_selector")->Int()==65535&&readonly_reply->Get("calls")->Int()==2
            &&readonly_reply->Get("registration_errno")->Int()==22&&readonly_reply->Get("registration_committed")->Bool()
            &&!readonly_reply->Get("output_copied")->Bool()&&!readonly_reply->Get("feature_return_completed")->Bool()
            &&readonly_reply->Get("capabilities_available")->Int()==0x400000de,
            "Read-only copyout/duplicate lost EINVAL carry ABI, registration persistence or truthful feature boundary: "+readonly_registration.bootstrap.Serialize());
        const auto* readonly_identity=readonly_registration.bootstrap.Get("thread_identity");
        Require(readonly_reply->Get("entries_converted")->Bool()
            &&std::stoull(readonly_reply->Get("converted_thread_start")->Serialize())
                !=std::stoull(readonly_identity->Get("threadstart")->Serialize()),
            "Duplicate PAC poison was stripped, validated eagerly or replaced the registered entry: "+readonly_reply->Serialize()
                +" registered="+readonly_identity->Get("threadstart")->Serialize());
        const auto legacy_registration=commpage_probe("_pthreadRegistrationLegacyEntry");
        const auto* legacy_reply=legacy_registration.bootstrap.Get("pthread_registration");
        Require(legacy_registration.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&legacy_registration.bootstrap.Get("syscall_selector")->Int()==65535
            &&legacy_reply->Get("registration_committed")->Bool()&&!legacy_reply->Get("output_copied")->Bool()
            &&legacy_reply->Get("feature_return_completed")->Bool()
            &&legacy_reply->Get("copyin_bytes")->Int()==0&&legacy_reply->Get("normalized_offsets")->Get("dispatch_queue")->Int()==48,
            "Legacy registration attempted copyout or lost dispatch offset");
        const auto credentials_consumer=commpage_probe("_credentialQueriesEntry");
        Require(credentials_consumer.bootstrap.Get("syscall_selector")->Int()==65535&&credentials_consumer.bootstrap.Get("credentials")->Get("calls")->Int()==9,"Credential/group query real SID projection, capacity, canary or error ABI failed: "+credentials_consumer.bootstrap.Serialize());
        const auto queries=commpage_probe("_codesignQueriesEntry");
        Require(queries.bootstrap.Get("syscall_selector")->Int()==65535&&queries.bootstrap.Get("code_signing")->Get("calls")->Int()==6,"Code-sign query ABI/no-authority/no-placeholder consumer failed: "+queries.bootstrap.Serialize());
        const auto pending_wait=commpage_probe("_unsupportedWaitEntry");
        Require(pending_wait.bootstrap.GetString("stop_reason")=="unsupported_interrupt"&&pending_wait.bootstrap.Get("syscall_selector")->Int()==515,"Unimplemented wait falsely returned success");
        const auto pac_failure=commpage_probe("_pacFailureEntry");
        Require(pac_failure.bootstrap.GetString("stop_reason")=="pointer_authentication_failure"&&pac_failure.bootstrap.Get("interrupt")->Int()==7,"PAC failure stripped/resumed instead of stopping");
        const auto& pac_registers=pac_failure.bootstrap.Get("last_instructions")->ArrayItems().back().Get("registers")->ArrayItems();
        Require(pac_registers[0].Serialize()==std::to_string(0x8000000000001234ULL)&&pac_registers[16].Serialize()==std::to_string(0x8000000000004321ULL),"PAC failure provenance lost original pointer/register state");
        const auto timebase=commpage_probe("_timebaseConsumerEntry");
        Require(timebase.mapped&&timebase.bootstrap.Get("syscall_selector")->Int()==65535&&timebase.bootstrap.Get("timebase_info")->Get("calls")->Int()==1,"Timebase layout/canary/NZCV/clock consumer failed: "+timebase.bootstrap.Serialize());
        const auto& timebase_call=timebase.bootstrap.Get("timebase_info")->Get("call_prefix")->ArrayItems().at(0);
        Require(timebase_call.Get("copied")->Bool()&&timebase_call.Get("readback_verified")->Bool()&&timebase.bootstrap.Get("clocks")->Get("absolute_calls")->Int()==2,"Timebase successful copyout not bound to actual clock calls");
        const auto timebase_invalid=commpage_probe("_timebaseInvalidEntry");
        Require(timebase_invalid.bootstrap.Get("syscall_selector")->Int()==65535&&timebase_invalid.bootstrap.Get("timebase_info")->Get("copyout_failures")->Int()==3,"Pinned XNU ignored-copyout-error return or memory guards differ: "+timebase_invalid.bootstrap.Serialize());
        for(const auto& call:timebase_invalid.bootstrap.Get("timebase_info")->Get("call_prefix")->ArrayItems())Require(!call.Get("copied")->Bool()&&!call.Get("readback_verified")->Bool(),"Failed timebase copyout reported successful write");
        const auto entropy=commpage_probe("_entropyConsumerEntry");
        Require(entropy.bootstrap.GetString("stop_reason")=="unsupported_interrupt"&&entropy.bootstrap.Get("syscall_selector")->Int()==65535&&entropy.bootstrap.Get("entropy")->Get("calls")->Int()==9,"Native entropy guest consumer failed: "+entropy.bootstrap.Serialize());
        const auto& entropy_calls=entropy.bootstrap.Get("entropy")->Get("call_prefix")->ArrayItems();
        for(unsigned n=0;n<entropy_calls.size();++n){const int expected=n==3||n==4?22:n==5||n==6||n==7?14:0;
            Require(entropy_calls[n].Get("errno")->Int()==expected&&entropy_calls[n].Get("copied")->Bool()==(n==0||n==1||n==8),"Entropy size/copyout contract differs");}
        const auto calendar=commpage_probe("_calendarConsumerEntry");
        Require(calendar.mapped&&calendar.bootstrap.Get("syscall_selector")->Int()==65535
            &&calendar.bootstrap.Get("registers")->ArrayItems()[0].Int()==7
            &&calendar.bootstrap.Get("calendar")->Get("calls")->Int()==7,
            "Calendar direct/indirect/error/copyout width/canary/NZV consumer failed: "+calendar.bootstrap.Serialize());
        const auto& calendar_calls=calendar.bootstrap.Get("calendar")->Get("call_prefix")->ArrayItems();
        Require(calendar_calls[2].Get("errno")->Int()==14&&!calendar_calls[2].Get("timeval_copied")->Bool()&&!calendar_calls[2].Get("absolute_copied")->Bool()
            &&calendar_calls[4].Get("errno")->Int()==45&&calendar_calls[4].Get("timeval_copied")->Bool()&&!calendar_calls[4].Get("absolute_copied")->Bool()
            &&calendar_calls[5].Get("errno")->Int()==14&&calendar_calls[5].Get("timeval_copied")->Bool(),"Ordered calendar output/error semantics lost");
        const auto snapshot=commpage_probe("_calendarSnapshotEntry");
        Require(snapshot.bootstrap.Get("syscall_selector")->Int()==65535&&snapshot.bootstrap.Get("registers")->ArrayItems()[0].Int()==0
            &&snapshot.bootstrap.Get("calendar")->Get("snapshot_reads")->Int()==6&&!snapshot.bootstrap.Get("calendar")->Get("snapshot_active")->Bool(),"Inactive calendar availability/data read sequence failed");
        const auto crossing_calendar=commpage_probe("_calendarCrossEntry");Require(crossing_calendar.bootstrap.GetString("stop_reason")=="unsupported_commpage_field","Calendar cross-field read consumed unrelated state");
        Require(boot.mapped&&boot_epoch&&boot_epoch->Get("reads")->Int()==2
            &&boot.bootstrap.Get("syscall_selector")->Int()==65535
            &&boot.bootstrap.Get("registers")->ArrayItems()[0].Serialize()==boot_epoch->Get("boottime_usec")->Serialize()
            &&boot.bootstrap.Get("registers")->ArrayItems()[1].Serialize()==boot_epoch->Get("boottime_usec")->Serialize(),
            "Native calendar epoch did not reach unchanged uint64 guest reads or was unstable");
        for(const auto& symbol:std::vector<std::string>{"_unknownCommpageEntry","_crossCommpageEntry","_crossBootTimeEntry"}){
            const auto probe=commpage_probe(symbol);
            Require(probe.mapped&&probe.bootstrap.GetString("stop_reason")=="unsupported_commpage_field"
                &&probe.bootstrap.Get("syscall_selector")->Serialize()=="0"
                &&probe.bootstrap.Get("instruction_callbacks")->Serialize()=="4",
                "Unknown/cross-field commpage read consumed fabricated backing state");
        }
        for(const auto& symbol:std::vector<std::string>{"_writeCommpageEntry","_fetchCommpageEntry"}){
            const auto probe=commpage_probe(symbol);
            Require(probe.mapped&&probe.bootstrap.GetString("stop_reason")=="unsupported_memory_access"
                &&probe.bootstrap.Get("commpage")->Get("validated_reads")->Serialize()=="0",
                "Commpage guest write or execution permission accepted");
        }
        ULONGLONG absolute_before=0,continuous_before=0,absolute_after=0,continuous_after=0;
        QueryUnbiasedInterruptTimePrecise(&absolute_before);QueryInterruptTimePrecise(&continuous_before);
        const auto clock_probe=commpage_probe("_clockEntry");
        QueryUnbiasedInterruptTimePrecise(&absolute_after);QueryInterruptTimePrecise(&continuous_after);
        Require(clock_probe.mapped&&clock_probe.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&clock_probe.bootstrap.Get("syscall_selector")->Serialize()=="65535",
            "Clock trap/fallback path failed or guest clock comparison rejected: "+clock_probe.bootstrap.Serialize());
        const auto& clocks=*clock_probe.bootstrap.Get("clocks");
        const auto ticks=[&](const char* name){return std::stoull(clocks.Get(name)->Serialize());};
        Require(ticks("absolute_calls")>=3&&ticks("continuous_calls")==1&&ticks("timebase_reads")>=2
            &&ticks("absolute_first")>=absolute_before&&ticks("absolute_last")<=absolute_after
            &&ticks("absolute_last")>=ticks("absolute_first")
            &&ticks("continuous_first")>=continuous_before&&ticks("continuous_last")<=continuous_after
            &&ticks("tick_nanoseconds")==100&&clocks.Get("timebase_info_service_implemented")->Bool(),
            "Clock values did not derive native clock intervals or advertised unavailable conversion service");
        for(const auto& symbol:std::vector<std::string>{"_wrongClockSvcEntry","_wrongClockHighEntry","_clockBreakEntry"}){
            const auto probe=commpage_probe(symbol);
            Require(probe.mapped&&probe.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
                &&probe.bootstrap.Get("clocks")->Get("absolute_calls")->Serialize()=="0",
                "Wrong SVC immediate/selector or breakpoint masqueraded as clock service");
        }
        Write(thread_dyld,thread_bytes);
        const auto kdebug_probe=commpage_probe("_kdebugEntry");
        Require(kdebug_probe.mapped&&kdebug_probe.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&kdebug_probe.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&kdebug_probe.bootstrap.Get("kdebug")->Get("flags")->Serialize()=="0"
            &&kdebug_probe.bootstrap.Get("kdebug")->Get("validated_reads")->Serialize()=="1"
            &&!kdebug_probe.bootstrap.Get("kdebug")->Get("collector_registered")->Bool(),
            "Disabled Darwin tracing capability did not reach the guest consumer");
        const auto clock_fallback=commpage_probe("_clockFallbackEntry");
        const auto& fallback_clocks=*clock_fallback.bootstrap.Get("clocks");
        const auto& fallback_registers=clock_fallback.bootstrap.Get("registers")->ArrayItems();
        Require(clock_fallback.mapped&&clock_fallback.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&clock_fallback.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&!clock_fallback.bootstrap.Get("commpage")->Get("approximate_shared_time")->Bool()
            &&!fallback_clocks.Get("approximate_counter_publisher_registered")->Bool()
            &&fallback_clocks.Get("approximate_capability_reads")->Serialize()=="23"
            &&fallback_clocks.Get("absolute_calls")->Serialize()=="22"
            &&fallback_clocks.Get("continuous_calls")->Serialize()=="1"
            &&fallback_clocks.Get("timebase_reads")->Serialize()=="1"
            &&clock_fallback.bootstrap.Get("timebase_info")->Get("numerator")->Int()==100
            &&clock_fallback.bootstrap.Get("timebase_info")->Get("denominator")->Int()==1,
            "Clock capability policy did not select real trap/bias fallback: "+clock_fallback.bootstrap.Serialize());
        const auto absolute_first=std::stoull(fallback_clocks.Get("absolute_first")->Serialize());
        const auto absolute_last=std::stoull(fallback_clocks.Get("absolute_last")->Serialize());
        const auto continuous_bias=std::stoull(fallback_clocks.Get("continuous_bias")->Serialize());
        Require(absolute_first>0&&absolute_last>absolute_first
            &&std::stoull(fallback_registers[23].Serialize())==absolute_last+continuous_bias
            &&fallback_registers[24].Serialize()==fallback_clocks.Get("continuous_last")->Serialize(),
            "Approximate/continuous wrapper did not consume advancing native clocks and actual sleep bias");
        const auto& approximate_reads=fallback_clocks.Get("approximate_capability_read_prefix")->ArrayItems();
        Require(approximate_reads.size()==16,"Approximate capability trace is not bounded independently of its count");
        for(const auto& read:approximate_reads)Require(read.Get("address")->Serialize()=="68719460552"
            &&read.Get("size")->Int()==1&&read.Get("value")->Int()==0,"Approximate flag readback differs from real backing");
        for(const auto* symbol:{"_clockCapWideEntry","_clockCapRoEntry","_clockRawApproxEntry","_clockRawHardwareEntry","_clockRawTimebaseEntry","_clockCapNextEntry"}){
            const auto negative=commpage_probe(symbol);
            Require(negative.mapped&&negative.bootstrap.GetString("stop_reason")=="unsupported_commpage_field"
                &&negative.bootstrap.Get("clocks")->Get("approximate_capability_reads")->Serialize()=="0",
                std::string("Disabled clock exposed raw timestamp/unknown/undefined RO bytes: ")+symbol);
        }
        for(const auto* symbol:{"_clockCapWriteEntry","_clockCapFetchEntry"}){
            const auto negative=commpage_probe(symbol);
            Require(negative.mapped&&negative.bootstrap.GetString("stop_reason")=="unsupported_memory_access"
                &&negative.bootstrap.Get("memory_address")->Serialize()=="68719460552",
                std::string("Approximate clock flag allowed guest mutation or instruction fetch: ")+symbol);
        }
        const auto atm_probe=commpage_probe("_atmPolicyEntry");
        const auto& atm=*atm_probe.bootstrap.Get("atm_logging");
        Require(atm_probe.mapped&&atm_probe.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&atm_probe.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&atm.Get("diagnostic_config")->Serialize()=="256"&&!atm.Get("collector_registered")->Bool()
            &&!atm.Get("configuration_mutation_supported")->Bool()&&atm.Get("legacy_mapping_only")->Bool()
            &&atm.Get("validated_reads")->Serialize()=="28"&&atm.Get("read_prefix")->ArrayItems().size()==16
            &&atm_probe.bootstrap.Get("kdebug")->Get("validated_reads")->Serialize()=="1"
            &&atm_probe.bootstrap.Get("multiuser")->Get("validated_reads")->Serialize()=="1",
            "Disabled ATM provider policy, original bit8 branch, LE subwords or bounded tracing failed: "+atm_probe.bootstrap.Serialize());
        const std::array<unsigned,8> atm_widths{4,1,1,1,1,2,2,2},atm_offsets{0,0,1,2,3,0,2,1};
        const std::array<unsigned,8> atm_values{256,0,1,0,0,256,0,1};
        for(std::size_t i=0;i<atm.Get("read_prefix")->ArrayItems().size();++i){
            const auto& item=atm.Get("read_prefix")->ArrayItems()[i];
            const auto slot=i<8?i:0;
            Require(item.Get("address")->Serialize()==std::to_string(0xfffffc104ULL+atm_offsets[slot])
                &&item.Get("size")->Int()==atm_widths[slot]&&item.Get("value")->Int()==atm_values[slot],
                "ATM trace did not record the guest's actual LE subword read");
        }
        for(const auto* symbol:{"_atmCrossReadEntry","_atmLeftCrossEntry","_atmRightCrossEntry","_atmRoAliasEntry","_atmUnknownEntry"}){
            const auto negative=commpage_probe(symbol);
            Require(negative.mapped&&negative.bootstrap.GetString("stop_reason")=="unsupported_commpage_field"
                &&negative.bootstrap.Get("atm_logging")->Get("validated_reads")->Serialize()=="0",
                std::string("ATM field admitted cross-field/unknown/undefined RO alias: ")+symbol);
        }
        for(const auto* symbol:{"_atmWriteEntry","_atmFetchEntry"}){
            const auto negative=commpage_probe(symbol);
            Require(negative.mapped&&negative.bootstrap.GetString("stop_reason")=="unsupported_memory_access"
                &&negative.bootstrap.Get("memory_address")->Serialize()=="68719460612"
                &&negative.bootstrap.Get("atm_logging")->Get("validated_reads")->Serialize()=="0",
                std::string("ATM policy allowed guest mutation or execution: ")+symbol);
        }
        const auto cross_kdebug=commpage_probe("_crossKdebugEntry");
        Require(cross_kdebug.mapped&&cross_kdebug.bootstrap.GetString("stop_reason")=="unsupported_commpage_field"
            &&cross_kdebug.bootstrap.Get("instruction_callbacks")->Serialize()=="4"
            &&cross_kdebug.bootstrap.Get("kdebug")->Get("validated_reads")->Serialize()=="0",
            "Kdebug crossing read exposed unknown adjacent state");
        const auto write_kdebug=commpage_probe("_writeKdebugEntry");
        Require(write_kdebug.mapped&&write_kdebug.bootstrap.GetString("stop_reason")=="unsupported_memory_access"
            &&write_kdebug.bootstrap.Get("instruction_callbacks")->Serialize()=="4",
            "Guest changed kernel-debug capability flags");
        Write(thread_dyld,thread_bytes);
        const auto task_probe=commpage_probe("_taskEntry");
        Require(task_probe.mapped&&task_probe.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&task_probe.bootstrap.Get("syscall_selector")->Serialize()=="65535", "Task port guest equality/validity check failed");
        const auto& task_state=*task_probe.bootstrap.Get("mach_task");
        Require(task_state.Get("self_calls")->Serialize()=="2"&&task_state.Get("send_user_refs")->Serialize()=="3"
            &&task_state.Get("pinned")->Bool()&&task_state.Get("port_type")->Serialize()=="65536"
            &&task_state.Get("resolves_to_guest")->Bool()&&task_state.Get("invalid_names_rejected")->Bool()
            &&task_state.Get("mapped_images")->Serialize()==std::to_string(task_probe.images)
            &&task_state.Get("call_prefix")->ArrayItems().size()==2,
            "Actual task binding/namespace/send references did not reach the bootstrap consumer");
        for(const auto& call:task_state.Get("call_prefix")->ArrayItems())
            Require(call.Get("port")->Serialize()==task_state.Get("self_name")->Serialize(),"Repeated self port was not coalesced");
        const auto wrong_task=commpage_probe("_wrongTaskSvcEntry");
        Require(wrong_task.mapped&&wrong_task.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&wrong_task.bootstrap.Get("mach_task")->Get("self_calls")->Serialize()=="0"
            &&wrong_task.bootstrap.Get("mach_task")->Get("send_user_refs")->Serialize()=="1",
            "Wrong SVC modified task rights or returned a task port");
        const auto task_loop=commpage_probe("_taskLoopEntry");
        Require(task_loop.mapped&&(task_loop.bootstrap.GetString("stop_reason")=="instruction_budget"
            ||task_loop.bootstrap.GetString("stop_reason")=="timeout")
            &&std::stoull(task_loop.bootstrap.Get("mach_task")->Get("self_calls")->Serialize())>0xffff
            &&task_loop.bootstrap.Get("mach_task")->Get("send_user_refs")->Serialize()=="65535",
            "Task copyout did not exercise/peg the 16-bit reference count within execution budget");
        Write(thread_dyld,thread_bytes);
        const auto fresh_task=commpage_probe("_taskEntry");
        Require(fresh_task.mapped&&fresh_task.bootstrap.Get("mach_task")->Get("send_user_refs")->Serialize()=="3"
            &&fresh_task.bootstrap.Get("mach_task")->Get("resolves_to_guest")->Bool(),"Task namespace leaked rights across guest lifetimes");
        Write(thread_dyld,thread_bytes);
        const auto port_probe=commpage_probe("_portEntry");
        Require(port_probe.mapped&&port_probe.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&port_probe.bootstrap.Get("syscall_selector")->Serialize()=="65535","Reply/thread/special port guest consumer failed");
        const auto& ports=*port_probe.bootstrap.Get("mach_ports");
        Require(ports.Get("reply_calls")->Serialize()=="2"&&ports.Get("thread_calls")->Serialize()=="2"
            &&ports.Get("special_reply_calls")->Serialize()=="2"&&ports.Get("namespace_entries")->Serialize()=="6"
            &&ports.Get("receive_rights")->Serialize()=="4"&&ports.Get("bound_special_replies")->Serialize()=="1"
            &&ports.Get("thread_binding_agrees")->Bool()&&!ports.Get("ipc_service_implemented")->Bool(),
            "Port ownership, receive rights or special reply binding did not match executed consumer");
        const auto thread_id=port_probe.bootstrap.Get("thread_context")->Get("current_thread_id")->Serialize();
        std::size_t reply_entries=0,thread_entries=0,special_entries=0;
        for(const auto& port:ports.Get("entry_prefix")->ArrayItems()){
            Require(port.Get("resolves_actual_owner")->Bool()&&port.Get("invalid_generation_rejected")->Bool()
                &&port.Get("queue_size")->Serialize()=="0","Port name/queue did not bind actual namespace");
            const auto* binding=port.Get("bound_thread_id");
            Require(binding!=nullptr,"Port diagnostics omit actual thread-object binding");
            const auto expected_binding=port.GetString("object")=="thread"||port.Get("bound_to_thread")->Bool()?thread_id:"0";
            Require(binding->Serialize()==expected_binding,"Port binding does not resolve its actual guest thread");
            if(port.GetString("object")=="reply"){
                ++reply_entries;Require(port.Get("type")->Serialize()=="131072"&&port.Get("send_refs")->Serialize()=="0"
                    &&!port.Get("resolves_as_task_send")->Bool()&&!port.Get("resolves_as_thread_send")->Bool(),"Reply port fabricated a send/control right");
            }else if(port.GetString("object")=="thread"){
                ++thread_entries;Require(port.Get("type")->Serialize()=="65536"&&port.Get("send_refs")->Serialize()=="2"
                    &&port.Get("resolves_as_thread_send")->Bool()&&!port.Get("resolves_as_task_send")->Bool()
                    &&!port.Get("pinned")->Bool(),"Raw initial thread control right did not coalesce or alias-check");
            }else if(port.GetString("object")=="special_reply"){
                ++special_entries;Require(port.Get("type")->Serialize()=="196608"&&port.Get("send_refs")->Serialize()=="1"
                    &&!port.Get("resolves_as_thread_send")->Bool(),"Special reply did not own send+receive rights");
            }
        }
        Require(reply_entries==2&&thread_entries==1&&special_entries==2,"Port allocation reused or lost a live namespace entry");
        const auto wrong_port=commpage_probe("_wrongPortSvcEntry");
        Require(wrong_port.mapped&&wrong_port.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&wrong_port.bootstrap.Get("mach_ports")->Get("namespace_entries")->Serialize()=="1"
            &&wrong_port.bootstrap.Get("mach_ports")->Get("reply_calls")->Serialize()=="0","Wrong SVC allocated a reply port");
        const auto fresh_ports=commpage_probe("_portEntry");
        Require(fresh_ports.mapped&&fresh_ports.bootstrap.Get("mach_ports")->Get("namespace_entries")->Serialize()=="6"
            &&fresh_ports.bootstrap.Get("mach_ports")->Get("bound_special_replies")->Serialize()=="1","Guest destruction leaked port/thread state");
        Write(thread_dyld,thread_bytes);
        const auto rights=commpage_probe("_machRightsEntry");
        Require(rights.mapped&&rights.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&rights.bootstrap.Get("syscall_selector")->Serialize()=="65535","Mach rights assembly consumer failed: "+rights.bootstrap.Serialize());
        const auto& right_ports=*rights.bootstrap.Get("mach_ports");
        Require(right_ports.Get("mod_refs_calls")->Serialize()=="10"&&right_ports.Get("deallocate_calls")->Serialize()=="5"
            &&right_ports.Get("thread_calls")->Serialize()=="3"&&right_ports.Get("receive_rights")->Serialize()=="0"
            &&right_ports.Get("special_reply_name")->Serialize()=="0"&&!right_ports.Get("guard_delivery_implemented")->Bool(),
            "Mach lifetime counters/binding differ");
        const auto& right_entries=right_ports.Get("entry_prefix")->ArrayItems();
        Require(right_entries.size()==6&&right_entries[1].Get("type")->Serialize()=="0"
            &&right_entries[2].Get("type")->Serialize()=="0"&&right_entries[3].Get("type")->Serialize()=="0"
            &&right_entries[4].Get("type")->Serialize()=="0"&&right_entries[4].Get("dead_refs")->Serialize()=="0"
            &&right_entries[5].Get("send_refs")->Serialize()=="1"&&right_entries[5].Get("resolves_as_thread_send")->Bool(),
            "Mach retired/dead name state or thread reacquisition differs");
        for(std::size_t i=1;i<right_entries.size();++i){
            const auto* binding=right_entries[i].Get("bound_thread_id");
            Require(binding&&binding->Serialize()==(i==5?rights.bootstrap.Get("thread_context")->Get("current_thread_id")->Serialize():"0"),
                "Retired thread/special-reply right retained a thread object or reacquisition lost it");
        }
        const auto& right_calls=right_ports.Get("rights_call_prefix")->ArrayItems();
        Require(right_calls.size()==15&&right_calls[12].Get("after_refs")->Serialize()=="65535"
            &&right_calls[13].Get("after_refs")->Serialize()=="65535"&&right_calls[14].Get("after_refs")->Serialize()=="0",
            "Mach pegged reference count semantics differ");
        const auto pinned=commpage_probe("_machPinnedEntry");
        Require(pinned.mapped&&pinned.bootstrap.GetString("stop_reason")=="unsupported_mach_port_guard"
            &&pinned.bootstrap.Get("mach_task")->Get("send_user_refs")->Serialize()=="2"
            &&pinned.bootstrap.Get("mach_ports")->Get("mod_refs_calls")->Serialize()=="0",
            "Pinned last right silently removed or guard delivery fabricated");
        const auto bad_target=commpage_probe("_machBadTargetEntry");
        Require(bad_target.mapped&&bad_target.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&bad_target.bootstrap.Get("mach_ports")->Get("rights_call_prefix")->ArrayItems()[0].Get("result")->Serialize()=="268435459",
            "Mach fast-trap invalid destination differs");
        for(const auto* symbol:{"_machWrongSvcEntry","_machHighSelectorEntry"}){
            const auto wrong=commpage_probe(symbol);
            Require(wrong.mapped&&wrong.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
                &&wrong.bootstrap.Get("mach_ports")->Get("mod_refs_calls")->Serialize()=="0",
                "Invalid Mach SVC/selector mutated namespace");}
        for(const auto* symbol:{"_vmNoneEntry","_migVmNoneEntry"}){
            const auto probe=commpage_probe(symbol);
            Require(probe.mapped&&probe.bootstrap.GetString("stop_reason")=="unsupported_memory_access"
                &&probe.bootstrap.Get("memory_type")->Serialize()=="22",
                std::string("VM_PROT_NONE did not reject guest write: ")+symbol+" "+probe.diagnostic);
        }
        const auto bad_destination=commpage_probe("_migBadDestinationEntry");
        Require(bad_destination.bootstrap.Get("syscall_selector")->Serialize()=="65535",
            "MIG map accepted an invalid task destination: "+bad_destination.diagnostic);
        const auto memory_object=commpage_probe("_migMemoryObjectEntry");
        Require(memory_object.bootstrap.GetString("stop_reason")=="unsupported_mach_vm_memory_object",
            "Unimplemented memory object became anonymous memory: "+memory_object.diagnostic);
        const auto open_observation=commpage_probe("_unsupportedOpenEntry");
        Require(open_observation.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&open_observation.bootstrap.Get("open_path_terminated")->Bool()
            &&open_observation.bootstrap.GetString("open_path")=="/owned/guest-file",
            "Missing original file open did not report ENOENT or lost its pathname");
        const auto sandbox=commpage_probe("_sandboxEntry");
        Require(sandbox.mapped&&sandbox.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&sandbox.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&sandbox.bootstrap.Get("sandbox")->GetString("profile_state")=="none"
            &&sandbox.bootstrap.Get("sandbox")->Get("call_prefix")->ArrayItems().size()==16,
            "Sandbox self PID/copyout/carry/read-only fault or bounded trace failed: "+sandbox.diagnostic);
        const auto unknown_sandbox=commpage_probe("_sandboxUnknownEntry");
        Require(unknown_sandbox.mapped&&unknown_sandbox.bootstrap.GetString("stop_reason")=="unsupported_sandbox_check"
            &&unknown_sandbox.bootstrap.Get("sandbox")->Get("call_prefix")->ArrayItems()[0].Get("decision")->Serialize()==std::to_string(UINT64_MAX),
            "Unknown operation received a fabricated Sandbox decision");
        const auto profile_sandbox=commpage_probe("_sandboxProfileEntry");
        Require(profile_sandbox.mapped&&profile_sandbox.bootstrap.GetString("stop_reason")=="unsupported_mac_policy_call",
            "Unsupported profile installation silently succeeded");
        const auto unavailable=commpage_probe("_sandboxUnavailableEntry");
        Require(unavailable.mapped&&unavailable.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&unavailable.bootstrap.Get("syscall_selector")->Serialize()=="555"
            &&unavailable.bootstrap.Get("sandbox")->Get("call_prefix")->ArrayItems()[0].Get("decision")->Serialize()=="0",
            "Sandbox permission was confused with BSD implementation availability");
        Require(sandbox.bootstrap.Get("sandbox")->Get("pid")->Serialize()!=unavailable.bootstrap.Get("sandbox")->Get("pid")->Serialize(),
            "Independent live guest processes reused their PID");
        const auto sysctl=commpage_probe("_sysctlEntry");
        Require(sysctl.mapped&&sysctl.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&sysctl.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&sysctl.bootstrap.Get("sysctl")->Get("calls")->Serialize()=="30"
            &&sysctl.bootstrap.Get("sysctl")->Get("call_prefix")->ArrayItems().size()==16,
            "Sysctl registry/MIB/sizing/permissions/error/carry/indirect ABI failed: "+sysctl.diagnostic);
        const auto absent_policy=commpage_probe("_missingMacPolicyEntry");
        Require(absent_policy.mapped&&absent_policy.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&absent_policy.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&absent_policy.bootstrap.Get("sandbox")->Get("registered_policies")->ArrayItems().size()==2,
            "Absent MAC policy error/buffer preservation/indirect ABI/bounds failed: "+absent_policy.diagnostic);
        for(const auto& call:absent_policy.bootstrap.Get("sandbox")->Get("call_prefix")->ArrayItems())
            Require(call.Get("errno")->Serialize()=="103"&&!call.Get("policy_registered")->Bool()&&!call.Get("decision_produced")->Bool(),
                "Absent MAC policy fabricated a callback result");
        for(const auto& symbol:std::vector<std::string>{"_fatalObservationEntry","_fatalPayloadEntry","_fatalBadPointerEntry"}){
            const auto fatal=commpage_probe(symbol);
            Require(fatal.mapped&&fatal.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
                &&fatal.bootstrap.Get("syscall_selector")->Serialize()=="65535",
                "Fatal diagnostic observer changed guest execution: "+fatal.diagnostic);
            const auto& observation=*fatal.bootstrap.Get("fatal_api_observations");
            Require(observation.Get("observational_only")->Bool()&&!observation.Get("capture_failed")->Bool()
                &&observation.Get("calls")->ArrayItems().size()==1,"Original export did not propagate to fatal observer");
            const auto& call=observation.Get("calls")->ArrayItems()[0];
            if(symbol=="_fatalBadPointerEntry")Require(!call.Get("readable")->Bool()&&!call.Get("terminated")->Bool()
                &&call.GetString("reason").empty(),"Fatal observer substituted unreadable message");
            else Require(call.Get("readable")->Bool()&&call.Get("terminated")->Bool()
                &&call.GetString("reason")=="Owned fatal reason observation","Fatal observer copied wrong API argument");
        }
        std::string vm_tail_source(200123,'\0');
        for(std::size_t i=0;i<vm_tail_source.size();++i)vm_tail_source[i]=static_cast<char>((i*31+i/8192)%251);
        Write(thread_tree/"process/vm-eof-source",vm_tail_source);
        const auto vm_tail_hash=Sha256File(thread_tree/"process/vm-eof-source");
        const auto vm_geometry=commpage_probe("_mmapGeometryEntry");
        Require(vm_geometry.mapped&&vm_geometry.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&vm_geometry.bootstrap.Get("syscall_selector")->Int()==65535
            &&vm_geometry.bootstrap.Get("file_mappings")->Get("calls")->Int()==4
            &&vm_geometry.bootstrap.Get("vm_regions")->Get("region_count")->Int()==0
            &&Sha256File(thread_tree/"process/vm-eof-source")==vm_tail_hash,
            "Final partial EOF page, legacy fixed offset/remainder, UNIX03 error, unchanged source and independent mapping lifetimes failed: "+vm_geometry.bootstrap.Serialize());
        const auto mmap_consumer=commpage_probe("_mmapConsumerEntry");
        Require(mmap_consumer.mapped&&mmap_consumer.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&mmap_consumer.bootstrap.Get("file_mappings")->Get("calls")->Serialize()=="2"
            &&mmap_consumer.bootstrap.Get("original_files")->Get("bytes_read")->Serialize()=="8"
            &&mmap_consumer.bootstrap.Get("original_files")->Get("closes")->Serialize()=="1",
            "Original file mmap bytes/COW/cursor/closed-fd/partial-unmap/direct-indirect ABI failed: "+mmap_consumer.diagnostic);
        const auto mmap_write_denied=commpage_probe("_mmapWriteDeniedEntry");
        Require(mmap_write_denied.mapped&&mmap_write_denied.bootstrap.GetString("stop_reason")=="unsupported_memory_access"
            &&mmap_write_denied.bootstrap.Get("file_mappings")->Get("calls")->Serialize()=="1"
            &&mmap_write_denied.bootstrap.Get("memory_type")->Serialize()=="22",
            "mmap protection mask/read/WRITE protection failed: "+mmap_write_denied.diagnostic);
        const auto mmap_errors=commpage_probe("_mmapErrorConsumerEntry");
        Require(mmap_errors.mapped&&mmap_errors.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&mmap_errors.bootstrap.Get("file_mappings")->Get("calls")->Serialize()=="120"
            &&mmap_errors.bootstrap.Get("file_mappings")->Get("call_prefix")->ArrayItems().size()==16,
            "mmap invalid-fd/zero-length/offset/negative-offset/EOF/unsupported-policy errors or carry ABI failed: "+mmap_errors.diagnostic);
        const auto mmap_hole=commpage_probe("_mmapPartialHoleEntry");
        Require(mmap_hole.mapped&&mmap_hole.bootstrap.GetString("stop_reason")=="unsupported_memory_access"
            &&mmap_hole.bootstrap.Get("file_mappings")->Get("calls")->Serialize()=="1"
            &&mmap_hole.bootstrap.Get("memory_type")->Serialize()=="19",
            "Partial file munmap falsely acknowledged retained readable memory: "+mmap_hole.diagnostic);
        const auto write_consumer=commpage_probe("_writeConsumerEntry");
        Require(write_consumer.mapped&&write_consumer.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&write_consumer.bootstrap.Get("original_files")->Get("write_calls")->Serialize()=="60"
            &&write_consumer.bootstrap.Get("original_files")->Get("bytes_written")->Serialize()=="320",
            "Real inherited stderr write counts/memory/direct-indirect/carry/NZV/errors/close ABI failed: "+write_consumer.diagnostic);
        const auto& written_output=write_consumer.bootstrap.Get("original_files")->Get("output_descriptors")->ArrayItems()[0];
        std::string expected_output;for(unsigned i=0;i<40;++i)expected_output+="6f662d7772697465";
        Require(written_output.Get("closed")->Bool()&&written_output.GetString("prefix_hex")==expected_output,
            "Production inherited stderr did not preserve actual guest bytes or close state");
        // This consumer tests the linker's embedded CodeDirectory. The ABI
        // variants above are owned header-mutation fixtures, whose signatures
        // intentionally no longer match. Use the original signed ARM64 fixture
        // here; preserve every signature/trust/error assertion below.
        Write(thread_main,signed_arm64_main);
        const auto signature_consumer=commpage_probe("_signatureConsumerEntry");
        Write(thread_main,owned_main_abi);
        Require(signature_consumer.mapped&&signature_consumer.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&signature_consumer.bootstrap.Get("file_signatures")->Get("calls")->Serialize()=="140"
            &&signature_consumer.bootstrap.Get("original_files")->Get("signature_registrations")->ArrayItems().size()==1,
            "File signature direct/indirect/result width/error preservation guest contract failed: "+signature_consumer.diagnostic);
        Require(signature_consumer.bootstrap.Get("library_validation")->Get("calls")->Serialize()=="121",
            "Library-validation consumer error/message/optional-buffer contract failed");
        const auto& library_first=signature_consumer.bootstrap.Get("library_validation")->Get("call_prefix")->ArrayItems()[0];
        Require(library_first.Get("source_registered")->Bool()&&!library_first.Get("validation_required")->Bool()
            &&library_first.Get("message_bytes")->Serialize()=="0"&&!library_first.Get("platform_authority")->Bool(),
            "Native library policy ignored source identity or fabricated task trust");
        const auto& signature_first=signature_consumer.bootstrap.Get("file_signatures")->Get("call_prefix")->ArrayItems()[0];
        Require(signature_first.Get("ad_hoc")->Bool()&&signature_first.Get("copied")->Bool()
            &&!signature_first.Get("certificate_chain_trusted")->Bool()&&!signature_first.Get("platform_authority")->Bool(),
            "Owned guest registration fabricated certificate trust");
        const auto loader_policy_consumer=commpage_probe("_loaderPolicyConsumerEntry");
        Require(loader_policy_consumer.mapped&&loader_policy_consumer.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&loader_policy_consumer.bootstrap.Get("loader_policy")->Get("flags")->Serialize()=="1"
            &&!loader_policy_consumer.bootstrap.Get("loader_policy")->Get("signature_authority")->Bool()
            &&loader_policy_consumer.bootstrap.Get("sandbox")->Get("call_prefix")->ArrayItems().size()==16,
            "Native loader policy direct/indirect/query/bounds/copyout/carry/NZV contract failed: "+loader_policy_consumer.diagnostic);
        const auto loader_policy_mutation=commpage_probe("_loaderPolicyMutationEntry");
        Require(loader_policy_mutation.mapped&&loader_policy_mutation.bootstrap.GetString("stop_reason")=="unsupported_mac_policy_call",
            "Unimplemented AMFI operation acknowledged success: "+loader_policy_mutation.diagnostic);
        const auto metadata_consumer=commpage_probe("_metadataConsumerEntry");
        Require(metadata_consumer.mapped&&metadata_consumer.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&metadata_consumer.bootstrap.Get("file_metadata")->Get("calls")->Serialize()=="160"
            &&metadata_consumer.bootstrap.Get("file_metadata")->Get("call_prefix")->ArrayItems().size()==16
            &&metadata_consumer.bootstrap.Get("original_files")->Get("opens")->Serialize()=="1"
            &&metadata_consumer.bootstrap.Get("original_files")->Get("closes")->Serialize()=="1",
            "stat64/fstat64 actual metadata/layout, direct/indirect/copyout/error or descriptor isolation failed: "+metadata_consumer.diagnostic);
        const auto code_sign_consumer=commpage_probe("_codeSignConsumerEntry");
        Require(code_sign_consumer.mapped&&code_sign_consumer.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&code_sign_consumer.bootstrap.Get("code_signing")->Get("calls")->Serialize()=="160"
            &&code_sign_consumer.bootstrap.Get("code_signing")->Get("call_prefix")->ArrayItems().size()==16
            &&!code_sign_consumer.bootstrap.Get("code_signing")->Get("signature_validated")->Bool()
            &&!code_sign_consumer.bootstrap.Get("code_signing")->Get("platform_binary")->Bool(),
            "Native task CS status/PID/copyout/null/usersize/direct-indirect ABI failed: "+code_sign_consumer.diagnostic);
        const auto code_sign_mutation=commpage_probe("_codeSignMutationEntry");
        Require(code_sign_mutation.mapped&&code_sign_mutation.bootstrap.GetString("stop_reason")=="unsupported_codesign_operation"
            &&code_sign_mutation.bootstrap.Get("code_signing")->Get("calls")->Serialize()=="0",
            "Unimplemented code-sign mutation silently succeeded: "+code_sign_mutation.diagnostic);
        const auto identity_consumer=commpage_probe("_identityPathConsumerEntry");
        Require(identity_consumer.mapped&&identity_consumer.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&identity_consumer.bootstrap.Get("identity_paths")->Get("calls")->Serialize()=="100"
            &&identity_consumer.bootstrap.Get("identity_paths")->Get("call_prefix")->ArrayItems().size()==16,
            "Identity syscall absence/bounds/copyin/indirect ABI or guest buffer preservation failed: "+identity_consumer.diagnostic);
        const auto descriptor_aliases=commpage_probe("_descriptorAliasesConsumerEntry");
        Require(descriptor_aliases.mapped&&descriptor_aliases.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&descriptor_aliases.bootstrap.Get("syscall_selector")->Int()==65535
            &&descriptor_aliases.bootstrap.Get("instruction_callbacks")->Int()<2000
            &&descriptor_aliases.bootstrap.Get("original_files")->Get("opens")->Int()==2
            &&descriptor_aliases.bootstrap.Get("original_files")->Get("bytes_read")->Int()==20
            &&descriptor_aliases.bootstrap.Get("original_files")->Get("descriptors")->ArrayItems().empty(),
            "Guest dup/dup2 shared cursor/source lifetime/FD flags/direct-indirect errno NZCV consumer failed: "+descriptor_aliases.bootstrap.Serialize());
        const auto file_consumer=commpage_probe("_fileConsumerEntry");
        Require(file_consumer.mapped&&file_consumer.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&file_consumer.bootstrap.Get("original_files")->Get("opens")->Serialize()=="1"
            &&file_consumer.bootstrap.Get("original_files")->Get("bytes_read")->Serialize()=="8",
            "Original-file catalog or guest read/pread/seek/close ABI propagation failed: "+file_consumer.diagnostic);
        Require(CreateSymbolicLinkW((thread_tree/"process/alias").c_str(),thread_main.c_str(),SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE),
            "Owned original file symlink fixture failed");
        const auto directory_consumer=commpage_probe("_directoryConsumerEntry");
        Require(directory_consumer.mapped&&directory_consumer.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&directory_consumer.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&directory_consumer.bootstrap.Get("original_files")->Get("opens")->Serialize()=="20"
            &&directory_consumer.bootstrap.Get("original_files")->Get("closes")->Serialize()=="20",
            "Mounted directory/indirect ABI/F_GETPATH/flags/read error propagation failed: "+directory_consumer.diagnostic);
        const auto openat_consumer=commpage_probe("_openAtConsumerEntry");
        Require(openat_consumer.mapped&&openat_consumer.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&openat_consumer.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&openat_consumer.bootstrap.Get("original_files")->Get("opens")->Serialize()=="43"
            &&openat_consumer.bootstrap.Get("original_files")->Get("closes")->Serialize()=="43"
            &&openat_consumer.bootstrap.Get("original_files")->Get("bytes_read")->Serialize()=="80"
            &&openat_consumer.bootstrap.Get("original_files")->GetString("working_directory")=="/",
            "openat directory/CWD/absolute/indirect/memory/error ABI failed: "+openat_consumer.diagnostic);
        const auto file_closure=DarwinClosure::Inspect("/process/main",{},{thread_tree});
        Require(file_closure.StrongImagesResolved(),"Owned original-file closure failed");
        DarwinFiles owned_files(file_closure);
        Require(owned_files.Open("/process/Main",0).error==2&&owned_files.Open("/../process/main",0).error==22,
            "Original virtual file namespace ignored case or escaped root");
        Require(owned_files.Open("/process/main",1).error==30&&owned_files.Open("/process/main",0x200).error==30,
            "Immutable original input accepted writable/create open");
        Require(file_closure.original_directories.contains("/")&&file_closure.original_directories.contains("/empty"),
            "Mount indexing lost root or empty directory");
        const auto root_directory=owned_files.Open("/",0x21100000);
        const auto empty_directory=owned_files.Open("/empty",0x20100000);
        Require(!root_directory.error&&!empty_directory.error&&root_directory.value!=empty_directory.value,
            "Native directory objects or namespace allocation failed");
        std::string directory_path;
        std::array<char,1> unchanged_directory_byte{'Q'};
        Require(!owned_files.Path(static_cast<int>(root_directory.value),directory_path).error&&directory_path=="/"
            &&owned_files.ReadCapacity(static_cast<int>(root_directory.value),1).error==21
            &&owned_files.Read(static_cast<int>(root_directory.value),unchanged_directory_byte).error==21
            &&unchanged_directory_byte[0]=='Q'&&owned_files.Seek(static_cast<int>(root_directory.value),0,0).error==45,
            "Directory handle masqueraded as regular file bytes/cursor or host-root path");
        Require(owned_files.Open("/process/main",0x00100000).error==20
            &&owned_files.Open("/missing",0x20100000).error==2
            &&owned_files.Open("/process/main/../main",0x20000000).error==20
            &&owned_files.Open("/process/main/",0).error==20
            &&owned_files.Open("/missing/../process",0).error==2,
            "Directory/type/component lookup errors were normalized away");
        Require(owned_files.Open("/process/alias",0x100).error==62
            &&owned_files.Open("/process/alias",0x20000000).error==62
            &&owned_files.Open("/process/alias/../main",0x20000000).error==62,
            "NOFOLLOW/NOFOLLOW_ANY admitted symbolic link or erased it via parent traversal");
        const auto followed_alias=owned_files.Open("/process/alias",0x20000);
        Require(!followed_alias.error&&!owned_files.Path(static_cast<int>(followed_alias.value),directory_path).error
            &&directory_path=="/process/main","Allowed original symlink/NOCTTY lost canonical identity");
        Require(!owned_files.Close(static_cast<int>(followed_alias.value)).error
            &&!owned_files.Close(static_cast<int>(root_directory.value)).error
            &&!owned_files.Close(static_cast<int>(empty_directory.value)).error
            &&owned_files.Path(static_cast<int>(root_directory.value),directory_path).error==9,
            "Closed directory descriptor retained a live binding");
        const auto original_fd=owned_files.Open("/process/./main",0x01000000);
        Require(!original_fd.error&&owned_files.Fcntl(static_cast<int>(original_fd.value),1,0).value==1,
            "Original lease or close-on-exec descriptor state missing");
        std::string canonical_file_path;Require(!owned_files.Path(static_cast<int>(original_fd.value),canonical_file_path).error&&canonical_file_path=="/process/main","F_GETPATH did not bind canonical guest identity");
        DarwinFileMetadata path_metadata,fd_metadata,alias_metadata;
        const auto before_stat=owned_files.ToJson().Serialize();
        Require(!owned_files.Stat("process/main",path_metadata).error
            &&!owned_files.Fstat(static_cast<int>(original_fd.value),fd_metadata).error
            &&!owned_files.Stat("/process/alias",alias_metadata).error
            &&path_metadata.inode==fd_metadata.inode&&path_metadata.inode==alias_metadata.inode
            &&path_metadata.device==fd_metadata.device&&path_metadata.size==std::int64_t(fs::file_size(thread_main))
            &&owned_files.ToJson().Serialize()==before_stat,
            "stat/fstat/alias failed to derive same held source metadata or altered descriptor state");
        Require(owned_files.Stat("/process/main/../main",path_metadata).error==20
            &&owned_files.Stat("/missing/../process/main",path_metadata).error==2
            &&owned_files.Stat("",path_metadata).error==2
            &&owned_files.Stat("/",path_metadata).error==45
            &&owned_files.Fstat(999,fd_metadata).error==9&&!fd_metadata.inode,
            "Metadata lookup normalized away type/missing errors or fabricated directory/bad-fd metadata");
        const auto blocked_writer=CreateFileW(thread_main.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
        Require(blocked_writer==INVALID_HANDLE_VALUE,"Open original descriptor did not hold a stable read-only lease");
        std::array<char,8> file_bytes{};
        Require(owned_files.Read(static_cast<int>(original_fd.value),file_bytes,0).value==8
            &&std::string(file_bytes.data(),file_bytes.size())==Read(thread_main).substr(0,8)
            &&owned_files.Seek(static_cast<int>(original_fd.value),0,1).value==0,
            "Positioned original read changed descriptor cursor or source bytes");
        Require(owned_files.Seek(static_cast<int>(original_fd.value),-1,0).error==22
            &&owned_files.Seek(static_cast<int>(original_fd.value),INT64_MIN,1).error==22
            &&owned_files.Fcntl(static_cast<int>(original_fd.value),97,0).error==45,
            "Invalid seek or unsupported code-signing command acknowledged success");
        const auto at_directory=owned_files.Open("/process",0x00100000);
        Require(!at_directory.error,"Descriptor-relative base directory is not owned");
        const auto at_file=owned_files.OpenAt(static_cast<int>(at_directory.value),"main",0x20000000);
        std::string at_path;
        Require(!at_file.error&&!owned_files.Path(static_cast<int>(at_file.value),at_path).error&&at_path=="/process/main",
            "openat did not derive canonical file path from owned directory");
        Require(owned_files.OpenAt(static_cast<int>(at_file.value),"main",0).error==20
            &&owned_files.OpenAt(999,"process/main",0).error==9
            &&owned_files.OpenAt(static_cast<int>(at_directory.value),"missing",0).error==2
            &&owned_files.OpenAt(static_cast<int>(at_directory.value),"alias",0x20000000).error==62,
            "openat ignored descriptor/type/missing/link semantics");
        const auto ignored_base=owned_files.OpenAt(999,"/process/main",0);
        Require(!ignored_base.error&&!owned_files.Close(static_cast<int>(ignored_base.value)).error,
            "Absolute openat incorrectly depended on invalid dirfd");
        const auto parent_file=owned_files.OpenAt(static_cast<int>(at_directory.value),"../usr/lib/dyld",0);
        Require(!parent_file.error&&!owned_files.Path(static_cast<int>(parent_file.value),at_path).error&&at_path=="/usr/lib/dyld",
            "Valid descriptor-relative parent traversal failed");
        Require(!owned_files.Close(static_cast<int>(parent_file.value)).error
            &&!owned_files.Close(static_cast<int>(at_file.value)).error
            &&!owned_files.Close(static_cast<int>(at_directory.value)).error
            &&owned_files.OpenAt(static_cast<int>(at_directory.value),"main",0).error==9,
            "Closed openat directory remained a live namespace base");
        DarwinFiles launch_directory_files(file_closure,{},"/process");
        const auto cwd_file=launch_directory_files.OpenAt(-2,"main",0);
        Require(!cwd_file.error&&!launch_directory_files.Path(static_cast<int>(cwd_file.value),at_path).error&&at_path=="/process/main"
            &&launch_directory_files.ToJson().GetString("working_directory")=="/process",
            "Guest launch directory did not propagate automatically through AT_FDCWD");
        const auto relative_open=launch_directory_files.Open("main",0);
        Require(!relative_open.error&&!launch_directory_files.Close(static_cast<int>(relative_open.value)).error
            &&!launch_directory_files.Close(static_cast<int>(cwd_file.value)).error,
            "Ordinary relative open did not share native task CWD");
        for(const auto& invalid:std::vector<std::string>{"/missing","/process/main"}){bool rejected=false;
            try{DarwinFiles invalid_cwd(file_closure,{},invalid);}catch(const std::invalid_argument&){rejected=true;}
            Require(rejected,"Missing/non-directory initial CWD acknowledged");}
        DarwinFiles other_task_files(file_closure);
        Require(other_task_files.Read(static_cast<int>(original_fd.value),file_bytes).error==9,
            "Task-local descriptor resolved another task's handle");
        auto wrong_identity=file_closure;
        const auto main_identity=std::find_if(wrong_identity.images.begin(),wrong_identity.images.end(),[](const auto& image){return image.virtual_path=="/process/main";});
        Require(main_identity!=wrong_identity.images.end(),"Original file identity fixture missing");
        main_identity->metadata.sha256=std::string(64,'0');DarwinFiles mismatched_files(wrong_identity);
        Require(mismatched_files.Open("/process/main",0).error==5,
            "Opened original file did not match loader's source identity");
        Require(!owned_files.Close(static_cast<int>(original_fd.value)).error
            &&owned_files.Read(static_cast<int>(original_fd.value),file_bytes).error==9,
            "Closed descriptor remained usable");
        const auto debugger=commpage_probe("_debuggerCapabilityEntry");
        Require(debugger.mapped&&debugger.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&debugger.bootstrap.Get("syscall_selector")->Serialize()=="65535",
            "Native debugger capability/aliases did not reach guest: "+debugger.diagnostic);
        const auto& debugger_state=*debugger.bootstrap.Get("debugger_capability");
        Require(!debugger_state.Get("kernel_debugger_available")->Bool()&&debugger_state.Get("flags")->Serialize()=="0"
            &&debugger_state.Get("reads")->Serialize()=="80"&&debugger_state.Get("read_prefix")->ArrayItems().size()==16,
            "Debugger capability was fabricated or trace bound affected implementation");
        for(const auto& read:debugger_state.Get("read_prefix")->ArrayItems())
            Require(read.Get("value")->Serialize()=="0","Debugger native capability readback differs from owner");
        for(const auto& symbol:std::vector<std::string>{"_DebuggerCrossROEntry","_DebuggerCrossLegacyEntry","_DebuggerAdjacentEntry",
            "_DebuggerWriteROEntry","_DebuggerWriteLegacyEntry"}){
            const auto negative=commpage_probe(symbol);const bool write=symbol.find("Write")!=std::string::npos;
            Require(negative.mapped&&negative.bootstrap.GetString("stop_reason")==
                (write?"unsupported_memory_access":"unsupported_commpage_field")
                &&negative.bootstrap.Get("debugger_capability")->Get("reads")->Serialize()=="0",
                "Debugger field accepted crossing/adjacent read or write: "+negative.diagnostic);
        }
        const auto reprotect=commpage_probe("_vmReprotectEntry");
        Require(reprotect.mapped&&reprotect.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&reprotect.bootstrap.Get("syscall_selector")->Serialize()=="65535",
            "Guest R-to-RW protection transition failed: "+reprotect.diagnostic);
        const auto geometry_probe=commpage_probe("_geometryEntry");
        Require(geometry_probe.mapped&&geometry_probe.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&geometry_probe.bootstrap.Get("syscall_selector")->Serialize()=="65535","Guest relocated/legacy page geometry consumer failed");
        const auto& geometry=*geometry_probe.bootstrap.Get("commpage_geometry");
        const auto guest_page_size=std::stoull(geometry_probe.process_stack.Get("darwin_page_size")->Serialize());
        Require(geometry.Get("derived_from_owned_stack")->Bool()&&geometry.Get("page_size")->Serialize()==std::to_string(guest_page_size)
            &&(1ULL<<std::stoul(geometry.Get("kernel_page_shift")->Serialize()))==guest_page_size
            &&geometry.Get("kernel_page_shift")->Serialize()==geometry.Get("user_page_shift")->Serialize()
            &&geometry.Get("kernel_reads")->Serialize()=="2"&&geometry.Get("user_reads")->Serialize()=="2"
            &&geometry.Get("read_prefix")->ArrayItems().size()==4,"Commpage geometry did not derive owned guest stack policy");
        for(const auto& read:geometry.Get("read_prefix")->ArrayItems())
            Require(read.Get("value")->Serialize()==geometry.Get("kernel_page_shift")->Serialize(),"Guest page field readback differs from owned geometry");
        for(const auto& symbol:std::vector<std::string>{"_crossGeometryEntry","_unknownGeometryEntry"}){
            const auto probe=commpage_probe(symbol);
            Require(probe.mapped&&probe.bootstrap.GetString("stop_reason")=="unsupported_commpage_field"
                &&probe.bootstrap.Get("commpage_geometry")->Get("kernel_reads")->Serialize()=="0", "RO commpage unknown/crossing read exposed adjacent state");
        }
        for(const auto& symbol:std::vector<std::string>{"_writeGeometryEntry","_fetchGeometryEntry"}){
            const auto probe=commpage_probe(symbol);
            Require(probe.mapped&&probe.bootstrap.GetString("stop_reason")=="unsupported_memory_access", "RO commpage allowed guest write or instruction fetch");
        }
        Write(thread_dyld,thread_bytes);
        const auto identity_probe=commpage_probe("_threadIdentityEntry");
        Require(identity_probe.mapped&&identity_probe.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&identity_probe.bootstrap.Get("syscall_selector")->Serialize()=="65535","BSD identity/carry/uint64 consumer failed");
        const auto& identity=*identity_probe.bootstrap.Get("thread_identity");
        const auto tid=identity.Get("thread_id")->Serialize();
        Require(tid!="0"&&identity.Get("thread_binding_agrees")->Bool()&&identity.Get("selfid_calls")->Serialize()=="3",
            "Guest identity did not bind actual context");
        for(const auto& c:identity.Get("call_prefix")->ArrayItems())
            Require(c.Get("x0")->Serialize()==tid&&c.Get("x1")->Serialize()=="0"
                &&(std::stoull(c.Get("nzcv_before")->Serialize())&~0x20000000ULL)==std::stoull(c.Get("nzcv_after")->Serialize()),
                "BSD uint64 return failed X1/carry/NZV preservation");
        const auto next_identity=commpage_probe("_threadIdentityEntry");
        Require(next_identity.bootstrap.Get("thread_identity")->Get("thread_id")->Serialize()!=tid,
            "Fresh guest reused the destroyed guest thread ID");
        for(const auto& symbol:std::vector<std::string>{"_wrongIdentitySvcEntry","_wrongIdentityHighEntry"}){
            const auto probe=commpage_probe(symbol);
            Require(probe.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
                &&probe.bootstrap.Get("thread_identity")->Get("selfid_calls")->Serialize()=="0","Malformed identity syscall accepted");
        }
        const auto tls=commpage_probe("_tlsContextEntry");
        Require(tls.mapped&&tls.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&tls.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&tls.bootstrap.Get("thread_identity")->Get("platform_calls")->Serialize()=="4"
            &&tls.bootstrap.Get("thread_identity")->Get("tpidrro_agrees")->Bool(),
            "TSD base or platform preserved registers/flags failed: "+tls.bootstrap.Serialize());
        const auto fresh_tls=commpage_probe("_threadIdentityEntry");
        Require(fresh_tls.bootstrap.Get("thread_identity")->Get("tsd_base")->Serialize()=="0",
            "Fresh guest inherited another context's TSD");
        for(const auto& pair:std::vector<std::pair<const char*,const char*>>{
            {"_unknownPlatformEntry","unsupported_platform_syscall"},
            {"_wrongPlatformSvcEntry","unsupported_interrupt"}}){
            const auto probe=commpage_probe(pair.first);
            Require(probe.bootstrap.GetString("stop_reason")==pair.second
                &&probe.bootstrap.Get("thread_identity")->Get("platform_calls")->Serialize()=="0","Unsupported platform call succeeded");
        }
        const auto unaligned_tsd=commpage_probe("_unalignedTsdEntry");
        Require(unaligned_tsd.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&unaligned_tsd.bootstrap.Get("thread_identity")->Get("tsd_base")->Serialize()=="4097",
            "Register-only TSD setter incorrectly imposed alignment");
        const auto invalid_tsd=commpage_probe("_invalidTsdRangeEntry");
        Require(invalid_tsd.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&invalid_tsd.bootstrap.Get("thread_identity")->Get("tsd_base")->Serialize()=="0","Out-of-user-range TSD was not cleared");
        const auto crossarch=commpage_probe("_crossarchContextEntry");
        Require(crossarch.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&crossarch.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&crossarch.bootstrap.Get("thread_identity")->Get("crossarch_calls")->Serialize()=="4",
            "BSD crossarch namespace width/error ABI consumer failed");
        const auto flags=commpage_probe("_dyldFlagsEntry");
        Require(flags.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&flags.bootstrap.Get("dyld_flags")->Get("validated_reads")->Serialize()=="2","Dyld system policy did not reach consumer");
        const auto crossing_flags=commpage_probe("_crossDyldFlagsEntry");
        Require(crossing_flags.bootstrap.GetString("stop_reason")=="unsupported_commpage_field","Crossing dyld flags exposed adjacent state");
        const auto write_flags=commpage_probe("_writeDyldFlagsEntry");
        Require(write_flags.bootstrap.GetString("stop_reason")=="unsupported_memory_access","Dyld policy was guest writable");
        Write(thread_dyld,thread_bytes);
        const auto csr=commpage_probe("_csrctlCheckEntry");
        Require(csr.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&csr.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&csr.bootstrap.Get("thread_identity")->Get("csrctl_calls")->Serialize()=="3","CSR policy consumer failed");
        const auto csr_fault=commpage_probe("_csrFaultEntry");
        Require(csr_fault.bootstrap.GetString("stop_reason")=="unsupported_interrupt"
            &&csr_fault.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&csr_fault.bootstrap.Get("thread_identity")->Get("csrctl_calls")->Serialize()=="6",
            "CSR invalid pointers/size/op or write protection failed: "+csr_fault.bootstrap.Serialize());
        const auto no_shared_region=commpage_probe("_sharedRegionCheckEntry");
        Require(no_shared_region.bootstrap.Get("syscall_selector")->Serialize()=="65535"
            &&no_shared_region.bootstrap.Get("thread_identity")->Get("shared_region_start")->Serialize()=="0"
            &&no_shared_region.bootstrap.Get("thread_identity")->Get("shared_region_calls")->Serialize()=="2",
            "Standalone guest fabricated a mapped cache shared region");
        Write(thread_dyld,thread_bytes);
        const auto arm_result = RunDarwinArm64Function("/origin/server", {arm_tree}, "_original_result", {4, 5});
        Require(arm_result.returned && arm_result.value == 27 && arm_result.diagnostic.empty(),
            "original ARM64 instructions/bind/rebase/argument execution failed: " + arm_result.diagnostic);
        for (const auto key : {0ULL, 1ULL}) {
            const auto pac = RunDarwinArm64Function("/origin/server", {arm_tree}, "_pac_probe", {key});
            Require(pac.returned && pac.value == 7 && pac.diagnostic.empty(),
                "Windows ARM64 PAC signing/roundtrip/tamper rejection failed: " + pac.diagnostic);
        }
        // Same guest instructions, dependency and loader, with only the owned
        // main ABI varied. ARM64 providers must not disable an ARM64e task;
        // ARM64e providers must not enable an ordinary ARM64 task.
        for(const auto subtype:{0u,2u,0x80000002u}){
            auto main_bytes=original_arm_consumer;Little32(main_bytes,8,subtype);Write(arm_consumer,main_bytes);
            auto provider_bytes=original_arm_provider;Little32(provider_bytes,8,subtype?0u:2u);Write(arm_provider,provider_bytes);
            for(std::uint64_t key=0;key<4;++key){
                const auto pac=RunDarwinArm64Function("/origin/server",{arm_tree},"_pac_policy_probe",{key});
                Require(pac.returned&&pac.diagnostic.empty(),"Task ABI PAC instruction probe failed: "+pac.diagnostic);
                const bool enabled=subtype!=0||key==1;
                Require(enabled?(pac.value&7)==7:(pac.value&11)==10,
                    "Task ABI did not select IA/DA/DB no-op versus enforced IB authentication");
            }
            const auto good_return=RunDarwinArm64Function("/origin/server",{arm_tree},"_ib_return_probe",{0});
            const auto bad_return=RunDarwinArm64Function("/origin/server",{arm_tree},"_ib_return_probe",{1});
            Require(good_return.returned&&good_return.value==0&&!bad_return.returned&&!bad_return.diagnostic.empty(),
                "Task ABI disabled IB return protection or rejected a valid signed return");
        }
        Write(arm_consumer,original_arm_consumer);Write(arm_provider,original_arm_provider);
        const auto privileged=RunDarwinArm64Function("/origin/server",{arm_tree},"_privileged_probe");
        Require(!privileged.returned&&privileged.diagnostic.find("exception/syscall service is unavailable")!=std::string::npos,
            "EL0 guest executed a privileged CurrentEL register read");
        const auto trap_result = RunDarwinArm64Function("/origin/server", {arm_tree}, "_syscall_probe");
        Require(!trap_result.returned && trap_result.diagnostic.find("syscall service is unavailable") != std::string::npos,
            "unsupported original Darwin syscall returned fake success");
        const auto loop_result = RunDarwinArm64Function("/origin/server", {arm_tree}, "_endless");
        Require(!loop_result.returned && !loop_result.diagnostic.empty(), "ARM64 execution instruction/time budget ignored");
        if (argc == 2) {
            const auto executable = fs::absolute(argv[1]).wstring();
            const auto cli = Win32Process::Run(executable, {executable, L"runtime", L"run-arm64", L"/origin/server",
                L"_original_no_args", arm_tree.wstring()});
            const auto report = JsonValue::Parse(cli.std_out);
            Require(cli.success && report && report->Get("function_returned")->Bool(false)
                && report->Get("result_value")->Serialize() == "18" && !report->Get("plugin_execution_validated")->Bool(true),
                "native ARM64 CLI did not execute original compiled code");
            const auto pac_cli=Win32Process::Run(executable,{executable,L"runtime",L"run-arm64",L"/origin/server",L"_pac_probe",arm_tree.wstring()});
            const auto pac_report=JsonValue::Parse(pac_cli.std_out);
            Require(pac_cli.success&&pac_report&&pac_report->Get("function_returned")->Bool(false)
                &&pac_report->Get("result_value")->Serialize()=="7"&&!pac_report->Get("plugin_execution_validated")->Bool(true),
                "Native CLI failed to propagate ARM64 PAC execution semantics");
            const auto privileged_cli=Win32Process::Run(executable,{executable,L"runtime",L"run-arm64",L"/origin/server",L"_privileged_probe",arm_tree.wstring()});
            const auto privileged_report=JsonValue::Parse(privileged_cli.std_out);
            Require(!privileged_cli.success&&privileged_report&&!privileged_report->Get("function_returned")->Bool(true)
                &&privileged_report->GetString("diagnostic").find("exception/syscall service is unavailable")!=std::string::npos,
                "Native CLI allowed privileged execution by ARM64 user code");


        }
        Require(Read(arm_consumer) == original_arm_consumer && Read(arm_provider) == original_arm_provider,
            "native ARM64 execution modified original file bytes");
        Require(Read(path) == fat, "original fixture image changed");
        fs::remove_all(root);
        std::cout << "Real Clang/LLD images -> native host slice/dependency metadata; malformed cases rejected PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << "\nFixture: " << root << '\n'; return 1; }
}
