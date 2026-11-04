#include "openib/compiler.hpp"
#include "openib/diff.hpp"
#include "openib/model.hpp"
#include "openib/nib.hpp"
#include "openib/version.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs=std::filesystem;

static void usage(){std::cout<<"OpenIB "<<openib::version_string()<<"\n\n"
"Usage:\n"
"  openib analyze <file.storyboard|file.xib>\n"
"  openib compile <input> -o <output> [--strict] [--coder-version 10] [--module <target module>]\n"
"  openib dump <file.nib> [--no-types] [--nested INDEX]\n"
"  openib diff <left.nib> <right.nib>\n"
"  openib version\n";}
static void print_diags(const openib::Diagnostics& d) {
    for (auto& i : d.items()) {
        const char* s = i.severity == openib::Severity::Error     ? "error"
                        : i.severity == openib::Severity::Warning ? "warning"
                                                                  : "info";
        std::cerr << s << " " << i.code << ": ";
        if (!i.file.empty()) std::cerr << i.file << (i.line ? ":" + std::to_string(i.line) : "") << ": ";
        std::cerr << i.message << "\n";
    }
}

static openib::nib::Archive nested_archive(const openib::nib::Archive& outer,std::size_t selected){
    std::size_t index=0;
    for(const auto& object:outer.objects){
        if(object.class_index>=outer.classes.size()||outer.classes[object.class_index].name!="NSData")continue;
        for(std::uint32_t i=0;i<object.value_count;++i){
            const auto value_index=object.value_start+i;if(value_index>=outer.values.size())continue;
            const auto& value=outer.values[value_index];
            if(value.key_index>=outer.keys.size()||outer.keys[value.key_index]!="NS.bytes"||value.type!=openib::nib::ValueType::Bytes)continue;
            const auto& bytes=std::get<openib::nib::Bytes>(value.payload).data;
            if(bytes.size()<10||std::memcmp(bytes.data(),"NIBArchive",10)!=0)continue;
            if(index++==selected)return openib::nib::Reader().read_bytes(bytes);
        }
    }
    throw std::runtime_error("nested NIB index out of range");
}

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            usage();
            return 2;
        }
        std::string cmd = argv[1];
        if (cmd == "version" || cmd == "--version") {
            std::cout << openib::version_string() << "\n";
            return 0;
        }
        if (cmd == "analyze") {
            if (argc < 3) {
                usage();
                return 2;
            }
            openib::Diagnostics d;
            openib::IBParser p;
            auto doc = p.parse(argv[2], d);
            auto r = openib::analyze_document(doc);
            std::cout << "type: " << doc.type << "\nformat: " << doc.format_version
                      << "\ntoolsVersion: " << doc.tools_version << "\ntargetRuntime: " << doc.target_runtime
                      << "\nscenes: " << r.scene_count << "\noutlets: " << r.outlet_count
                      << "\nactions: " << r.action_count << "\nsegues: " << r.segue_count
                      << "\nconstraints: " << r.constraint_count
                      << "\nunsupported tags: " << r.unsupported_tag_counts.size() << "\n";
            std::vector<std::pair<std::string, std::size_t>> u(r.unsupported_tag_counts.begin(),
                                                               r.unsupported_tag_counts.end());
            std::sort(u.begin(), u.end());
            for (auto& [k, v] : u) std::cout << "  " << k << ": " << v << "\n";
            print_diags(d);
            return d.has_errors() ? 1 : 0;
        }
        if (cmd == "dump") {
            if (argc < 3) {
                usage();
                return 2;
            }
            bool types = true;
            std::optional<std::size_t> nested;
            for (int i = 3; i < argc; ++i) {
                if (std::string(argv[i]) == "--no-types")
                    types = false;
                else if (std::string(argv[i]) == "--nested" && i + 1 < argc)
                    nested = std::stoull(argv[++i]);
            }
            openib::nib::Reader r;
            auto archive = r.read_file(argv[2]);
            std::cout << openib::nib::dump_text(nested ? nested_archive(archive, *nested) : archive, types);
            return 0;
        }
        if (cmd == "diff") {
            if (argc < 4) {
                usage();
                return 2;
            }
            auto r = openib::diff_nib_files(argv[2], argv[3]);
            std::cout << openib::format_diff(r);
            return r.equivalent ? 0 : 1;
        }
        if (cmd == "compile") {
            if (argc < 3) {
                usage();
                return 2;
            }
            fs::path in = argv[2], out;
            openib::CompileOptions options;
            for (int i = 3; i < argc; ++i) {
                std::string a = argv[i];
                if ((a == "-o" || a == "--output") && i + 1 < argc)
                    out = argv[++i];
                else if (a == "--strict")
                    options.strict = true;
                else if (a == "--module" && i + 1 < argc)
                    options.target_module = argv[++i];
                else if (a == "--coder-version" && i + 1 < argc)
                    options.nib_coder_version = static_cast<std::uint32_t>(std::stoul(argv[++i]));
            }
            if (out.empty()) {
                std::cerr << "compile requires -o <output>\n";
                return 2;
            }
            openib::Diagnostics d;
            openib::Compiler c;
            auto r = c.compile(in, out, options, d);
            print_diags(d);
            std::cout << "written: " << r.files_written << " file(s)\n";
            return r.success ? 0 : 1;
        }
        usage();
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }
}
