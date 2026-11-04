#include "capabilities.hpp"
#include "project_inspection.hpp"
#include "win32_process.hpp"
#include "operation_events.hpp"
#include "openfruit_version.hpp"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <string>
#include <windows.h>

namespace fs = std::filesystem;

int main(int argc, char** argv) {
    bool passed = true;

    // 1. Test Capabilities Query
    const auto caps = OpenFruit::Capabilities::Query();
    if (caps.GetString("engine_version") != OPENFRUIT_VERSION) {
        std::cerr << "Capabilities failed: engine_version mismatch\n";
        passed = false;
    }
    const auto* ops = caps.Get("operations");
    if (!ops || ops->GetString("project_inspect") != "implemented" ||
        ops->GetString("sdk_remove") != "implemented" ||
        ops->GetString("sdk_select") != "implemented") {
        std::cerr << "Capabilities failed: operations mismatch\n";
        passed = false;
    }

    // 2. Test ProjectInspection on invalid path
    const auto invalid = OpenFruit::ProjectInspection::Inspect(L"C:\\nonexistent_project_path");
    if (invalid.success) {
        std::cerr << "ProjectInspection failed: expected failure on nonexistent path\n";
        passed = false;
    }
    const auto invalid_json = invalid.ToJson();
    if (!invalid_json.Get("success") || invalid_json.Get("success")->Bool() != false || invalid_json.GetString("error").empty()) {
        std::cerr << "ProjectInspection failed: invalid error JSON serialization\n";
        passed = false;
    }

    // 3. Optional: inspect a local Swiftfin checkout named by OPENFRUIT_TEST_SWIFTFIN.
    fs::path swiftfin_path;
    if (const DWORD length = GetEnvironmentVariableW(L"OPENFRUIT_TEST_SWIFTFIN", nullptr, 0); length > 1) {
        std::wstring value(length, L'\0');
        value.resize(GetEnvironmentVariableW(L"OPENFRUIT_TEST_SWIFTFIN", value.data(), length));
        swiftfin_path = value;
    }
    if (!swiftfin_path.empty() && fs::exists(swiftfin_path)) {
        const auto insp = OpenFruit::ProjectInspection::Inspect(swiftfin_path.wstring(), "Debug");
        if (!insp.success) {
            std::cerr << "ProjectInspection failed on Swiftfin: " << insp.error_message << "\n";
            passed = false;
        } else {
            const auto json = insp.ToJson();
            std::cout << "Project Name: " << json.GetString("project_name") << "\n";
            std::cout << "Bundle ID: " << json.GetString("bundle_id") << "\n";
            std::cout << "Swift source count: " << (json.Get("swift_source_count") ? json.Get("swift_source_count")->Int() : -1) << "\n";
            if (json.GetString("project_name").empty() ||
                json.GetString("bundle_id") != "org.jellyfin.swiftfin" ||
                !json.Get("swift_source_count") ||
                json.Get("swift_source_count")->Int() < 700) {
                std::cerr << "ProjectInspection failed: incorrect project metadata parsed\n";
                passed = false;
            }
        }
    }

    // Both UTF-8 encodings must preserve the same authoritative Xcode graph.
    try {
        const fs::path fixture(OPENFRUIT_SHELL_PHASE_FIXTURE);
        const fs::path temporary = fs::temp_directory_path() /
            ("OPENFRUIT-project-encoding-" + OpenFruit::NewOperationId());
        fs::create_directory(temporary);
        const auto read = [](const fs::path& path) {
            std::ifstream input(path, std::ios::binary);
            if (!input) throw std::runtime_error("Cannot read encoding fixture");
            return std::string(std::istreambuf_iterator<char>(input), {});
        };
        const auto original = read(fixture / "ShellPhaseProbe.xcodeproj/project.pbxproj");
        auto plain = original;
        if (plain.compare(0, 3, "\xef\xbb\xbf") == 0) plain.erase(0, 3);
        for (const bool bom : {false, true}) {
            const auto root = temporary / (bom ? "bom" : "plain");
            fs::copy(fixture, root, fs::copy_options::recursive);
            const auto project = root / "ShellPhaseProbe.xcodeproj";
            const auto file = project / "project.pbxproj";
            const auto bytes = (bom ? std::string("\xef\xbb\xbf") : std::string()) + plain;
            { std::ofstream output(file, std::ios::binary | std::ios::trunc);
              output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
              if (!output) throw std::runtime_error("Cannot write encoding fixture"); }
            const auto result = OpenFruit::ProjectInspection::Inspect(project.wstring(), "Release");
            if (!result.success || result.project.project_name != L"ShellPhaseConsumer" ||
                result.project.c_sources.size() != 1 || result.project.target_dependencies.size() != 1 ||
                result.project.minimum_os_version != L"17.4" || read(file) != bytes) {
                throw std::runtime_error("UTF-8 BOM changed project discovery, graph or source bytes");
            }
        }
        if (read(fixture / "ShellPhaseProbe.xcodeproj/project.pbxproj") != original)
            throw std::runtime_error("Original project fixture was mutated");
        fs::remove_all(temporary); // Only the fresh directory reserved by this test.
    } catch (const std::exception& error) {
        std::cerr << "Project encoding regression failed: " << error.what() << '\n';
        passed = false;
    }

    // A declared intent is a compiler input, including when its file is missing.
    // Exercise metadata discovery and propagation rather than injecting AppBuildSpec paths.
    try {
        const fs::path fixture(OPENFRUIT_SHELL_PHASE_FIXTURE);
        const fs::path temporary = fs::temp_directory_path() /
            ("OPENFRUIT-project-intents-" + OpenFruit::NewOperationId());
        fs::create_directory(temporary);
        const auto read = [](const fs::path& path) {
            std::ifstream input(path, std::ios::binary);
            if (!input) throw std::runtime_error("Cannot read intent fixture");
            return std::string(std::istreambuf_iterator<char>(input), {});
        };
        const auto write = [](const fs::path& path, const std::string& bytes) {
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
            if (!output) throw std::runtime_error("Cannot write intent fixture");
        };
        const auto original = read(fixture / "ShellPhaseProbe.xcodeproj/project.pbxproj");
        const std::string objects = R"(
            I00000000000000000000001 = { isa = PBXFileReference; path = Declared.intentdefinition; sourceTree = SOURCE_ROOT; };
            I00000000000000000000002 = { isa = PBXBuildFile; fileRef = I00000000000000000000001; };
            I00000000000000000000003 = { isa = PBXVariantGroup; path = Localized.intentdefinition; sourceTree = SOURCE_ROOT;
                children = (I00000000000000000000004, I00000000000000000000005,); };
            I00000000000000000000004 = { isa = PBXFileReference; name = en; path = en.lproj/Localized.intentdefinition; sourceTree = SOURCE_ROOT; };
            I00000000000000000000005 = { isa = PBXFileReference; name = Base; path = Base.lproj/Localized.intentdefinition; sourceTree = SOURCE_ROOT; };
            I00000000000000000000006 = { isa = PBXBuildFile; fileRef = I00000000000000000000003; };
            I00000000000000000000007 = { isa = PBXVariantGroup; path = Unrelated.strings; sourceTree = SOURCE_ROOT;
                children = (I00000000000000000000008,); };
            I00000000000000000000008 = { isa = PBXFileReference; path = en.lproj/Unrelated.strings; sourceTree = SOURCE_ROOT; };
            I00000000000000000000009 = { isa = PBXBuildFile; fileRef = I00000000000000000000007; };
            I0000000000000000000000A = { isa = PBXResourcesBuildPhase; files = (I00000000000000000000006, I00000000000000000000009, DIRECT_RESOURCE); };
        )";
        for (const bool direct_in_sources : {false, true}) {
            for (const bool direct_present : {false, true}) {
                for (const bool base_present : {false, true}) {
                    const auto root = temporary /
                        (std::to_string(direct_in_sources) + std::to_string(direct_present) + std::to_string(base_present));
                    fs::copy(fixture, root, fs::copy_options::recursive);
                    fs::create_directory(root / "en.lproj");
                    fs::create_directory(root / "Base.lproj");
                    write(root / "en.lproj/Localized.intentdefinition", "localized intent");
                    if (direct_present) write(root / "Declared.intentdefinition", "direct intent");
                    if (base_present) write(root / "Base.lproj/Localized.intentdefinition", "base intent");
                    auto bytes = original;
                    const auto replace = [&](const std::string& from, const std::string& to) {
                        const auto position = bytes.find(from);
                        if (position == std::string::npos) throw std::runtime_error("Intent fixture structure changed");
                        bytes.replace(position, from.size(), to);
                    };
                    replace("objects = {", "objects = {" + objects);
                    replace("DIRECT_RESOURCE", direct_in_sources ? "" : "I00000000000000000000002,");
                    replace("buildPhases = (A00000000000000000000020,);",
                        "buildPhases = (A00000000000000000000020, I0000000000000000000000A,);");
                    if (direct_in_sources) replace("files = (A00000000000000000000040,);",
                        "files = (A00000000000000000000040, I00000000000000000000002,);");
                    const auto file = root / "ShellPhaseProbe.xcodeproj/project.pbxproj";
                    write(file, bytes);
                    const auto inspected = OpenFruit::ProjectInspection::Inspect(file.parent_path().wstring(), "Release");
                    const auto spec = OpenFruit::UniversalProject::ToAppBuildSpec(inspected.project);
                    const auto has = [](const auto& paths, const fs::path& expected) {
                        return std::any_of(paths.begin(), paths.end(), [&](const auto& actual) {
                            return fs::path(actual).lexically_normal() == expected.lexically_normal();
                        });
                    };
                    if (!inspected.success || inspected.project.intent_definitions.size() != 2 ||
                        spec.intent_definitions != inspected.project.intent_definitions ||
                        !has(spec.intent_definitions, root / "Declared.intentdefinition") ||
                        !has(spec.intent_definitions, root / "Base.lproj/Localized.intentdefinition") ||
                        has(spec.intent_definitions, root / "en.lproj/Localized.intentdefinition") ||
                        has(inspected.project.resource_files, root / "en.lproj/Unrelated.strings") ||
                        read(file) != bytes || fs::exists(root / "Declared.intentdefinition") != direct_present ||
                        fs::exists(root / "Base.lproj/Localized.intentdefinition") != base_present) {
                        std::cerr << "Intent case sources=" << direct_in_sources
                            << " direct_present=" << direct_present << " base_present=" << base_present
                            << " inspected=" << inspected.success << " error=" << inspected.error_message
                            << " discovered=" << inspected.project.intent_definitions.size()
                            << " propagated=" << spec.intent_definitions.size() << '\n';
                        for (const auto& path : spec.intent_definitions)
                            std::cerr << "Intent actual: " << OpenFruit::Win32Process::ToNarrow(path) << '\n';
                        std::cerr << "Intent expected direct: " << (root / "Declared.intentdefinition").string()
                            << "\nIntent expected Base: " << (root / "Base.lproj/Localized.intentdefinition").string() << '\n';
                        throw std::runtime_error("Declared intent metadata was lost, substituted or mutated before AppBuildSpec");
                    }
                }
            }
        }
        if (read(fixture / "ShellPhaseProbe.xcodeproj/project.pbxproj") != original)
            throw std::runtime_error("Original project fixture was mutated");
        fs::remove_all(temporary); // Only the fresh directory reserved by this test.
    } catch (const std::exception& error) {
        std::cerr << "Intent propagation regression failed: " << error.what() << '\n';
        passed = false;
    }

    // 6. Test Candidate A: ParseSearchPathsSetting & Search Paths / CopyFiles phases
    try {
        const fs::path temp_base = fs::temp_directory_path() / "openfruit_wave4_test";
        fs::remove_all(temp_base);
        fs::create_directories(temp_base / "headers" / "sub_alpha");
        fs::create_directories(temp_base / "headers" / "sub_beta");
        fs::create_directories(temp_base / "headers" / "MyIgnored.framework" / "Headers");
        fs::create_directories(temp_base / "headers" / "Ignored.bundle" / "Resources");
        fs::create_directories(temp_base / "headers" / ".git" / "objects");
        fs::create_directories(temp_base / "libs");

        // 6a. Non-mutating behavior for build/Products
        const fs::path non_existent_products = temp_base / "nonexistent" / "build" / "Products" / "Release-iphoneos";
        if (fs::exists(non_existent_products)) {
            throw std::runtime_error("Unexpected pre-existing products directory");
        }
        const auto parsed_products = OpenFruit::ParseSearchPathsSetting(
            non_existent_products.wstring(), temp_base
        );
        if (parsed_products.size() != 1) {
            throw std::runtime_error("ParseSearchPathsSetting should resolve non-existent build/Products path");
        }
        if (fs::exists(non_existent_products)) {
            throw std::runtime_error("ParseSearchPathsSetting mutated disk by creating non-existent Products directory!");
        }

        // 6b. Recursive /** expansion skipping bundles
        const std::wstring recursive_spec = (temp_base / "headers").wstring() + L"/**";
        const auto parsed_recursive = OpenFruit::ParseSearchPathsSetting(
            recursive_spec, temp_base
        );
        
        bool has_root = false;
        bool has_sub_alpha = false;
        bool has_sub_beta = false;
        bool has_bundle = false;
        bool has_framework = false;
        bool has_git = false;

        const auto norm_root = (temp_base / "headers").lexically_normal().wstring();
        const auto norm_alpha = (temp_base / "headers" / "sub_alpha").lexically_normal().wstring();
        const auto norm_beta = (temp_base / "headers" / "sub_beta").lexically_normal().wstring();

        for (const auto& item : parsed_recursive) {
            if (item == norm_root) has_root = true;
            if (item == norm_alpha) has_sub_alpha = true;
            if (item == norm_beta) has_sub_beta = true;
            if (item.find(L"MyIgnored.framework") != std::wstring::npos) has_framework = true;
            if (item.find(L"Ignored.bundle") != std::wstring::npos) has_bundle = true;
            if (item.find(L".git") != std::wstring::npos) has_git = true;
        }

        if (!has_root || !has_sub_alpha || !has_sub_beta) {
            throw std::runtime_error("ParseSearchPathsSetting /** failed to expand subdirectories");
        }
        if (has_framework || has_bundle || has_git) {
            throw std::runtime_error("ParseSearchPathsSetting /** traversed into bundle interior or dot-directory");
        }

        // 6c. PBXCopyFilesBuildPhase and FRAMEWORK_SEARCH_PATHS / LIBRARY_SEARCH_PATHS
        const fs::path pbxproj_dir = temp_base / "CopyPhaseTest.xcodeproj";
        fs::create_directories(pbxproj_dir);
        fs::create_directories(temp_base / "Source");
        fs::create_directories(temp_base / "CustomFrameworks" / "Vendor.framework");
        fs::create_directories(temp_base / "CustomResources");
        fs::create_directories(temp_base / "libs");
        std::ofstream(temp_base / "Source" / "main.swift") << "import Foundation\n";
        std::ofstream(temp_base / "CustomResources" / "asset.png") << "PNG";

        const std::string fwk_search = (temp_base / "CustomFrameworks").generic_string();
        const std::string lib_search = (temp_base / "libs").generic_string();

        const std::string pbxproj_content = 
            "// !$*UTF8*$!\n"
            "{\n"
            "    archiveVersion = 1;\n"
            "    classes = { };\n"
            "    objectVersion = 56;\n"
            "    objects = {\n"
            "        PROJ01 = { isa = PBXProject; targets = ( TGT01 ); buildConfigurationList = CFG01; };\n"
            "        CFG01 = { isa = XCConfigurationList; buildConfigurations = ( BC01 ); };\n"
            "        BC01 = { isa = XCBuildConfiguration; name = Release; buildSettings = {\n"
            "            PRODUCT_NAME = CopyApp;\n"
            "            FRAMEWORK_SEARCH_PATHS = \"" + fwk_search + "\";\n"
            "            LIBRARY_SEARCH_PATHS = \"" + lib_search + "\";\n"
            "        }; };\n"
            "        TGT01 = { isa = PBXNativeTarget; name = CopyApp; productType = \"com.apple.product-type.application\";\n"
            "            buildPhases = ( PH_SRC, PH_COPY_FWK, PH_COPY_RES ); buildConfigurationList = CFG01; };\n"
            "        PH_SRC = { isa = PBXSourcesBuildPhase; files = ( F_SRC ); };\n"
            "        PH_COPY_FWK = { isa = PBXCopyFilesBuildPhase; dstSubfolderSpec = 10; files = ( F_FWK ); };\n"
            "        PH_COPY_RES = { isa = PBXCopyFilesBuildPhase; dstSubfolderSpec = 7; files = ( F_RES ); };\n"
            "        F_SRC = { isa = PBXBuildFile; fileRef = REF_SRC; };\n"
            "        F_FWK = { isa = PBXBuildFile; fileRef = REF_FWK; };\n"
            "        F_RES = { isa = PBXBuildFile; fileRef = REF_RES; };\n"
            "        REF_SRC = { isa = PBXFileReference; path = Source/main.swift; };\n"
            "        REF_FWK = { isa = PBXFileReference; path = CustomFrameworks/Vendor.framework; };\n"
            "        REF_RES = { isa = PBXFileReference; path = CustomResources/asset.png; };\n"
            "    };\n"
            "    rootObject = PROJ01;\n"
            "}\n";

        std::ofstream(pbxproj_dir / "project.pbxproj") << pbxproj_content;
        const auto inspected = OpenFruit::ProjectInspection::Inspect(pbxproj_dir.wstring(), "Release");
        if (!inspected.success) {
            throw std::runtime_error("Inspection failed on CopyPhaseTest: " + inspected.error_message);
        }

        // Verify Framework Search Paths and Library Search Paths
        bool found_fsp = false;
        const auto norm_fsp = (temp_base / "CustomFrameworks").lexically_normal().wstring();
        for (const auto& dir : inspected.project.embedded_framework_dirs) {
            if (dir == norm_fsp) found_fsp = true;
        }
        if (!found_fsp) {
            throw std::runtime_error("FRAMEWORK_SEARCH_PATHS not propagated to embedded_framework_dirs");
        }

        bool found_lsp = false;
        const auto norm_lsp = (temp_base / "libs").lexically_normal().wstring();
        for (const auto& dir : inspected.project.library_search_paths) {
            if (dir == norm_lsp) found_lsp = true;
        }
        if (!found_lsp) {
            throw std::runtime_error("LIBRARY_SEARCH_PATHS not propagated to library_search_paths");
        }

        // Verify PBXCopyFilesBuildPhase dstSubfolderSpec 10 -> frameworks
        bool found_copied_fwk = false;
        const auto norm_fwk = (temp_base / "CustomFrameworks" / "Vendor.framework").lexically_normal().wstring();
        for (const auto& fwk : inspected.project.embedded_frameworks) {
            if (fwk == norm_fwk) found_copied_fwk = true;
        }
        if (!found_copied_fwk) {
            throw std::runtime_error("PBXCopyFilesBuildPhase dstSubfolderSpec 10 framework not collected into embedded_frameworks");
        }

        // Verify PBXCopyFilesBuildPhase dstSubfolderSpec 7 -> resources
        bool found_copied_res = false;
        const auto norm_res = (temp_base / "CustomResources" / "asset.png").lexically_normal().wstring();
        for (const auto& res : inspected.project.resource_files) {
            if (res == norm_res) found_copied_res = true;
        }
        if (!found_copied_res) {
            throw std::runtime_error("PBXCopyFilesBuildPhase dstSubfolderSpec 7 resource not collected into resource_files");
        }

        // Verify propagation to AppBuildSpec
        const auto spec = OpenFruit::UniversalProject::ToAppBuildSpec(inspected.project);
        bool spec_found_lsp = false;
        for (const auto& dir : spec.library_search_paths) {
            if (dir == norm_lsp) spec_found_lsp = true;
        }
        if (!spec_found_lsp) {
            throw std::runtime_error("library_search_paths not propagated to AppBuildSpec");
        }

        fs::remove_all(temp_base);
    } catch (const std::exception& error) {
        std::cerr << "Candidate A regression failed: " << error.what() << '\n';
        passed = false;
    }

    if (!passed) {
        std::cerr << "Project inspection tests FAILED\n";
        return 1;
    }

    std::cout << "Project inspection and capabilities tests PASSED\n";
    return 0;
}
