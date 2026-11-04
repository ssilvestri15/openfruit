#include "xcode_project.hpp"

#include <filesystem>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::cerr <<
            "usage: xcode_xcconfig_anchor_probe <project> [expected-bundle-id]\n";
        return 2;
    }

    const std::string expected = argc == 3
        ? argv[2]
        : "org.OPENFRUIT.xcconfig-anchor-probe";

    const auto project = OpenFruit::XcodeProject::Load(
        std::filesystem::path(argv[1])
    );
    if (!project) {
        std::cerr << "failed to load fixture project\n";
        return 3;
    }

    const auto target = project->MainApplicationTarget();
    if (!target) {
        std::cerr << "failed to select fixture application target\n";
        return 4;
    }

    const auto resolved = project->ResolveTarget(*target, "Debug");
    if (!resolved) {
        std::cerr << "failed to resolve fixture target\n";
        return 5;
    }

    const auto value = resolved->build_settings.find(
        "PRODUCT_BUNDLE_IDENTIFIER"
    );
    if (value == resolved->build_settings.end()) {
        std::cerr << "PRODUCT_BUNDLE_IDENTIFIER missing\n";
        return 6;
    }

    std::cout << value->second << '\n';
    return value->second == expected ? 0 : 7;
}
