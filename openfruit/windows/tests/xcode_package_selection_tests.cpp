#include "package_engine.hpp"
#include "universal_project.hpp"
#include "xcode_project.hpp"
#include "win32_process.hpp"
#include "operation_events.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace OpenFruit;

int main() {
    const auto root = fs::temp_directory_path() / ("openfruit-package-selection-" + NewOperationId());
    try {
        const auto bundle = root / "Owned.xcodeproj";
        fs::create_directories(bundle);
        std::ofstream(bundle / "project.pbxproj") << R"PBX({
archiveVersion=1; objectVersion=56; objects={
P={isa=PBXProject; mainGroup=G; targets=(FIRST,SECOND,TRANSITIVE_APP,CHILD_LIB,); buildConfigurationList=CL; packageReferences=(PKG,CHILD_PKG,);};
G={isa=PBXGroup; children=(APP_SWIFT,); sourceTree="<group>";};
APP_SWIFT={isa=PBXFileReference; path=App.swift; sourceTree="<group>";};
SOURCES_BUILD={isa=PBXBuildFile; fileRef=APP_SWIFT;};
SOURCES={isa=PBXSourcesBuildPhase; files=(SOURCES_BUILD,);};
FIRST={isa=PBXNativeTarget; name=First; productType="com.apple.product-type.application"; buildConfigurationList=CL; buildPhases=(SOURCES,); packageProductDependencies=(PROD,);};
SECOND={isa=PBXNativeTarget; name=UUIDTHATISONLYANAME; productName=SelectedProof; productType="com.apple.product-type.application"; buildConfigurationList=SECOND_CL; buildPhases=(SOURCES,);};
TRANSITIVE_APP={isa=PBXNativeTarget; name=TransitiveApp; productName=TransitiveApp; productType="com.apple.product-type.application"; buildConfigurationList=CL; buildPhases=(SOURCES,); dependencies=(DEP_CHILD,);};
CHILD_LIB={isa=PBXNativeTarget; name=ChildLib; productName=ChildLib; productType="com.apple.product-type.framework"; buildConfigurationList=CL; buildPhases=(SOURCES,); packageProductDependencies=(CHILD_PROD,);};
DEP_CHILD={isa=PBXTargetDependency; target=CHILD_LIB;};
CL={isa=XCConfigurationList; buildConfigurations=(D,); defaultConfigurationName=Debug;};
D={isa=XCBuildConfiguration; name=Debug; buildSettings={PRODUCT_NAME="$(TARGET_NAME)";};};
SECOND_CL={isa=XCConfigurationList; buildConfigurations=(SECOND_D,); defaultConfigurationName=Debug;};
SECOND_D={isa=XCBuildConfiguration; name=Debug; buildSettings={PRODUCT_NAME=SelectedProof;};};
PKG={isa=XCLocalSwiftPackageReference; relativePath=AbsentPackage;};
PROD={isa=XCSwiftPackageProductDependency; package=PKG; productName=AbsentProduct;};
CHILD_PKG={isa=XCLocalSwiftPackageReference; relativePath=AbsentChildPackage;};
CHILD_PROD={isa=XCSwiftPackageProductDependency; package=CHILD_PKG; productName=AbsentChildProduct;};
}; rootObject=P;})PBX";
        std::ofstream(root / "App.swift") << "import Foundation\n";
        const XcodeDependencyOptions strict{false, false, true};
        SDKInfo sdk;
        // No compiler/SDK is supplied: a target with no products must not start
        // package/tool acquisition, nor silently select FIRST's missing product.
        const auto selected = PackageEngine::BuildXcodePackages(root.wstring(), bundle.wstring(),
            sdk, L"debug", 1, nullptr, "SECOND", &strict);
        if (!selected.success || fs::exists(root / "build" / "xcode-packages-v4"))
            throw std::runtime_error("Selected UUID did not govern the actual package consumer");
        const auto label = PackageEngine::BuildXcodePackages(root.wstring(), bundle.wstring(),
            sdk, L"Debug", 1, nullptr, "UUIDTHATISONLYANAME", &strict);
        if (label.success) throw std::runtime_error("Missing UUID fell back to a target label");
        const auto missing_configuration = PackageEngine::BuildXcodePackages(root.wstring(), bundle.wstring(),
            sdk, L"NotConfigured", 1, nullptr, "SECOND", &strict);
        if (missing_configuration.success) throw std::runtime_error("Missing configuration reported success");
        const auto loaded = XcodeProject::Load(bundle);
        const auto second = loaded ? loaded->FindTarget("SECOND") : std::nullopt;
        if (!loaded || !second) throw std::runtime_error("Failed to load SECOND target by UUID");
        const auto inspected = UniversalProject::InspectTarget(*loaded, *second, "Debug", strict);
        if (!inspected.is_valid || inspected.project_name != L"UUIDTHATISONLYANAME" ||
            inspected.product_name != L"SelectedProof" || inspected.module_name != L"SelectedProof" ||
            inspected.display_name != L"SelectedProof")
            throw std::runtime_error("Selected target inspection conflated target name with product/module identity");
        const auto build_spec = UniversalProject::ToAppBuildSpec(inspected, 1);
        const auto pkg_spec = UniversalProject::ToPackagingSpec(inspected);
        if (build_spec.app_name != L"UUIDTHATISONLYANAME" || build_spec.product_name != L"SelectedProof" ||
            build_spec.module_name != L"SelectedProof" || pkg_spec.target_name != L"UUIDTHATISONLYANAME" ||
            pkg_spec.product_name != L"SelectedProof" || pkg_spec.app_name != L"SelectedProof" ||
            pkg_spec.module_name != L"SelectedProof")
            throw std::runtime_error("Selected target spec conversion failed to preserve distinct target/product/module identity");
        const auto transitive_target = loaded->FindTarget("TRANSITIVE_APP");
        if (!transitive_target) throw std::runtime_error("Failed to load TRANSITIVE_APP target by UUID");
        const auto resolved_transitive = loaded->ResolveTarget(*transitive_target, "Debug", strict);
        if (!resolved_transitive || resolved_transitive->package_products.size() != 1 ||
            resolved_transitive->package_products.front().product_name != "AbsentChildProduct" ||
            resolved_transitive->package_references.size() != 1 ||
            resolved_transitive->package_references.front().relative_path != "AbsentChildPackage")
            throw std::runtime_error("Selected target resolution did not collect transitive PBXTargetDependency package products");
        const auto transitive_build = PackageEngine::BuildXcodePackages(root.wstring(), bundle.wstring(),
            sdk, L"Debug", 1, nullptr, "TRANSITIVE_APP", &strict);
        if (transitive_build.success || !fs::exists(root / "build" / "xcode-packages-v4"))
            throw std::runtime_error("BuildXcodePackages did not attempt transitive package product resolution for TRANSITIVE_APP");
        fs::remove_all(root);
        std::cout << "Selected target package consumer passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "; owned fixture retained: " << root << '\n';
        return 1;
    }
}
