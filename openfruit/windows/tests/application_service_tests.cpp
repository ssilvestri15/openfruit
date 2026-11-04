#include "application_service.hpp"

#include <filesystem>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace OpenFruit;
namespace fs = std::filesystem;
namespace {
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }

BuildContext Context(const fs::path& root, OperationContextPtr operation) {
    BuildContext context;
    context.repository_root = root / "repository";
    context.configuration.user_state_root = (root / "state").wstring();
    context.configuration.cache_root = (root / "cache").wstring();
    context.configuration.toolchain_path = (root / "compiler").wstring();
    context.credentials.signing_password = L"DO-NOT-SERIALIZE-APPLICATION-CREDENTIAL";
    context.operation = std::move(operation);
    return context;
}

void TerminalBeforeMutation(const fs::path& root) {
    BuildRequest request;
    request.project.path = root / "must-not-be-inspected.xcodeproj";
    auto outer = std::make_shared<OperationContext>();
    outer->build_id = "outer-operation";
    OperationBinding binding(outer);
    auto cancelled = std::make_shared<OperationContext>();
    cancelled->build_id = "cancelled-operation";
    cancelled->control->cancellation_requested = true;
    const auto context = Context(root, cancelled);
    const auto original_toolchain = context.configuration.toolchain_path;
    const auto original_request = request.project.path;
    const auto result = ApplicationService::Build(request, context);
    Require(result.exit_code == 130 && result.outcome == BuildOutcome::Cancelled,
        "Cancelled request entered native discovery or returned ordinary failure");
    Require(CurrentOperationContext() == outer && !outer->CancellationRequested(),
        "Explicit service operation escaped its thread binding or cancelled the caller");
    Require(context.configuration.toolchain_path == original_toolchain && request.project.path == original_request,
        "Application service changed its immutable input snapshot");
    Require(!fs::exists(root), "Pre-cancelled application operation created user state");
    Require(result.ToJson().Serialize().find("DO-NOT-SERIALIZE") == std::string::npos,
        "Application result exposed credential snapshot");

    auto expired = std::make_shared<OperationContext>();
    expired->control = std::make_shared<OperationControl>(
        std::chrono::steady_clock::now() - std::chrono::seconds(1));
    const auto timeout = ApplicationService::Build(request, Context(root, expired));
    Require(timeout.exit_code == 124 && timeout.outcome == BuildOutcome::TimedOut,
        "Expired request reached project discovery or hid its deadline");
    Require(!fs::exists(root) && CurrentOperationContext() == outer,
        "Expired operation changed state or its caller binding");
}

void InvalidRequestIsNotAnOperation(const fs::path& root) {
    const auto context = Context(root, std::make_shared<OperationContext>());
    BuildRequest request;
    request.project.path = "relative.xcodeproj";
    Require(ApplicationService::Build(request, context).outcome == BuildOutcome::InvalidRequest,
        "Relative application input was resolved against a hidden working directory");
    request.project.path = root / "not-opened.xcodeproj";
    request.sdk_path = L"relative-sdk";
    Require(ApplicationService::Build(request, context).exit_code == 2,
        "Relative explicit SDK was not rejected at the service boundary");
    request.sdk_path.reset();
    request.mode = BuildProductMode::UnsignedPackage;
    request.p12_path = L""; // Presence is an explicit override, including empty.
    Require(ApplicationService::Build(request, context).outcome == BuildOutcome::InvalidRequest,
        "Unsigned package silently accepted an explicit signing override");
    request.p12_path.reset();
    request.deploy = true;
    Require(ApplicationService::Build(request, context).exit_code == 2,
        "Unsigned package silently accepted deployment");
    request.deploy = false;
    request.project.action = ProjectBuildAction::Testing;
    Require(ApplicationService::Build(request, context).exit_code == 2,
        "Build purpose without a scheme entered the build pipeline");
    Require(!fs::exists(root), "Invalid request initialized or touched user state");
}

void IndependentControls(const fs::path& root) {
    auto left = std::make_shared<OperationContext>();
    auto right = std::make_shared<OperationContext>();
    left->control->cancellation_requested = true;
    BuildRequest request;
    request.project.path = root / "not-opened.xcodeproj";
    request.cache_path = L"relative-cache";
    auto first = std::async(std::launch::async, [&] {
        return ApplicationService::Build(request, Context(root, left));
    });
    auto second = std::async(std::launch::async, [&] {
        return ApplicationService::Build(request, Context(root, right));
    });
    Require(first.get().outcome == BuildOutcome::Cancelled &&
        second.get().outcome == BuildOutcome::InvalidRequest && !right->CancellationRequested(),
        "Application operation controls contaminated another request");
    Require(!fs::exists(root), "Preflight controls unexpectedly invoked a build");
}
}

int main() {
    const auto root = fs::temp_directory_path() / ("openfruit-application-service-" + NewOperationId());
    try {
        TerminalBeforeMutation(root);
        InvalidRequestIsNotAnOperation(root);
        IndependentControls(root);
        std::cout << "Application service preflight, binding and snapshot contracts passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "; owned test root: " << root << '\n';
        return 1;
    }
}
