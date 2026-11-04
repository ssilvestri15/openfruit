#include "manifest_projection.hpp"

#include "json_value.hpp"
#include "operation_events.hpp"
#include "win32_process.hpp"
#include "text_util.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <optional>
#include <sstream>
#include <thread>
#include <unordered_set>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {


std::optional<fs::path> FindCheckout(
    const fs::path& checkouts,
    const std::string& identity
) {
    const fs::path exact = checkouts / identity;
    std::error_code ec;
    if (fs::is_directory(exact, ec) && !ec) {
        return exact;
    }

    if (!fs::is_directory(checkouts, ec) || ec) {
        return std::nullopt;
    }

    const std::string wanted = ToLowerAscii(identity);
    for (fs::directory_iterator it(
             checkouts,
             fs::directory_options::skip_permission_denied,
             ec);
         it != fs::directory_iterator();
         it.increment(ec)) {

        if (ec) {
            ec.clear();
            continue;
        }

        if (!it->is_directory(ec) || ec) {
            ec.clear();
            continue;
        }

        if (ToLowerAscii(it->path().filename().string()) == wanted) {
            return it->path();
        }
    }

    return std::nullopt;
}

std::optional<std::unordered_set<std::string>> DumpProducts(
    const fs::path& swift,
    const fs::path& package,
    const fs::path& scratch,
    const std::vector<std::pair<std::wstring, std::wstring>>& environment
) {
    const auto document = ManifestProjection::EvaluateOriginalManifest(
        swift, package, scratch, environment);
    if (!document) return std::nullopt;

    const JsonValue* products = document->Get("products");
    if (!products || !products->IsArray()) {
        return std::unordered_set<std::string>{};
    }

    std::unordered_set<std::string> names;
    for (const auto& product : products->ArrayItems()) {
        if (!product.IsObject()) {
            continue;
        }
        const std::string name = product.GetString("name");
        if (!name.empty()) {
            names.insert(name);
        }
    }

    return names;
}

std::vector<std::string> MissingProducts(
    const std::unordered_set<std::string>& available,
    const std::vector<std::string>& required
) {
    std::vector<std::string> missing;
    std::unordered_set<std::string> seen;

    for (const auto& product : required) {
        if (!seen.insert(product).second) {
            continue;
        }
        if (available.find(product) == available.end()) {
            missing.push_back(product);
        }
    }

    return missing;
}

std::string Join(const std::vector<std::string>& values) {
    std::ostringstream output;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0) {
            output << ", ";
        }
        output << values[i];
    }
    return output.str();
}

} // namespace

std::optional<JsonValue> ManifestProjection::EvaluateOriginalManifest(
    const fs::path& swift,
    const fs::path& package,
    const fs::path& scratch,
    const std::vector<std::pair<std::wstring, std::wstring>>& environment
) {
    ProcessRunOptions options;
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    options.capture_limit_bytes = 2 * 1024 * 1024;
    const ProcessResult dump = Win32Process::Run(
        swift.wstring(),
        {
            swift.wstring(),
            L"package",
            L"--package-path",
            package.wstring(),
            L"--scratch-path",
            scratch.wstring(),
            L"--cache-path",
            (scratch / "shared-cache").wstring(),
            L"--manifest-cache",
            L"local",
            L"dump-package"
        },
        package.wstring(),
        environment,
        nullptr,
        nullptr,
        options
    );

    if (!dump.success || dump.timed_out || dump.cancelled || dump.callback_failed ||
        dump.output_truncated || dump.std_out.empty()) {
        std::cerr << "OPENFRUIT SwiftPM: original manifest evaluation failed (exit "
                  << dump.exit_code << ", timeout=" << dump.timed_out
                  << ", cancelled=" << dump.cancelled
                  << ", truncated=" << dump.output_truncated << ").\n"
                  << dump.std_err << std::endl;
        return std::nullopt;
    }

    std::string error;
    const auto document = JsonValue::Parse(dump.std_out, &error);
    if (!document || !document->IsObject()) {
        return std::nullopt;
    }

    return document;
}

ManifestProjectionResult ManifestProjection::LoadExistingAppleHostOverlays(
    const fs::path&,
    const fs::path&,
    const std::vector<ManifestProjectionRequirement>&,
    const std::vector<std::pair<std::wstring, std::wstring>>&
) {
    // Historical overlays contain rewritten upstream manifests. Never evaluate,
    // admit or delete them: preserved bytes are diagnostic state, not authority.
    return {};
}

ManifestProjectionResult ManifestProjection::PrepareAppleHostOverlays(
    const fs::path& swift,
    const fs::path& scratch,
    const std::vector<ManifestProjectionRequirement>& requirements,
    const std::vector<std::pair<std::wstring, std::wstring>>& environment,
    const std::unordered_map<std::string, fs::path>& local_package_overrides
) {
    ManifestProjectionResult result;

    if (requirements.empty()) {
        return result;
    }

    const fs::path checkouts = scratch / "checkouts";
    std::vector<fs::path> packages;
    for (const auto& requirement : requirements) {
        const std::string normalized_identity =
            ToLowerAscii(requirement.identity);

        std::optional<fs::path> checkout;
        const auto local = local_package_overrides.find(normalized_identity);
        if (local != local_package_overrides.end()) {
            std::error_code ec;
            if (fs::is_directory(local->second, ec) && !ec) {
                checkout = local->second;
            }
        }
        if (!checkout) {
            checkout = FindCheckout(checkouts, requirement.identity);
        }
        if (!checkout) {
            std::cerr
                << "OPENFRUIT SwiftPM: direct package checkout missing for product validation: "
                << requirement.identity
                << std::endl;
            result.success = false;
            return result;
        }
        packages.push_back(*checkout);
    }

    // Each package evaluates in its own scratch, so the original manifests are
    // independent processes; run them concurrently and report in input order.
    std::vector<std::optional<std::unordered_set<std::string>>> evaluated(requirements.size());
    std::atomic<std::size_t> next{0};
    const auto operation = CurrentOperationContext();
    const auto evaluate = [&] {
        // Workers keep the build's cancellation, deadline and event journal.
        OperationBinding binding(operation);
        for (std::size_t index; (index = next++) < requirements.size();) {
            // Keep compiled manifest results outside source trees and outside the
            // global cache that may contain results from the historical rewriter.
            evaluated[index] = DumpProducts(swift, packages[index],
                scratch / "manifest-validation-original-v1" / ToLowerAscii(requirements[index].identity), environment);
        }
    };
    const std::size_t workers = std::min<std::size_t>(requirements.size(),
        std::max(1u, std::min(8u, std::thread::hardware_concurrency())));
    std::vector<std::thread> threads;
    for (std::size_t worker = 1; worker < workers; ++worker) threads.emplace_back(evaluate);
    evaluate();
    for (auto& thread : threads) thread.join();

    for (std::size_t index = 0; index < requirements.size(); ++index) {
        const auto& requirement = requirements[index];
        const auto& host_products = evaluated[index];
        if (!host_products) {
            std::cerr
                << "OPENFRUIT SwiftPM: unable to evaluate package manifest for product validation: "
                << requirement.identity
                << std::endl;
            result.success = false;
            return result;
        }

        const auto missing = MissingProducts(*host_products, requirement.required_products);
        if (missing.empty()) {
            continue;
        }

        std::cerr
            << "OPENFRUIT SwiftPM: original manifest does not expose required product(s) "
            << "on the selected host: " << requirement.identity << ": " << Join(missing)
            << ". An original compatible manifest host is required; source rewriting is disabled."
            << std::endl;
        result.success = false;
        return result;
    }

    return result;
}

} // namespace OpenFruit
