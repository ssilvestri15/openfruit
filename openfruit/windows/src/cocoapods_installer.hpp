#pragma once

#include "artifact_store.hpp"
#include "win32_process.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace OpenFruit {

// CocoaPods sandbox contract, as checked by the "[CP] Check Pods Manifest.lock"
// build phase: the installation root is current only when Pods/Manifest.lock
// is byte-identical to Podfile.lock.
bool CocoaPodsSandboxCurrent(const std::filesystem::path& installation_root);

// The CocoaPods version recorded by Podfile.lock ("COCOAPODS: x.y.z").
std::optional<std::string> CocoaPodsLockedVersion(const std::filesystem::path& podfile_lock);

// Runs the original CocoaPods `pod install --deployment` of the locked version
// in an installation root (a projected source view, never the user's
// checkout) whose Podfile.lock is present but whose sandbox is not current.
// Returns false without changes when the root has no locked Podfile.
bool EnsureCocoaPodsSandbox(const std::filesystem::path& installation_root,
                            const ProcessRunOptions& control = {});

// As `pod install` precedes an Xcode build, a target whose locked Podfile has
// no current sandbox in the checkout is redirected to an owned view of that
// checkout (below views_parent) in which the sandbox is installed. The caller
// holds the lease while the view is read. Returns nullopt when the checkout's
// sandbox is already current or no locked Podfile applies.
struct CocoaPodsView {
    std::filesystem::path target;
    std::shared_ptr<ArtifactLease> lease;
};
std::optional<CocoaPodsView> PrepareCocoaPodsView(const std::filesystem::path& target,
    const std::filesystem::path& source_root, const std::filesystem::path& views_parent,
    const ProcessRunOptions& control = {});

} // namespace OpenFruit
