#include "xcode_scheme.hpp"
#include "content_hash.hpp"
#include "win32_process.hpp"

#include <windows.h>
#include <shlwapi.h>
#include <xmllite.h>
#include <wrl/client.h>
#include <algorithm>
#include <cwctype>
#include <fstream>
#include <map>
#include <set>

namespace fs = std::filesystem;
namespace OpenFruit {
namespace {
using Microsoft::WRL::ComPtr;
constexpr std::size_t kMetadataBytes = 8 * 1024 * 1024;
struct XmlNode {
    std::wstring name;
    std::map<std::wstring, std::wstring> attributes;
    std::vector<std::size_t> children;
    std::wstring Attribute(const wchar_t* key) const {
        const auto found = attributes.find(key);
        return found == attributes.end() ? L"" : found->second;
    }
};
using XmlTree = std::vector<XmlNode>;
void Error(std::string* error, const std::string& message) { if (error) *error = message; }
std::optional<XmlTree> ReadXml(std::string_view bytes, const wchar_t* root_name, std::string* error) {
    if (bytes.empty() || bytes.size() > kMetadataBytes) {
        Error(error, "Xcode XML metadata is empty or exceeds its byte limit."); return std::nullopt;
    }
    ComPtr<IStream> stream;
    stream.Attach(SHCreateMemStream(reinterpret_cast<const BYTE*>(bytes.data()), static_cast<UINT>(bytes.size())));
    ComPtr<IXmlReader> xml;
    if (!stream || FAILED(CreateXmlReader(__uuidof(IXmlReader), reinterpret_cast<void**>(xml.GetAddressOf()), nullptr)) ||
        FAILED(xml->SetProperty(XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit)) ||
        FAILED(xml->SetProperty(XmlReaderProperty_MaxElementDepth, 64)) || FAILED(xml->SetInput(stream.Get()))) {
        Error(error, "Cannot initialize the Xcode XML reader."); return std::nullopt;
    }
    XmlTree tree; std::vector<std::size_t> stack;
    XmlNodeType type{}; HRESULT result = S_OK;
    while ((result = xml->Read(&type)) == S_OK) {
        if (type == XmlNodeType_Element) {
            if (tree.size() >= 50000) { Error(error, "Xcode XML element limit exceeded."); return std::nullopt; }
            const wchar_t* name = nullptr; const wchar_t* ns = nullptr;
            if (FAILED(xml->GetLocalName(&name, nullptr)) || !name ||
                FAILED(xml->GetNamespaceUri(&ns, nullptr))) {
                Error(error, "Cannot read Xcode XML element identity."); return std::nullopt;
            }
            XmlNode node;
            node.name = ns && *ns ? L"{" + std::wstring(ns) + L"}" + name : name;
            UINT count = 0;
            if (FAILED(xml->GetAttributeCount(&count)) || count > 128) {
                Error(error, "Xcode XML attribute limit exceeded."); return std::nullopt;
            }
            HRESULT attribute = xml->MoveToFirstAttribute();
            while (attribute == S_OK) {
                const wchar_t* local = nullptr; const wchar_t* uri = nullptr; const wchar_t* value = nullptr;
                UINT length = 0;
                if (FAILED(xml->GetLocalName(&local, nullptr)) || !local ||
                    FAILED(xml->GetNamespaceUri(&uri, nullptr)) ||
                    FAILED(xml->GetValue(&value, &length)) || !value || length > 65536) {
                    Error(error, "Cannot read bounded Xcode XML attribute."); return std::nullopt;
                }
                const auto key = uri && *uri ? L"{" + std::wstring(uri) + L"}" + local : std::wstring(local);
                node.attributes.emplace(key, std::wstring(value, length));
                attribute = xml->MoveToNextAttribute();
            }
            if (FAILED(attribute) || FAILED(xml->MoveToElement())) {
                Error(error, "Malformed Xcode XML attributes."); return std::nullopt;
            }
            if (stack.empty() && (!tree.empty() || node.name != root_name)) {
                Error(error, "Unexpected Xcode XML root."); return std::nullopt;
            }
            const auto index = tree.size(); tree.push_back(std::move(node));
            if (!stack.empty()) tree[stack.back()].children.push_back(index);
            if (!xml->IsEmptyElement()) stack.push_back(index);
        } else if (type == XmlNodeType_EndElement) {
            if (stack.empty()) { Error(error, "Malformed Xcode XML nesting."); return std::nullopt; }
            stack.pop_back();
        }
    }
    if (result != S_FALSE || tree.empty() || !stack.empty()) {
        Error(error, "Malformed Xcode XML metadata (DTD declarations are prohibited)."); return std::nullopt;
    }
    return tree;
}
std::vector<std::size_t> Children(const XmlTree& tree, std::size_t parent, const wchar_t* name) {
    std::vector<std::size_t> result;
    for (const auto child : tree[parent].children) if (tree[child].name == name) result.push_back(child);
    return result;
}
std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    return value;
}
bool Container(const fs::path& path, const wchar_t* suffix) { return Lower(path.extension().wstring()) == suffix; }
std::optional<fs::path> Location(const std::wstring& location, const fs::path& group,
    const fs::path& container, bool allow_empty, std::string* error) {
    const auto colon = location.find(L':');
    if (colon == std::wstring::npos) { Error(error, "Xcode container reference has no supported location kind."); return std::nullopt; }
    const auto kind = location.substr(0, colon); const fs::path value(location.substr(colon + 1));
    if (value.empty() && !allow_empty) { Error(error, "Xcode container reference is empty."); return std::nullopt; }
    if (kind == L"absolute") {
        if (!value.is_absolute()) { Error(error, "Absolute Xcode container reference is not absolute on this host."); return std::nullopt; }
        return value.lexically_normal();
    }
    if ((kind != L"group" && kind != L"container") || value.is_absolute() || value.has_root_name() || value.has_root_directory()) {
        Error(error, "Unsupported Xcode container reference location kind or rooted relative path."); return std::nullopt;
    }
    return ((kind == L"group" ? group : container) / value).lexically_normal();
}
std::optional<XcodeTargetDependency> Reference(const XmlNode& reference, const fs::path& owner, std::string* error) {
    const auto id = reference.Attribute(L"BlueprintIdentifier");
    const auto location = reference.Attribute(L"ReferencedContainer");
    if (id.empty() || location.empty()) {
        Error(error, "Selected scheme build reference has no qualified target UUID/container."); return std::nullopt;
    }
    if (!location.starts_with(L"container:")) {
        Error(error, "Unsupported scheme build reference container location."); return std::nullopt;
    }
    const auto project = Location(location, owner.parent_path(), owner.parent_path(), false, error);
    if (!project || !Container(*project, L".xcodeproj")) {
        if (project) Error(error, "Selected scheme reference does not identify an Xcode project.");
        return std::nullopt;
    }
    XcodeTargetDependency result;
    result.target_id = Win32Process::ToNarrow(id);
    result.name = result.target_name = Win32Process::ToNarrow(reference.Attribute(L"BlueprintName"));
    result.project_path = *project; result.scheme_entry = true;
    result.is_subproject = owner.lexically_normal() != *project;
    return result;
}
const wchar_t* Flag(ProjectBuildAction action) {
    switch (action) {
    case ProjectBuildAction::Running: return L"buildForRunning";
    case ProjectBuildAction::Testing: return L"buildForTesting";
    case ProjectBuildAction::Profiling: return L"buildForProfiling";
    case ProjectBuildAction::Analyzing: return L"buildForAnalyzing";
    case ProjectBuildAction::Archiving: return L"buildForArchiving";
    default: return L"";
    }
}
const wchar_t* ActionTag(ProjectBuildAction action) {
    switch (action) {
    case ProjectBuildAction::Running: return L"LaunchAction";
    case ProjectBuildAction::Testing: return L"TestAction";
    case ProjectBuildAction::Profiling: return L"ProfileAction";
    case ProjectBuildAction::Analyzing: return L"AnalyzeAction";
    case ProjectBuildAction::Archiving: return L"ArchiveAction";
    default: return L"";
    }
}
std::optional<bool> OptionalFlag(const XmlNode& node, const wchar_t* key, std::vector<std::string>& diagnostics) {
    const auto value = node.Attribute(key);
    if (value == L"YES") return true;
    if (value == L"NO") return false;
    diagnostics.push_back("Scheme flag '" + Win32Process::ToNarrow(key) + "' is absent or unknown.");
    return std::nullopt;
}
}

std::optional<XcodeSchemeSelection> XcodeScheme::Parse(const fs::path& logical_scheme_path,
    const fs::path& owner_container, std::string_view bytes, ProjectBuildAction action, std::string* error) {
    if (error) error->clear();
    if (!logical_scheme_path.is_absolute() || !owner_container.is_absolute() ||
        (!Container(owner_container, L".xcodeproj") && !Container(owner_container, L".xcworkspace"))) {
        Error(error, "Scheme parsing requires an absolute logical file and owning project/workspace."); return std::nullopt;
    }
    const auto tree = ReadXml(bytes, L"Scheme", error);
    if (!tree) return std::nullopt;
    const auto build_actions = Children(*tree, 0, L"BuildAction");
    if (build_actions.size() != 1) { Error(error, "Scheme must declare exactly one BuildAction."); return std::nullopt; }
    const auto build = build_actions.front();
    for (const auto* phase : {L"PreActions", L"PostActions"})
        for (const auto index : Children(*tree, build, phase))
            if (!Children(*tree, index, L"ExecutionAction").empty()) {
                Error(error, "Scheme BuildAction execution actions are not implemented."); return std::nullopt;
            }
    const auto build_entries = Children(*tree, build, L"BuildActionEntries");
    if (build_entries.size() != 1) { Error(error, "Scheme must declare exactly one BuildActionEntries collection."); return std::nullopt; }
    XcodeSchemeSelection result;
    result.scheme_file = logical_scheme_path.lexically_normal(); result.owner_container = owner_container.lexically_normal();
    result.action = action;
    const auto digest = Sha256(bytes);
    if (!digest) { Error(error, "Cannot bind scheme metadata content identity."); return std::nullopt; }
    result.content_sha256 = *digest;
    result.build_implicit_dependencies = OptionalFlag((*tree)[build], L"buildImplicitDependencies", result.diagnostics);
    result.parallelize_buildables = OptionalFlag((*tree)[build], L"parallelizeBuildables", result.diagnostics);
    for (const auto entry : Children(*tree, build_entries.front(), L"BuildActionEntry")) {
        bool enabled = false;
        if (action == ProjectBuildAction::LegacyProductBuild) {
            enabled = false;
            for (const auto purpose : {ProjectBuildAction::Running, ProjectBuildAction::Profiling,
                     ProjectBuildAction::Archiving, ProjectBuildAction::Analyzing})
                if ((*tree)[entry].Attribute(Flag(purpose)) != L"NO") enabled = true;
        } else {
            const auto value = (*tree)[entry].Attribute(Flag(action));
            if (value == L"NO") continue;
            if (value != L"YES") { Error(error, "Selected scheme entry has an absent or unknown build-purpose flag."); return std::nullopt; }
            enabled = true;
        }
        if (!enabled) continue;
        const auto references = Children(*tree, entry, L"BuildableReference");
        if (references.size() != 1) { Error(error, "Selected scheme entry must contain exactly one BuildableReference."); return std::nullopt; }
        auto reference = Reference((*tree)[references.front()], result.owner_container, error);
        if (!reference) return std::nullopt;
        result.build_entries.push_back(std::move(*reference));
    }
    if (action != ProjectBuildAction::LegacyProductBuild) {
        const auto actions = Children(*tree, 0, ActionTag(action));
        if (actions.size() > 1) { Error(error, "Scheme selected action is ambiguous."); return std::nullopt; }
        if (!actions.empty()) {
            const auto selected = actions.front();
            result.configuration = Win32Process::ToNarrow((*tree)[selected].Attribute(L"buildConfiguration"));
            if (action == ProjectBuildAction::Running || action == ProjectBuildAction::Profiling) {
                const auto runnables = Children(*tree, selected, L"BuildableProductRunnable");
                if (runnables.size() > 1) { Error(error, "Scheme has multiple runnable products for the selected action."); return std::nullopt; }
                if (!runnables.empty()) {
                    const auto references = Children(*tree, runnables.front(), L"BuildableReference");
                    if (references.size() != 1) { Error(error, "Scheme runnable has no unique BuildableReference."); return std::nullopt; }
                    result.runnable = Reference((*tree)[references.front()], result.owner_container, error);
                    if (!result.runnable) return std::nullopt;
                }
            }
        }
    }
    return result;
}

std::optional<XcodeSchemeSelection> XcodeScheme::Inspect(const fs::path& scheme_path,
    const fs::path& owner_container, ProjectBuildAction action, std::string* error) {
    if (error) error->clear();
    std::ifstream input(scheme_path, std::ios::binary | std::ios::ate);
    if (!input || input.tellg() < 0 || input.tellg() > static_cast<std::streamoff>(kMetadataBytes)) {
        Error(error, "Cannot read bounded scheme metadata."); return std::nullopt;
    }
    std::string bytes(static_cast<std::size_t>(input.tellg()), '\0'); input.seekg(0);
    if (!input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()))) {
        Error(error, "Cannot read complete scheme metadata."); return std::nullopt;
    }
    return Parse(scheme_path, owner_container, bytes, action, error);
}

std::optional<XcodeWorkspaceContents> XcodeWorkspace::Parse(const fs::path& logical_workspace_path,
    std::string_view bytes, std::string* error) {
    if (error) error->clear();
    if (!logical_workspace_path.is_absolute() || !Container(logical_workspace_path, L".xcworkspace")) {
        Error(error, "Workspace parsing requires an absolute logical workspace path."); return std::nullopt;
    }
    const auto tree = ReadXml(bytes, L"Workspace", error);
    if (!tree) return std::nullopt;
    XcodeWorkspaceContents result;
    const auto container = logical_workspace_path.parent_path().lexically_normal();
    std::vector<std::pair<std::size_t, fs::path>> pending{{0, container}};
    std::set<fs::path> projects, other;
    while (!pending.empty()) {
        const auto [index, group] = pending.back(); pending.pop_back();
        const auto& node = (*tree)[index];
        auto base = group;
        if (node.name == L"FileRef") {
            const auto path = Location(node.Attribute(L"location"), group, container, false, error);
            if (!path) return std::nullopt;
            if (Container(*path, L".xcodeproj")) {
                if (projects.insert(*path).second) result.projects.push_back(*path);
            } else if (other.insert(*path).second) result.other_references.push_back(*path);
            continue;
        }
        if (node.name == L"Group") {
            const auto location = node.Attribute(L"location");
            if (!location.empty()) {
                const auto resolved = Location(location, group, container, true, error);
                if (!resolved) return std::nullopt;
                base = *resolved;
            }
        } else if (index != 0) continue;
        // Reverse insertion, then pop one node at a time to retain XML order
        // across both direct references and nested groups.
        for (auto it = node.children.rbegin(); it != node.children.rend(); ++it)
            pending.emplace_back(*it, base);
    }
    return result;
}

} // namespace OpenFruit
