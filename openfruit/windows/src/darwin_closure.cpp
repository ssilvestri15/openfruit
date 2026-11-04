#include "darwin_closure.hpp"
#include "win32_process.hpp"
#include "dyld_cache.hpp"
#include <map>
#include <set>
#include <algorithm>
#include <stdexcept>
namespace OpenFruit {
namespace {
namespace fs = std::filesystem;
struct Invalid : std::runtime_error { using std::runtime_error::runtime_error; };
void Check(bool condition, const char* error) { if (!condition) throw Invalid(error); }
std::string Normal(const std::string& path) {
    Check(!path.empty() && path.front() == '/' && path.find('\\') == std::string::npos
        && path.find('\0') == std::string::npos && path.size() <= 32768, "Unsupported virtual Darwin path.");
    std::vector<std::string> parts;
    for (std::size_t begin = 1; begin <= path.size();) {
        const auto end = path.find('/', begin); const auto part = path.substr(begin, end == std::string::npos ? end : end - begin);
        if (part == "..") { Check(!parts.empty(), "Virtual Darwin path escapes root."); parts.pop_back(); }
        else if (!part.empty() && part != ".") parts.push_back(part);
        if (end == std::string::npos) break; begin = end + 1;
    }
    std::string result;
    for (const auto& part : parts) result += '/' + part;
    return result.empty() ? "/" : result;
}
std::string Parent(const std::string& path) { const auto end = path.rfind('/'); return end ? path.substr(0, end) : "/"; }
std::string Expand(const std::string& value, const std::string& owner, const std::string& executable) {
    for (const auto& [token, anchor] : std::vector<std::pair<std::string, std::string>>{
            {"@loader_path", Parent(owner)}, {"@executable_path", Parent(executable)}}) {
        if (value == token) return Normal(anchor);
        if (value.starts_with(token + '/')) return Normal(anchor + value.substr(token.size()));
    }
    return Normal(value); // Relative/unknown tokens fail; no Windows-CWD/basename fallback.
}
bool Within(const fs::path& root, const fs::path& target) {
    auto part = target.begin();
    for (const auto& component : root) { if (part == target.end() || *part != component) return false; ++part; }
    return true;
}
class Scan {
public:
    Scan(DarwinClosure& result, const DarwinClosureOptions& options, std::string executable)
        : result(result), options(options), executable(std::move(executable)) {}
    void Control() {
        const auto context = CurrentOperationContext();
        Check(!options.cancellation.Requested() && (!context || !context->CancellationRequested()), "Darwin closure cancelled.");
        Check(std::chrono::steady_clock::now() < options.deadline && (!context || !context->DeadlineExceeded()), "Darwin closure deadline exceeded.");
    }
    void Index(const std::vector<fs::path>& roots) {
        Check(!roots.empty(), "Original Darwin trees are required.");
        for (const auto& root : roots) {
            Control(); Check(root.is_absolute() && fs::is_directory(root) && !fs::is_symlink(root), "Invalid original Darwin tree.");
            const auto canonical_root = fs::canonical(root);
            result.original_directories.insert("/");
            for (const auto& entry : fs::recursive_directory_iterator(root)) {
                Control();
                if (entry.is_directory()) {
                    Check(!entry.is_symlink(), "Directory symlink mount traversal unsupported.");
                    Check(Within(canonical_root,fs::canonical(entry.path())),"Original directory escapes its mount.");
                    const auto key=Normal('/'+Win32Process::ToNarrow(entry.path().lexically_relative(root).generic_wstring()));
                    Check(!files.contains(key),"Original directory conflicts with file mount.");
                    result.original_directories.insert(key);
                    Check(result.original_directories.size()<=options.max_files,"Darwin directory catalog budget exceeded.");
                    continue;
                }
                Check(entry.is_regular_file(), "Unsupported original tree entry.");
                Check(files.size() < options.max_files, "Darwin closure file budget exceeded.");
                Check(Within(canonical_root, fs::canonical(entry.path())), "Original tree link escapes its mount.");
                const auto relative = entry.path().lexically_relative(root);
                const auto key = Normal('/' + Win32Process::ToNarrow(relative.generic_wstring()));
                Check(!result.original_directories.contains(key),"Original file conflicts with directory mount.");
                Check(files.emplace(key, fs::canonical(entry.path())).second, "Ambiguous original virtual file binding.");
                result.original_real_paths.emplace(key,Normal('/'+Win32Process::ToNarrow(fs::canonical(entry.path()).lexically_relative(canonical_root).generic_wstring())));
            }
        }
        result.original_files=files;
    }
    bool Has(const std::string& path, bool interpreter = false){
        const bool file=files.contains(path);std::string error;const bool cached=options.shared_cache&&options.shared_cache->ContainsImage(path,error);if(!error.empty())throw Invalid(error);
        if(!interpreter)Check(!(file&&cached),"Ambiguous original tree/cache path binding.");
        return file||cached;
    }
    DarwinImage Read(const std::string& path, bool root = false) {
        const auto file = files.find(path);if(file==files.end()){
            Check(options.shared_cache!=nullptr,"Original root image is missing.");DarwinImage cached;std::string error;if(!options.shared_cache->InspectImage(path,cached,error))throw Invalid(error);if(root){result.cpu=cached.cpu;platform=cached.platform;}else{Check(cached.cpu==result.cpu,"Cached dependency has no matching original CPU.");Check(!cached.platform||!platform||cached.platform==platform,"Cached dependency host platform differs.");}return cached;
        }
        if (root) {
            std::vector<DarwinImage> images; std::string error;
            if (!ReadDarwinImageSlices(file->second, images, error)) throw Invalid(error);
            auto selected = std::find_if(images.begin(), images.end(), [](const auto& image) { return image.cpu == DarwinProcessCpu(); });
            if (selected == images.end()) { Check(images.size() == 1, "Ambiguous foreign CPU root."); selected = images.begin(); }
            result.cpu = selected->cpu; platform = selected->platform; return *selected;
        }
        DarwinImage image; std::string error;
        if (!ReadDarwinImage(file->second, result.cpu, image, error)) throw Invalid(error);
        Check(!image.platform || !platform || image.platform == platform, "Dependency host platform differs.");
        return image;
    }
    void Visit(const std::string& path, std::vector<std::string> inherited, std::size_t depth, bool root = false, bool interpreter = false) {
        Control(); if (visited.contains(path)) return;
        Check(depth <= options.max_depth && result.images.size() < options.max_images, "Darwin closure image/depth budget exceeded.");
        Check(Has(path, interpreter),"Original root image is missing.");const auto image = Read(path, root); visited.insert(path);
        const auto source=files.find(path);result.images.push_back({path,source==files.end()?fs::path{}:source->second,image,source==files.end()});
        std::vector<std::string> search;
        for (const auto& value : image.rpaths) search.push_back(Expand(value, path, executable));
        for (const auto& value : inherited) if (std::find(search.begin(), search.end(), value) == search.end()) search.push_back(value);
        if (root) root_search = search;
        for (const auto& dependency : image.dependencies) Edge(path, dependency.install_name, dependency.weak, false, search, depth);
        if (!image.interpreter.empty()) Edge(path, image.interpreter, false, true, search, depth);
    }
    void Edge(const std::string& owner, const std::string& name, bool weak, bool interpreter,
        const std::vector<std::string>& search, std::size_t depth) {
        Control(); Check(result.edges.size() < options.max_edges, "Darwin closure edge budget exceeded.");
        DarwinClosureEdge edge; edge.owner = owner; edge.install_name = name; edge.weak = weak; edge.interpreter = interpreter;
        if (name.starts_with("@rpath/")) {
            for (const auto& path : search) edge.candidates.push_back(Normal(path + '/' + name.substr(7)));
        } else {
            edge.candidates.push_back(Expand(name, owner, executable));
            if (name.starts_with("@loader_path/")) {
                const auto sub = name.substr(13);
                for (const auto& path : search) edge.candidates.push_back(Normal(path + '/' + sub));
            }
        }
        for (const auto& candidate : edge.candidates) if (Has(candidate, interpreter)) { edge.resolved_path = candidate; break; }
        if (edge.resolved_path.empty()) edge.diagnostic = "No exact original virtual path provider.";
        const auto selected = edge.resolved_path; result.edges.push_back(std::move(edge));
        if (!selected.empty()) Visit(selected, search, depth + 1, false, interpreter);
    }
    DarwinClosure& result; const DarwinClosureOptions& options; std::string executable;
    std::vector<std::string> root_search;
private:
    std::map<std::string, fs::path> files;
    std::set<std::string> visited;
    std::uint32_t platform = 0;
};
}
DarwinClosure DarwinClosure::Inspect(const std::string& executable, const std::vector<std::string>& plugins,
    const std::vector<std::filesystem::path>& trees, const DarwinClosureOptions& options) {
    DarwinClosure result;result.original_cache=options.shared_cache;
    try {
        const auto main = Normal(executable); Scan scan(result, options, main); scan.Index(trees); scan.Visit(main, {}, 0, true);
        for (const auto& plugin : plugins) scan.Visit(Normal(plugin), scan.root_search, 0);
        result.analyzed = true;
    } catch (const std::exception& error) {
        result.diagnostic = error.what(); result.images.clear(); result.edges.clear(); result.cpu = 0;result.original_cache.reset();
    }
    return result;
}
bool DarwinClosure::StrongImagesResolved() const noexcept {
    return analyzed && std::all_of(edges.begin(), edges.end(), [](const auto& edge) { return edge.weak || !edge.resolved_path.empty(); });
}
std::string NormalizeDarwinVirtualPath(const std::string& path){return Normal(path);}
bool DarwinClosure::EagerInitializationOrder(const std::string& executable,
    const std::vector<std::string>& plugins,std::vector<std::string>& order,
    std::string& error,const DarwinClosureOptions& options) const {
    order.clear();error.clear();try {
        Check(StrongImagesResolved(),"Original initialization graph has unresolved strong images.");
        Check(images.size()<=options.max_images&&edges.size()<=options.max_edges,"Initialization graph budget exceeded.");
        std::map<std::string,const DarwinClosureImage*> nodes;
        std::map<std::pair<std::string,std::string>,std::string> dependencies;
        for(const auto& image:images)Check(nodes.emplace(image.virtual_path,&image).second,"Duplicate initialization image.");
        for(const auto& edge:edges)if(!edge.interpreter){
            const auto [where,inserted]=dependencies.emplace(std::make_pair(edge.owner,edge.install_name),edge.resolved_path);
            Check(inserted||where->second==edge.resolved_path,"Ambiguous initialization dependency.");
        }
        std::set<std::string> visited;std::vector<std::string> result;
        const auto control=[&]{const auto context=CurrentOperationContext();
            Check(!options.cancellation.Requested()&&(!context||!context->CancellationRequested()),"Initialization scheduling cancelled.");
            Check(std::chrono::steady_clock::now()<options.deadline&&(!context||!context->DeadlineExceeded()),"Initialization scheduling deadline exceeded.");};
        const auto visit=[&](const auto& self,const std::string& path,std::size_t depth,std::vector<std::string>& upward)->void {
            control();if(visited.contains(path))return;
            Check(depth<=options.max_depth,"Initialization dependency depth budget exceeded.");
            const auto node=nodes.find(path);Check(node!=nodes.end(),"Initialization root/provider is not loaded.");
            visited.insert(path); // Mark before descent to terminate dependency cycles.
            for(const auto& dependency:node->second->metadata.dependencies){
                Check(!dependency.lazy,"Lazy-library initialization policy is unavailable.");
                const auto selected=dependencies.find({path,dependency.install_name});
                Check(selected!=dependencies.end(),"Initialization dependency edge is absent.");
                if(selected->second.empty()){Check(dependency.weak,"Required initialization dependency is missing.");continue;}
                if(dependency.upward){if(std::find(upward.begin(),upward.end(),selected->second)==upward.end())upward.push_back(selected->second);}
                else self(self,selected->second,depth+1,upward);
            }
            result.push_back(path);
        };
        const auto root=[&](const std::string& path){std::vector<std::string> upward;visit(visit,Normal(path),0,upward);
            while(!upward.empty()){std::vector<std::string> next;for(const auto& image:upward)visit(visit,image,0,next);upward=std::move(next);}};
        root(executable);for(const auto& plugin:plugins)root(plugin);
        order=std::move(result);return true;
    } catch(const std::exception& failure){error=failure.what();return false;}
}
JsonValue DarwinClosure::ToJson() const {
    auto value = JsonValue::ObjectValue(), nodes = JsonValue::ArrayValue(), links = JsonValue::ArrayValue();
    value.Set("schema_version", JsonValue::Number("1")); value.Set("analysis_complete", JsonValue::Boolean(analyzed));
    value.Set("diagnostic", JsonValue::String(diagnostic)); value.Set("cpu", JsonValue::Number(std::to_string(cpu)));
    value.Set("strong_image_dependencies_resolved", JsonValue::Boolean(StrongImagesResolved()));
    if(original_cache){const auto& layout=original_cache->Layout();value.Set("original_cache_main_uuid",JsonValue::String(layout.Get("main")->GetString("uuid_hex")));value.Set("original_cache_source_image_sha256",JsonValue::String(layout.GetString("source_image_sha256")));value.Set("original_cache_mapping_count",JsonValue::Number(std::to_string(layout.Get("mappings")->ArrayItems().size())));}
    value.Set("execution_validated", JsonValue::Boolean(false)); value.Set("runtime_closure_validated", JsonValue::Boolean(false));
    for (const auto& image : images) {
        auto node = image.metadata.ToJson(); node.Set("virtual_path", JsonValue::String(image.virtual_path));
        node.Set("source", JsonValue::String(Win32Process::ToNarrow(image.source.wstring())));node.Set("source_kind",JsonValue::String(image.shared_cache?"original-dyld-cache-vm":"original-file"));node.Set("sha256_scope",JsonValue::String(image.shared_cache?"original-macho-header-load-commands":"original-file")); nodes.ArrayItems().push_back(std::move(node));
    }
    for (const auto& edge : edges) {
        auto link = JsonValue::ObjectValue(), candidates = JsonValue::ArrayValue();
        link.Set("owner", JsonValue::String(edge.owner)); link.Set("install_name", JsonValue::String(edge.install_name));
        link.Set("resolved_path", JsonValue::String(edge.resolved_path)); link.Set("diagnostic", JsonValue::String(edge.diagnostic));
        link.Set("weak", JsonValue::Boolean(edge.weak)); link.Set("interpreter", JsonValue::Boolean(edge.interpreter));
        for (const auto& path : edge.candidates) candidates.ArrayItems().push_back(JsonValue::String(path));
        link.Set("candidates", std::move(candidates)); links.ArrayItems().push_back(std::move(link));
    }
    value.Set("images", std::move(nodes)); value.Set("edges", std::move(links)); return value;
}
}
