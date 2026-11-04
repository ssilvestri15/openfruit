#include "darwin_progress.hpp"
#include "content_hash.hpp"
#include <fstream>
#include <climits>
#include <deque>
#include <utility>
#include <initializer_list>
#include <map>
#include <set>
#include <stdexcept>

namespace OpenFruit {
namespace {
const JsonValue empty;
const JsonValue& Field(const JsonValue& v,const std::string& key){const auto* p=v.Get(key);return p?*p:empty;}
const JsonValue& At(const JsonValue& v,const std::string& path){
    const JsonValue* p=&v;std::size_t start=0;
    while(start<path.size()){const auto end=path.find('.',start);p=p->Get(path.substr(start,end-start));if(!p)return empty;
        if(end==std::string::npos)break;start=end+1;}
    return *p;
}
JsonValue N(std::size_t n){return JsonValue::Number(std::to_string(n));}
JsonValue Strings(const std::set<std::string>& values){auto a=JsonValue::ArrayValue();for(const auto& s:values)a.ArrayItems().push_back(JsonValue::String(s));return a;}
struct Input {JsonValue value;std::string hash;std::filesystem::path path;};
Input Read(const std::filesystem::path& path,std::uintmax_t limit=256ULL*1024*1024){
    const auto size=std::filesystem::file_size(path);if(size>limit)throw std::runtime_error("Darwin progress input exceeds diagnostic limit");
    std::ifstream f(path,std::ios::binary);if(!f)throw std::runtime_error("Cannot read Darwin progress input");
    std::string text(static_cast<std::size_t>(size),'\0');f.read(text.data(),static_cast<std::streamsize>(size));
    if(static_cast<std::uintmax_t>(f.gcount())!=size)throw std::runtime_error("Incomplete Darwin progress input read");
    const auto hash=Sha256(text);if(!hash)throw std::runtime_error("Cannot hash Darwin progress input");
    if(text.starts_with("\xef\xbb\xbf"))text.erase(0,3);
    std::string error;auto json=JsonValue::Parse(text,&error);if(!json||!json->IsObject())throw std::runtime_error("Invalid Darwin progress JSON: "+error);
    return {std::move(*json),*hash,std::filesystem::absolute(path)};
}
std::string Domain(int id){if(id==INT32_MIN)return "platform";if(id==-3||id==-4)return "arm-trap";return id<0?"mach":"bsd";}
std::string Key(int id){return Domain(id)+":"+std::to_string(id);}
struct ActiveSvc {JsonValue raw,selector;std::string source;};
ActiveSvc CurrentSvc(const JsonValue& bootstrap){
    ActiveSvc result;
    if(Field(bootstrap,"interrupt").Int()!=2||Field(bootstrap,"last_instruction_opcode").Serialize()!="3556773889")return result;
    const JsonValue* registers=nullptr;
    const auto& recent=Field(bootstrap,"last_instructions").ArrayItems();
    if(!recent.empty()){
        const auto& last=recent.back();
        if(Field(last,"pc").Serialize()==Field(bootstrap,"last_instruction_pc").Serialize()
            &&Field(last,"opcode").Serialize()=="3556773889"){
            registers=&Field(last,"registers");result.source="pre-trap-registers";
        }
    }
    if(!registers&&!Field(bootstrap,"registers").ArrayItems().empty()){
        registers=&Field(bootstrap,"registers");result.source="stop-registers";
    }
    try{
        if(registers){
            const auto& values=registers->ArrayItems();
            if(values.size()<=16)return {};
            result.raw=values[16];
            const auto raw=std::stoull(result.raw.Serialize());
            // syscall(2) carries the effective BSD selector in pre-trap X0.
            // Post-return X0 is a result, so cannot identify an indirect call.
            if(!raw&&result.source!="pre-trap-registers")return {};
            const auto selected=raw?raw:std::stoull(values[0].Serialize());
            result.selector=JsonValue::Number(std::to_string(static_cast<std::int32_t>(selected)));
        }else{
            // Legacy reports may have no register snapshots. Keep provenance
            // explicit; never prefer this potentially stale field to registers.
            result.raw=Field(bootstrap,"syscall_selector");
            const auto raw=std::stoull(result.raw.Serialize());
            if(!raw)return {};
            result.selector=JsonValue::Number(std::to_string(static_cast<std::int32_t>(raw)));
            result.source="legacy-selector-field";
        }
    }catch(...){return {};}
    return result;
}
std::string SymbolFamily(const std::string& s){
    if(s.starts_with("_$s")||s.starts_with("_$S")||s.starts_with("_swift_"))return "swift";
    if(s.starts_with("_objc_")||s.starts_with("_OBJC_"))return "objective-c";
    if(s.find("pthread")!=std::string::npos)return "pthread";
    if(s.find("tlv")!=std::string::npos||s.find("tls")!=std::string::npos)return "tls";
    if(s.find("commpage")!=std::string::npos)return "commpage";
    if(s.starts_with("_mach_")||s.starts_with("_host_")||s.starts_with("_mig_"))return "mach";
    return "other-or-unclassified";
}
struct Selector {int id=0;std::size_t sites=0;std::set<std::string> images,names;};
std::string SelectorWorkgroup(int id,const JsonValue& names){
    for(const auto& value:names.ArrayItems()){
        const auto name=value.StringValue();
        for(const auto* part:{"bsdthread","pthread","workq","psynch","ulock","semaphore","thread_switch"})
            if(name.find(part)!=std::string::npos)return "pthread/TLS";
        if(name.find("mach_vm")!=std::string::npos)return "Mach VM";
        for(const auto* vm:{"mmap","munmap","mprotect","madvise","mincore","shared_region_check_np","map_with_linking_np"})
            if(name==vm||name==std::string("_")+vm)return "Mach VM";
    }
    if(id==INT32_MIN)return "pthread/TLS";
    if(id==-3||id==-4||id==-89)return "ABI/clock";
    return id<0?"Mach IPC":"BSD";
}


// Dependency certainty and execution evidence are independent dimensions.
JsonValue TargetRequirements(const JsonValue& inventory,const JsonValue& bootstrap,bool bound) {
    auto targets=JsonValue::ArrayValue();
    std::map<std::string,const JsonValue*> images;
    for(const auto& image:Field(inventory,"images").ArrayItems()) {
        const auto name=image.GetString("image");
        if(name.empty()||!images.emplace(name,&image).second)throw std::runtime_error("Invalid/duplicate inventory image");
    }
    std::map<std::string,std::vector<const JsonValue*>> edges;
    for(const auto& edge:Field(inventory,"dependency_edges").ArrayItems())edges[edge.GetString("owner")].push_back(&edge);
    std::set<std::pair<std::string,int>> observations;std::size_t unparsed=0;
    std::map<std::string,int> registry;
    for(const auto& handler:Field(bootstrap,"service_manifest").ArrayItems())if(Field(handler,"selector_id").IsNumber())registry[handler.GetString("name")]=Field(handler,"selector_id").Int();
    for(const auto& [path,service]:std::initializer_list<std::pair<const char*,const char*>>{
        {"clock_call_prefix",""},{"timebase_info.call_prefix",""},{"file_call_prefix",""},{"mach_task.call_prefix",""},
        {"mach_ports.call_prefix",""},{"mach_ports.rights_call_prefix",""},{"thread_identity.call_prefix",""},
        {"entropy.call_prefix","getentropy"},{"calendar.call_prefix","gettimeofday"},
        {"mach_msg2_calls","mach_msg2_trap"},{"thread_identity.platform_prefix","platform_syscall"}})
        for(const auto& call:At(bootstrap,path).ArrayItems()) {
            try {
                if(!Field(call,"pc").IsNumber())throw std::runtime_error("Trace PC unavailable");
                int selector;
                if(Field(call,"selector").IsNumber())selector=static_cast<std::int32_t>(std::stoull(Field(call,"selector").Serialize()));
                else if(registry.contains(service))selector=registry.at(service);
                else throw std::runtime_error("Trace service identity unavailable");
                observations.emplace(Field(call,"pc").Serialize(),selector);
            }catch(...){++unparsed;} // Uninterpretable trace records stay explicit.
        }
    const auto active=CurrentSvc(bootstrap);
    if(active.selector.IsNumber())observations.emplace(Field(bootstrap,"last_instruction_pc").Serialize(),active.selector.Int());
    std::set<std::pair<std::string,int>> matched;
    for(const auto& site:Field(inventory,"svc_sites").ArrayItems())
        if(Field(site,"selector_id").IsNumber()&&Field(site,"opcode").Serialize()=="3556773889"&&
           observations.contains({Field(site,"pc").Serialize(),Field(site,"selector_id").Int()}))
            matched.emplace(Field(site,"pc").Serialize(),Field(site,"selector_id").Int());
    for(const auto& root_value:Field(inventory,"target_roots").ArrayItems()) {
        const auto root=root_value.StringValue();if(!images.contains(root))throw std::runtime_error("Target root absent from inventory");
        struct Witness {int rank;std::vector<std::string> path;};
        std::map<std::string,Witness> reached;reached.emplace(root,Witness{2,{root}});std::deque<std::string> pending{root};
        while(!pending.empty()) {
            const auto owner=pending.front();pending.pop_front();const auto source=reached.at(owner);
            for(const auto* edge:edges[owner]) {
                const auto to=edge->GetString("resolved_path");if(!images.contains(to))continue;
                bool potential=Field(*edge,"weak").Bool();
                for(const auto& dep:Field(*images.at(owner),"dependencies").ArrayItems())
                    if(dep.GetString("install_name")==edge->GetString("install_name")&&Field(dep,"lazy").Bool())potential=true;
                const auto rank=potential?1:source.rank;
                if(reached.contains(to)&&reached.at(to).rank>=rank)continue;
                auto path=source.path;path.push_back(to);reached[to]={rank,std::move(path)};pending.push_back(to);
            }
        }
        bool target_bound=false;
        const auto& opened=At(bootstrap,"original_files.open_prefix").ArrayItems();
        if(!opened.empty())target_bound=opened.front().GetString("virtual_path")==root&&
            images.at(root)->GetString("sha256").size()==64&&opened.front().GetString("sha256")==images.at(root)->GetString("sha256");
        std::set<std::pair<std::string,int>> target_matched;
        auto target=JsonValue::ObjectValue(),components=JsonValue::ArrayValue(),gaps=JsonValue::ArrayValue();
        std::size_t certain=0,potential=0,refs=0,unknown_refs=0,weak_refs=0,nonweak_refs=0;
        std::map<std::string,JsonValue> workgroups;std::map<std::string,std::set<std::string>> target_symbols;
        for(const auto& [name,witness]:reached) {
            auto row=JsonValue::ObjectValue();row.Set("image",JsonValue::String(name));
            row.Set("dependency_requirement",JsonValue::String(witness.rank==2?"structural-required":"potential"));
            witness.rank==2?++certain:++potential;
            auto path=JsonValue::ArrayValue();for(const auto& node:witness.path)path.ArrayItems().push_back(JsonValue::String(node));row.Set("dependency_witness",std::move(path));
            row.Set("reachability",Field(*images.at(name),"reachability"));row.Set("coverage_gaps",Field(*images.at(name),"coverage_gaps"));
            std::set<std::string> symbols;std::size_t count=0;
            for(const auto& import:Field(inventory,"imports").ArrayItems())if(import.GetString("image")==name) {
                ++count;++refs;const auto symbol=import.GetString("symbol");
                if(symbol.empty())++unknown_refs;else {symbols.insert(symbol);target_symbols[SymbolFamily(symbol)].insert(symbol);Field(import,"weak").Bool()?++weak_refs:++nonweak_refs;}
            }
            row.Set("import_references",N(count));row.Set("unique_symbol_candidates",N(symbols.size()));
            auto sites=JsonValue::ArrayValue();for(const auto& site:Field(inventory,"svc_sites").ArrayItems())if(site.GetString("image")==name) {
                auto entry=site;const auto pc=Field(site,"pc").Serialize();
                // Inventory availability may belong to an older candidate; use only this probe.
                entry.ObjectItems().erase("handler_available");
                bool registered=false;for(const auto& [name,id]:registry)if(Field(site,"selector_id").IsNumber()&&id==Field(site,"selector_id").Int())registered=true;
                entry.Set("dispatch_registered",Field(bootstrap,"service_manifest").IsArray()?JsonValue::Boolean(registered):JsonValue::Null());
                const bool observed=matched.contains({pc,Field(site,"selector_id").Int()});
                if(observed)target_matched.emplace(pc,Field(site,"selector_id").Int());
                entry.Set("requirement",JsonValue::String(observed&&bound&&target_bound?"observed-required":"potential"));
                entry.Set("observed_at_exact_static_pc",JsonValue::Boolean(observed));
                const auto& reach=Field(*images.at(name),"reachability");
                std::string static_reach="unknown";
                for(const auto& address:At(reach,"export_candidates.svc_pcs").ArrayItems())if(address.Serialize()==pc)static_reach="export-direct-candidate";
                for(const auto& address:At(reach,"entry.svc_pcs").ArrayItems())if(address.Serialize()==pc)static_reach="entry-direct-candidate";
                entry.Set("static_reachability",JsonValue::String(static_reach));
                entry.Set("semantic_verified",JsonValue::Boolean(false));
                const bool known=Field(site,"selector_id").IsNumber();
                const auto workgroup=known?SelectorWorkgroup(Field(site,"selector_id").Int(),Field(site,"reference_names")):"unclassified";
                entry.Set("workgroup",JsonValue::String(workgroup));auto& batch=workgroups[workgroup];
                if(!batch.IsObject()){
                    batch=JsonValue::ObjectValue();batch.Set("selector_candidates",JsonValue::ArrayValue());
                    batch.Set("semantic_verification_source",JsonValue::String("scoped-contract-ledger-only"));
                    batch.Set("all_required_contracts_discovered",JsonValue::Boolean(false));
                }
                batch.Get("selector_candidates")->ArrayItems().push_back(entry);
                batch.Set("static_sites",N(Field(batch,"static_sites").Int()+1));
                const bool required=observed&&bound&&target_bound;
                const auto certainty=required?"observed_required_sites":"potential_sites";
                batch.Set(certainty,N(Field(batch,certainty).Int()+1));
                if(!known)batch.Set("unknown_selector_sites",N(Field(batch,"unknown_selector_sites").Int()+1));
                else if(Field(bootstrap,"service_manifest").IsArray()){
                    const auto dispatch=registered?"registered_sites":"missing_dispatch_sites";
                    batch.Set(dispatch,N(Field(batch,dispatch).Int()+1));
                }
                sites.ArrayItems().push_back(std::move(entry));
            }
            row.Set("selector_sites",std::move(sites));row.Set("execution_verified",JsonValue::Boolean(false));components.ArrayItems().push_back(std::move(row));
            for(const auto* edge:edges[name])if(!images.contains(edge->GetString("resolved_path")))gaps.ArrayItems().push_back(*edge);
        }
        if(refs!=unknown_refs+weak_refs+nonweak_refs)throw std::runtime_error("Target import-reference conservation failed");
        auto backlog=JsonValue::ObjectValue();for(auto& [name,batch]:workgroups)backlog.Set(name,std::move(batch));
        target.Set("workgroup_selector_backlog",std::move(backlog));
        auto symbol_counts=JsonValue::ObjectValue();for(const auto& [family,values]:target_symbols)symbol_counts.Set(family,N(values.size()));
        target.Set("unique_symbol_candidates_by_family",std::move(symbol_counts));
        target.Set("target",JsonValue::String(root));target.Set("components",std::move(components));target.Set("unresolved_dependency_edges",std::move(gaps));
        target.Set("structural_required_images",N(certain));target.Set("potential_dependency_images",N(potential));target.Set("import_references",N(refs));
        target.Set("weak_symbol_references",N(weak_refs));target.Set("nonweak_symbol_references",N(nonweak_refs));target.Set("unknown_symbol_references",N(unknown_refs));
        target.Set("reference_conservation",JsonValue::Boolean(true));target.Set("matched_observed_sites",N(target_matched.size()));
        target.Set("unjoined_observed_sites",N(observations.size()-target_matched.size()));target.Set("command_probe_hash_bound",JsonValue::Boolean(bound));
        target.Set("unparsed_trace_records",N(unparsed));
        target.Set("probe_target_identity_bound",JsonValue::Boolean(target_bound));
        target.Set("semantic_verification_source",JsonValue::String("scoped-contract-ledger-only"));
        target.Set("all_required_contracts_discovered",JsonValue::Boolean(false));target.Set("execution_verified",JsonValue::Boolean(false));targets.ArrayItems().push_back(std::move(target));
    }
    return targets;
}

}
JsonValue ReportDarwinProgress(const std::filesystem::path& inventory_path,const std::filesystem::path& probe_path,
    const std::filesystem::path& command_path,const std::filesystem::path& ledger_path,const std::filesystem::path& previous_path){
    const auto inventory=Read(inventory_path),probe=Read(probe_path,64ULL*1024*1024),command=Read(command_path,4ULL*1024*1024),ledger=Read(ledger_path,4ULL*1024*1024);
    if(Field(inventory.value,"schema_version").Int()!=1||!Field(inventory.value,"svc_sites").IsArray()
       ||!Field(probe.value,"bootstrap").IsObject()||!Field(ledger.value,"contracts").IsArray()
       ||command.value.GetString("sha256").size()!=64)throw std::runtime_error("Unsupported Darwin progress input schema");
    const auto& b=Field(probe.value,"bootstrap");const auto candidate=command.value.GetString("sha256");
    if(!command.value.GetString("probe_sha256").empty()&&command.value.GetString("probe_sha256")!=probe.hash)throw std::runtime_error("Command/probe hash binding differs");
    auto result=JsonValue::ObjectValue();result.Set("schema_version",N(1));result.Set("scope",JsonValue::String("retained-closure-and-bounded-bootstrap"));
    result.Set("candidate_sha256",JsonValue::String(candidate));result.Set("probe_sha256",JsonValue::String(probe.hash));
    result.Set("command_probe_hash_bound",JsonValue::Boolean(command.value.GetString("probe_sha256")==probe.hash));
    auto sources=JsonValue::ArrayValue();for(const auto* input:{&inventory,&probe,&command,&ledger}){auto item=JsonValue::ObjectValue();
        item.Set("path",JsonValue::String(input->path.generic_string()));item.Set("sha256",JsonValue::String(input->hash));sources.ArrayItems().push_back(std::move(item));}
    result.Set("inputs",std::move(sources));
    const bool manifest_present=Field(b,"service_manifest").IsArray();std::map<std::string,std::string> handlers;
    for(const auto& h:Field(b,"service_manifest").ArrayItems())handlers[Key(Field(h,"selector_id").Int())]=h.GetString("name");
    std::map<std::string,Selector> selectors;std::size_t unresolved=0;
    for(const auto& site:Field(inventory.value,"svc_sites").ArrayItems()){
        if(!Field(site,"selector_id").IsNumber()){++unresolved;continue;}
        const auto id=Field(site,"selector_id").Int();auto& entry=selectors[Key(id)];entry.id=id;++entry.sites;entry.images.insert(site.GetString("image"));
        for(const auto& name:Field(site,"reference_names").ArrayItems())entry.names.insert(name.StringValue());
    }
    // Imports are requirements candidates, including data, weak and unreachable symbols.
    std::map<std::string,std::set<std::string>> imports,families;
    for(const auto& i:Field(inventory.value,"imports").ArrayItems()){const auto symbol=i.GetString("symbol");imports[i.GetString("image")].insert(symbol);families[SymbolFamily(symbol)].insert(symbol);}
    auto components=JsonValue::ArrayValue();for(const auto& image:Field(inventory.value,"images").ArrayItems()){
        const auto name=image.GetString("image");auto item=JsonValue::ObjectValue();item.Set("component",JsonValue::String(name));item.Set("unique_import_candidates",N(imports[name].size()));
        auto required=JsonValue::ArrayValue();std::size_t missing=0;for(const auto& [key,s]:selectors)if(s.images.contains(name)){
            required.ArrayItems().push_back(JsonValue::String(key));if(manifest_present&&!handlers.contains(key))++missing;}
        item.Set("local_selector_candidates",std::move(required));item.Set("missing_dispatches",manifest_present?N(missing):JsonValue::Null());
        item.Set("execution_verified",JsonValue::Boolean(false));components.ArrayItems().push_back(std::move(item));}
    result.Set("target_requirements",TargetRequirements(inventory.value,b,command.value.GetString("probe_sha256")==probe.hash));
    result.Set("components",std::move(components));auto symbols=JsonValue::ObjectValue();for(const auto& [family,set]:families)symbols.Set(family,N(set.size()));result.Set("unique_symbol_candidates_by_family",std::move(symbols));
    auto selector_rows=JsonValue::ArrayValue();std::size_t registered=0;
    for(const auto& [key,s]:selectors){auto row=JsonValue::ObjectValue();row.Set("id",JsonValue::String(key));row.Set("static_sites",N(s.sites));row.Set("components",Strings(s.images));row.Set("reference_names",Strings(s.names));
        const bool found=handlers.contains(key);if(found)++registered;row.Set("dispatch_registered",manifest_present?JsonValue::Boolean(found):JsonValue::Null());
        row.Set("semantic_verification",JsonValue::String("not-inferred-from-dispatch"));selector_rows.ArrayItems().push_back(std::move(row));}
    result.Set("selector_candidates",std::move(selector_rows));
    auto contracts=JsonValue::ArrayValue();std::set<std::string> ids;std::size_t implemented=0,verified=0,missing=0,partial=0,unreviewed=0;
    auto verification_issues=JsonValue::ArrayValue();
    for(const auto& specification:Field(ledger.value,"contracts").ArrayItems()){
        const auto id=specification.GetString("id"),implementation=specification.GetString("implementation");
        if(id.empty()||!ids.insert(id).second|| (implementation!="missing"&&implementation!="partial"&&implementation!="implemented"&&implementation!="unreviewed"))throw std::runtime_error("Invalid/duplicate semantic contract in ledger");
        auto row=specification;bool accepted=false;auto proofs=JsonValue::ArrayValue();
        for(const auto& proof:Field(specification,"evidence").ArrayItems()){
            auto status=proof;std::string issue;const auto level=proof.GetString("level");
            if(proof.GetString("scope")!=specification.GetString("scope"))issue="contract-scope-mismatch";
            else if(implementation=="missing"||implementation=="unreviewed")issue="implementation-not-reviewed";
            else if(proof.GetString("candidate_sha256")!=candidate)issue="candidate-mismatch";
            else if(level!="contract"&&level!="propagation"&&level!="original-path")issue="unsupported-validation-level";
            else if(level=="original-path"&&proof.GetString("probe_sha256")!=probe.hash)issue="probe-mismatch";
            else if(proof.GetString("result")!="pass")issue="no-pass-attestation";
            else try{const auto path=ledger.path.parent_path()/std::filesystem::path(proof.GetString("artifact"));const auto hash=Sha256File(path);
                if(proof.GetString("sha256").size()!=64||!hash||*hash!=proof.GetString("sha256"))issue="artifact-missing-or-hash-mismatch";
            }catch(...){issue="artifact-unreadable";}
            status.Set("accepted",JsonValue::Boolean(issue.empty()));status.Set("issue",JsonValue::String(issue));proofs.ArrayItems().push_back(std::move(status));
            if(issue.empty())accepted=true;else{auto item=JsonValue::ObjectValue();item.Set("contract",JsonValue::String(id));item.Set("issue",JsonValue::String(issue));verification_issues.ArrayItems().push_back(std::move(item));}
        }
        row.Set("evidence",std::move(proofs));row.Set("verified_scope",JsonValue::Boolean(accepted));
        const auto observation=specification.GetString("observation_path");if(!observation.empty())row.Set("observed",At(b,observation));
        if(implementation=="implemented")++implemented;else if(implementation=="partial")++partial;else if(implementation=="missing")++missing;else ++unreviewed;
        if(accepted)++verified;contracts.ArrayItems().push_back(std::move(row));
    }
    result.Set("contracts",std::move(contracts));result.Set("verification_issues",std::move(verification_issues));
    for(const auto* dimension:{"family","component","workgroup"}){std::map<std::string,JsonValue> groups;
        for (const auto& row : Field(result, "contracts").ArrayItems()) {
            auto name = row.GetString(dimension);
            if (name.empty() && std::string_view(dimension) == "workgroup") name = "unassigned";
            auto& group = groups[name];
            if (!group.IsObject()) {
                group = JsonValue::ObjectValue();
                group.Set("contracts", JsonValue::ArrayValue());
            }
            group.Get("contracts")->ArrayItems().push_back(JsonValue::String(row.GetString("id")));
            const auto state = row.GetString("implementation");
            group.Set(state, N(Field(group, state).Int() + 1));
            if (Field(row, "verified_scope").Bool())
                group.Set("verified_scopes", N(Field(group, "verified_scopes").Int() + 1));
        }
        auto data=JsonValue::ObjectValue();for(auto& [name,group]:groups)data.Set(name,std::move(group));result.Set(std::string("coverage_by_")+dimension,std::move(data));}
    auto summary = JsonValue::ObjectValue();
    summary.Set("identified_scoped_contracts", N(ids.size()));
    summary.Set("implemented_scoped_contracts", N(implemented));
    summary.Set("partial_scoped_contracts", N(partial));
    summary.Set("missing_scoped_contracts", N(missing));
    summary.Set("verified_scopes", N(verified));
    summary.Set("static_selector_candidates", N(selectors.size()));
    summary.Set("unresolved_selector_sites", N(unresolved));
    summary.Set("registered_candidate_dispatches", manifest_present ? N(registered) : JsonValue::Null());
    summary.Set("manifest_present", JsonValue::Boolean(manifest_present));
    result.Set("summary", std::move(summary));
    result.Get("summary")->Set("unreviewed_scoped_contracts",N(unreviewed));
    const auto active_svc=CurrentSvc(b);
    auto blocker = JsonValue::ObjectValue();
    blocker.Set("stop_reason", Field(b, "stop_reason"));
    blocker.Set("selector", active_svc.selector);
    blocker.Set("selector_raw", active_svc.raw);
    blocker.Set("selector_source", JsonValue::String(active_svc.source));
    blocker.Set("interrupt", Field(b, "interrupt"));
    blocker.Set("opcode", Field(b, "last_instruction_opcode"));
    blocker.Set("pc", Field(b, "last_instruction_pc"));
    blocker.Set("localization", JsonValue::String("observed-stop-not-automatically-root-cause"));
    result.Set("current_blocker", std::move(blocker));
    result.Set("priorities",Field(ledger.value,"priorities"));
    auto unknown = JsonValue::ArrayValue();
    for (
        const auto* text :
        {"Total Darwin contract count is unknown; no global percentage is computed.",
         "Static selectors/imports are candidates, not proven reachable calls or complete API semantics.",
         "Bounded prefixes do not measure total call frequency. Observed success is not semantic verification.",
         "Verification is an explicit evidence attestation with artifact/candidate hashes, not an independent proof engine.",
         "Dynamic lookup, indirect calls, optimized cache bindings, generated code and undiscovered ABI variants remain open.",
         "XNU reference kernel-version equivalence is unproved. Swift/Objective-C symbols may be implemented by original guest libraries.",
         "Process, component and plugin execution are not promoted by mapped images or passing scoped contracts."})
        unknown.ArrayItems().push_back(JsonValue::String(text));
    result.Set("measurement_limits", std::move(unknown));
    auto delta=JsonValue::ObjectValue();delta.Set("available",JsonValue::Boolean(!previous_path.empty()));
    if(!previous_path.empty()){const auto previous=Read(previous_path,16ULL*1024*1024);if(previous.value.GetString("scope")!=result.GetString("scope"))throw std::runtime_error("Incompatible previous progress scope");
        std::map<std::string,JsonValue> old;for(const auto& row:Field(previous.value,"contracts").ArrayItems())old[row.GetString("id")]=row;
        auto added=JsonValue::ArrayValue(),changed=JsonValue::ArrayValue(),removed=JsonValue::ArrayValue();
        for(const auto& row:Field(result,"contracts").ArrayItems()){const auto id=row.GetString("id");if(!old.contains(id))added.ArrayItems().push_back(JsonValue::String(id));
            else if (row.GetString("scope") != old[id].GetString("scope") ||
                     row.GetString("implementation") != old[id].GetString("implementation") ||
                     Field(row, "verified_scope").Bool() != Field(old[id], "verified_scope").Bool()) {
                auto change = JsonValue::ObjectValue();
                change.Set("id", JsonValue::String(id));
                change.Set("before", old[id]);
                change.Set("after", row);
                changed.ArrayItems().push_back(std::move(change));
            }
            old.erase(id);
        }
        for (const auto& [id, row] : old) removed.ArrayItems().push_back(JsonValue::String(id));
        delta.Set("added_contracts", std::move(added));
        delta.Set("changed_contracts", std::move(changed));
        delta.Set("removed_contracts", std::move(removed));
        delta.Set("previous_report_sha256", JsonValue::String(previous.hash));
        auto target_changes=JsonValue::ArrayValue();std::map<std::string,const JsonValue*> old_targets;
        for(const auto& target:Field(previous.value,"target_requirements").ArrayItems())old_targets[target.GetString("target")]=&target;
        for(const auto& target:Field(result,"target_requirements").ArrayItems()) {
            auto change=JsonValue::ObjectValue();const auto root=target.GetString("target");change.Set("target",JsonValue::String(root));
            change.Set("previous_available",JsonValue::Boolean(old_targets.contains(root)));
            for(const auto* key:{"structural_required_images","potential_dependency_images","import_references","matched_observed_sites","unjoined_observed_sites"}) {
                auto count=JsonValue::ObjectValue();count.Set("before",old_targets.contains(root)?Field(*old_targets.at(root),key):JsonValue::Null());count.Set("after",Field(target,key));change.Set(key,std::move(count));
            }
            target_changes.ArrayItems().push_back(std::move(change));
        }
        delta.Set("target_changes",std::move(target_changes));
        delta.Set("previous_candidate_sha256", Field(previous.value, "candidate_sha256"));
        delta.Set("previous_blocker", Field(previous.value, "current_blocker"));
        delta.Set("same_inventory",
                  Field(previous.value, "inputs").IsArray() && !Field(previous.value, "inputs").ArrayItems().empty()
                      ? JsonValue::Boolean(Field(previous.value, "inputs").ArrayItems()[0].GetString("sha256") ==
                                           inventory.hash)
                      : JsonValue::Boolean(false));
    }
    result.Set("comparison",std::move(delta));return result;
}
}
