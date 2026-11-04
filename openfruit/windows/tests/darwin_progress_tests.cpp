#include "darwin_progress.hpp"
#include "content_hash.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <windows.h>
using namespace OpenFruit;
void Require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
void Write(const std::filesystem::path& path,const std::string& value){std::ofstream f(path,std::ios::binary);f<<value;Require(bool(f),"Fixture write failed");}
int main(){
    const auto root=std::filesystem::temp_directory_path()/("openfruit-progress-"+std::to_string(GetCurrentProcessId()));
    try{
        Require(std::filesystem::create_directory(root),"Unique fixture directory required");
        const auto inv=root/"inventory.json",probe=root/"probe.json",command=root/"command.json",ledger=root/"ledger.json",evidence=root/"evidence.log",previous=root/"previous.json";
        Write(inv,R"({"schema_version":1,"svc_sites":[{"selector_id":-28,"image":"a","reference_names":["task_self"]},{"selector_id":-28,"image":"a"},{"selector_id":28,"image":"b"},{"selector_id":null,"image":"a"}],"imports":[{"image":"a","symbol":"_objc_msgSend"},{"image":"a","symbol":"_objc_msgSend"},{"image":"b","symbol":"_$sOriginal"}],"images":[{"image":"a"},{"image":"b"}]})");
        Write(probe,R"({"bootstrap":{"service_manifest":[{"selector_id":-28,"name":"task_self"}],"stop_reason":"unsupported_interrupt","syscall_selector":28,"last_instruction_pc":128,"file_signatures":{"calls":2}}})");
        const std::string candidate(64,'a');Write(command,"{\"sha256\":\""+candidate+"\"}");Write(evidence,"explicit owned test PASS\n");
        auto proof=JsonValue::ObjectValue();proof.Set("artifact",JsonValue::String("evidence.log"));proof.Set("sha256",JsonValue::String(*Sha256File(evidence)));proof.Set("candidate_sha256",JsonValue::String(candidate));proof.Set("probe_sha256",JsonValue::String(*Sha256File(probe)));proof.Set("level",JsonValue::String("original-path"));proof.Set("result",JsonValue::String("pass"));
        proof.Set("scope",JsonValue::String("owned signature scope"));
        auto row=JsonValue::ObjectValue();row.Set("id",JsonValue::String("file.signature"));row.Set("scope",JsonValue::String("owned signature scope"));row.Set("implementation",JsonValue::String("partial"));row.Set("workgroup",JsonValue::String("BSD"));row.Set("observation_path",JsonValue::String("file_signatures.calls"));row.Set("evidence",JsonValue::ArrayValue({proof}));
        auto data=JsonValue::ObjectValue();data.Set("contracts",JsonValue::ArrayValue({row}));Write(ledger,data.Serialize());
        const auto report=ReportDarwinProgress(inv,probe,command,ledger);const auto* summary=report.Get("summary");
        Require(summary&&summary->Get("static_selector_candidates")->Int()==2&&summary->Get("unresolved_selector_sites")->Int()==1,"Domain identity/deduplication lost");
        Require(summary->Get("registered_candidate_dispatches")->Int()==1&&summary->Get("verified_scopes")->Int()==1&&summary->Get("implemented_scoped_contracts")->Int()==0,"Dispatch or partial success promoted to implementation");
        const auto* group=report.Get("coverage_by_workgroup")->Get("BSD");
        Require(group&&group->Get("contracts")->ArrayItems().size()==1&&group->Get("partial")->Int()==1&&group->Get("verified_scopes")->Int()==1,"Subsystem coverage lost scoped contract or promoted partial implementation");
        Require(report.Get("components")->ArrayItems()[0].Get("unique_import_candidates")->Int()==1,"Duplicate symbol candidates counted twice");
        Require(report.Get("contracts")->ArrayItems()[0].Get("observed")->Int()==2,"Existing observation path not propagated");Write(previous,report.Serialize());
        Write(evidence,"changed after proof\n");auto stale=ReportDarwinProgress(inv,probe,command,ledger,previous);
        Require(stale.Get("summary")->Get("verified_scopes")->Int()==0&&stale.Get("comparison")->Get("changed_contracts")->ArrayItems().size()==1,"Mutated evidence retained verification or lost regression");
        Require(!stale.Get("coverage_by_workgroup")->Get("BSD")->Get("verified_scopes"),"Subsystem retained stale verification evidence");
        proof.Set("sha256",JsonValue::String(*Sha256File(evidence)));proof.Set("candidate_sha256",JsonValue::String(std::string(64,'b')));row.Set("evidence",JsonValue::ArrayValue({proof}));data.Set("contracts",JsonValue::ArrayValue({row}));Write(ledger,data.Serialize());
        Require(ReportDarwinProgress(inv,probe,command,ledger).Get("summary")->Get("verified_scopes")->Int()==0,"Another binary's proof accepted");
        proof.Set("candidate_sha256",JsonValue::String(candidate));proof.Set("probe_sha256",JsonValue::String(std::string(64,'b')));row.Set("evidence",JsonValue::ArrayValue({proof}));data.Set("contracts",JsonValue::ArrayValue({row}));Write(ledger,data.Serialize());
        Require(ReportDarwinProgress(inv,probe,command,ledger).Get("summary")->Get("verified_scopes")->Int()==0,"Another execution's proof accepted");
        proof.Set("probe_sha256",JsonValue::String(*Sha256File(probe)));row.Set("scope",JsonValue::String("changed contract semantics"));row.Set("evidence",JsonValue::ArrayValue({proof}));data.Set("contracts",JsonValue::ArrayValue({row}));Write(ledger,data.Serialize());
        Require(ReportDarwinProgress(inv,probe,command,ledger).Get("summary")->Get("verified_scopes")->Int()==0,"Proof silently reused after scope change");
        Write(probe,R"({"bootstrap":{"stop_reason":"legacy"}})");const auto legacy=ReportDarwinProgress(inv,probe,command,ledger);
        Require(legacy.Get("summary")->Get("registered_candidate_dispatches")->IsNull(),"Old manifest fabricated from stale static inventory");
        // Dependency graph cycles, weak-to-strong promotion, lazy edges and unrelated images.
        Write(inv,R"({"schema_version":1,"target_roots":["a"],"images":[{"image":"a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","dependencies":[{"install_name":"lazy","lazy":true}]},{"image":"b"},{"image":"c"},{"image":"d"},{"image":"unused"}],"dependency_edges":[{"owner":"a","install_name":"weak","resolved_path":"b","weak":true},{"owner":"a","install_name":"strong","resolved_path":"c"},{"owner":"c","resolved_path":"b"},{"owner":"b","resolved_path":"a"},{"owner":"a","install_name":"lazy","resolved_path":"d"},{"owner":"a","install_name":"missing","resolved_path":""}],"imports":[{"image":"b","symbol":"_objc_msgSend"},{"image":"b","symbol":"_objc_msgSend"},{"image":"d","symbol":"_weak","weak":true},{"image":"unused","symbol":"_excluded"}],"svc_sites":[{"image":"b","pc":128,"opcode":3556773889,"selector_id":-28,"handler_available":true},{"image":"c","pc":256,"opcode":3556773889,"selector_id":28}]})");
        Write(probe,R"({"bootstrap":{"original_files":{"open_prefix":[{"virtual_path":"a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]},"mach_task":{"call_prefix":[{"pc":128,"selector":18446744073709551588},{"pc":4096,"selector":18446744073709551588}]}}})");
        Write(command,"{\"sha256\":\""+candidate+"\",\"probe_sha256\":\""+*Sha256File(probe)+"\"}");
        auto target_report=ReportDarwinProgress(inv,probe,command,ledger);
        const auto& target=target_report.Get("target_requirements")->ArrayItems().at(0);
        Require(target.Get("structural_required_images")->Int()==3&&target.Get("potential_dependency_images")->Int()==1,"Weak/strong/lazy graph certainty conflated");
        Require(target.Get("import_references")->Int()==3&&target.Get("weak_symbol_references")->Int()==1&&target.Get("nonweak_symbol_references")->Int()==2,"Target imports lost references or included unrelated image");
        Require(target.Get("matched_observed_sites")->Int()==1&&target.Get("unjoined_observed_sites")->Int()==1,"Relocated/unknown observations fabricated static match");
        Require(target.Get("unresolved_dependency_edges")->ArrayItems().size()==1&&!target.Get("execution_verified")->Bool(),"Unresolved edge hidden or measurement promoted to execution");
        const auto* ipc=target.Get("workgroup_selector_backlog")->Get("Mach IPC");
        Require(ipc&&ipc->Get("static_sites")->Int()==1&&ipc->Get("observed_required_sites")->Int()==1
            &&!ipc->Get("all_required_contracts_discovered")->Bool(),"Target workgroup lost observed requirement or claimed discovery completion");
        Require(target.Get("unique_symbol_candidates_by_family")->Get("objective-c")->Int()==1
            &&!target.Get("unique_symbol_candidates_by_family")->Get("other-or-unclassified")->IsNull(),"Target symbol family failed deduplication or included unrelated image");
        const auto& target_components=target.Get("components")->ArrayItems();
        Require(target_components.at(1).Get("dependency_witness")->ArrayItems().size()==3,"Strong dependency witness missing");
        Require(target_components.at(1).Get("selector_sites")->ArrayItems().at(0).Get("dispatch_registered")->IsNull()&&!target_components.at(1).Get("selector_sites")->ArrayItems().at(0).Get("handler_available"),"Stale inventory dispatch availability retained");
        Require(target_components.at(1).Get("selector_sites")->ArrayItems().at(0).GetString("requirement")=="observed-required"&&!target_components.at(1).Get("selector_sites")->ArrayItems().at(0).Get("semantic_verified")->Bool(),"Dynamic reachability conflated with semantic verification");
        Write(command,"{\"sha256\":\""+candidate+"\"}");
        Require(ReportDarwinProgress(inv,probe,command,ledger).Get("target_requirements")->ArrayItems().at(0).Get("components")->ArrayItems().at(1).Get("selector_sites")->ArrayItems().at(0).GetString("requirement")=="potential","Unbound observation promoted to requirement");
        Write(probe,R"({"bootstrap":{"original_files":{"open_prefix":[{"virtual_path":"a","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]},"mach_task":{"call_prefix":[{"pc":128,"selector":18446744073709551588}]}}})");
        Write(command,"{\"sha256\":\""+candidate+"\",\"probe_sha256\":\""+*Sha256File(probe)+"\"}");
        const auto wrong_original=ReportDarwinProgress(inv,probe,command,ledger);
        Require(!wrong_original.Get("target_requirements")->ArrayItems().at(0).Get("probe_target_identity_bound")->Bool()&&wrong_original.Get("target_requirements")->ArrayItems().at(0).Get("components")->ArrayItems().at(1).Get("selector_sites")->ArrayItems().at(0).GetString("requirement")=="potential","Different original executable promoted to required contract");
        Write(inv,R"({"schema_version":1,"target_roots":["a"],"images":[{"image":"a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"imports":[],"svc_sites":[{"image":"a","pc":256,"opcode":3556773889,"selector_id":-89}]})");
        Write(probe,R"({"bootstrap":{"interrupt":2,"last_instruction_pc":256,"last_instruction_opcode":3556773889,"syscall_selector":18446744073709551527,"original_files":{"open_prefix":[{"virtual_path":"a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}})");
        Write(command,"{\"sha256\":\""+candidate+"\",\"probe_sha256\":\""+*Sha256File(probe)+"\"}");
        const auto wide_selector=ReportDarwinProgress(inv,probe,command,ledger);
        Require(wide_selector.Get("current_blocker")->Get("selector")->Int()==-89&&wide_selector.Get("current_blocker")->Get("selector_raw")->Serialize()=="18446744073709551527","Full-width Mach selector lost signed identity or raw provenance");
        Require(wide_selector.Get("target_requirements")->ArrayItems().at(0).Get("matched_observed_sites")->Int()==1&&wide_selector.Get("target_requirements")->ArrayItems().at(0).Get("unjoined_observed_sites")->Int()==0,"Observed full-width Mach trap not joined to its static site");

        // Older probes retained a prior BSD selector when a Mach handler
        // stopped internally. Actual register evidence must win in both the
        // blocker and the static-site/reachability join.
        auto active_probe=*JsonValue::Parse(R"({"bootstrap":{"interrupt":2,"last_instruction_pc":256,"last_instruction_opcode":3556773889,"syscall_selector":366,"original_files":{"open_prefix":[{"virtual_path":"a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}})");
        auto registers=JsonValue::ArrayValue();
        for(unsigned i=0;i<32;++i)registers.ArrayItems().push_back(JsonValue::Number("0"));
        registers.ArrayItems()[16]=JsonValue::Number("18446744073709551527");
        active_probe.Get("bootstrap")->Set("registers",registers);
        const auto active_report=[&]{Write(probe,active_probe.Serialize());Write(command,"{\"sha256\":\""+candidate+"\",\"probe_sha256\":\""+*Sha256File(probe)+"\"}");return ReportDarwinProgress(inv,probe,command,ledger);};
        const auto from_stop=active_report();
        Require(from_stop.Get("current_blocker")->Get("selector")->Int()==-89
            &&from_stop.Get("current_blocker")->GetString("selector_source")=="stop-registers"
            &&from_stop.Get("target_requirements")->ArrayItems().at(0).Get("matched_observed_sites")->Int()==1,
            "Stale BSD field overrode actual Mach stop registers or static match");
        auto instruction=JsonValue::ObjectValue();instruction.Set("pc",JsonValue::Number("256"));
        instruction.Set("opcode",JsonValue::Number("3556773889"));instruction.Set("registers",registers);
        active_probe.Get("bootstrap")->Set("last_instructions",JsonValue::ArrayValue({instruction}));
        registers.ArrayItems()[16]=JsonValue::Number("366");active_probe.Get("bootstrap")->Set("registers",registers);
        const auto from_before=active_report();
        Require(from_before.Get("current_blocker")->Get("selector")->Int()==-89
            &&from_before.Get("current_blocker")->GetString("selector_source")=="pre-trap-registers",
            "Post-handler registers overrode immutable pre-trap selector");
        registers.ArrayItems()[16]=JsonValue::Number("0");registers.ArrayItems()[0]=JsonValue::Number("555");
        instruction.Set("registers",registers);active_probe.Get("bootstrap")->Set("last_instructions",JsonValue::ArrayValue({instruction}));
        registers.ArrayItems()[0]=JsonValue::Number("9");active_probe.Get("bootstrap")->Set("registers",registers);
        const auto indirect=active_report();
        Require(indirect.Get("current_blocker")->Get("selector")->Int()==555
            &&indirect.Get("current_blocker")->Get("selector_raw")->Int()==0,
            "Indirect syscall attributed to post-handler X0 instead of pre-trap argument");
        active_probe.Get("bootstrap")->Set("last_instructions",JsonValue::ArrayValue());
        Require(active_report().Get("current_blocker")->Get("selector")->IsNull(),
            "Indirect selector invented from post-handler return value");
        active_probe.Get("bootstrap")->Set("last_instruction_opcode",JsonValue::Number("4181721088"));
        Require(active_report().Get("current_blocker")->Get("selector")->IsNull(),
            "Non-SVC stop attributed to stale interrupt/selector");

        Write(inv,R"({"schema_version":1,"target_roots":["a"],"images":[{"image":"a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"imports":[],"svc_sites":[{"image":"a","pc":256,"opcode":3556773889,"selector_id":515,"reference_names":["ulock_wait"]},{"image":"a","pc":260,"opcode":3556773889},{"image":"a","pc":264,"opcode":3556773889,"selector_id":197,"reference_names":["mmap"]}]})");
        const auto batch_report=ReportDarwinProgress(inv,probe,command,ledger);
        const auto& batch=batch_report.Get("target_requirements")->ArrayItems().at(0);
        const auto* pthread=batch.Get("workgroup_selector_backlog")->Get("pthread/TLS");
        Require(pthread&&pthread->Get("potential_sites")->Int()==1&&!pthread->Get("observed_required_sites")
            &&!pthread->Get("registered_sites"),"Potential pthread requirement fabricated observation or dispatch");
        Require(batch.Get("workgroup_selector_backlog")->Get("unclassified")->Get("unknown_selector_sites")->Int()==1
            &&batch.Get("workgroup_selector_backlog")->Get("Mach VM")->Get("static_sites")->Int()==1,"Unresolved selector concealed or VM candidate misclassified");
        data.Set("contracts",JsonValue::ArrayValue({row,row}));Write(ledger,data.Serialize());bool rejected=false;try{ReportDarwinProgress(inv,probe,command,ledger);}catch(const std::exception&){rejected=true;}Require(rejected,"Duplicate contract IDs accepted");
        std::filesystem::remove_all(root);std::cout<<"Darwin progress provenance, bounded scopes, stale evidence and comparison PASS\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
