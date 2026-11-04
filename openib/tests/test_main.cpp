#include "openib/compiler.hpp"
#include "openib/diff.hpp"
#include "openib/model.hpp"
#include "openib/nib.hpp"
#include "openib/text_layout.hpp"
#include "openib/xml.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <cmath>
#include <cstring>
#include <optional>
#include <stdexcept>

namespace fs=std::filesystem;
static void require(bool v,const char* m){if(!v)throw std::runtime_error(m);}

int main(){try{
    {
        // customModuleProvider="target" names the owning target's module, not
        // the module stored in the document.
        const auto dir=fs::temp_directory_path()/"openib-target-module";fs::create_directories(dir);
        const auto xib=dir/"Cell.xib";
        std::ofstream(xib,std::ios::binary)<<R"XIB(<?xml version="1.0" encoding="UTF-8"?>
<document type="com.apple.InterfaceBuilder3.CocoaTouch.XIB" version="3.0" toolsVersion="23504" targetRuntime="iOS.CocoaTouch" propertyAccessControl="none" useAutolayout="YES" colorMatched="YES">
    <objects>
        <placeholder placeholderIdentifier="IBFilesOwner" id="-1" userLabel="File's Owner"/>
        <placeholder placeholderIdentifier="IBFirstResponder" id="-2" customClass="UIResponder"/>
        <collectionViewCell opaque="NO" contentMode="center" id="c1" customClass="LabelCell" customModule="Stored_Module" customModuleProvider="target">
            <rect key="frame" x="0.0" y="0.0" width="50" height="50"/>
        </collectionViewCell>
    </objects>
</document>
)XIB";
        const auto classes=[&](const std::string& module){
            openib::Diagnostics d;openib::Compiler c;openib::CompileOptions o;o.target_module=module;
            const auto out=dir/(module.empty()?"stored.nib":"target.nib");
            require(c.compile(xib,out,o,d).success,"module-provider cell XIB compiles");
            std::ifstream in(out,std::ios::binary);return std::string((std::istreambuf_iterator<char>(in)),{});
        };
        const auto target=classes("App"),stored=classes("");
        require(target.find("_TtC3App9LabelCell")!=std::string::npos&&target.find("Stored_Module")==std::string::npos,
            "customModuleProvider=target did not use the target module");
        require(stored.find("_TtC13Stored_Module9LabelCell")!=std::string::npos,"stored customModule lost without a target module");
        fs::remove_all(dir);
    }
    // NIB reader/writer round trip.
    openib::nib::GraphBuilder gb;
    auto root = gb.object("NSObject");
    root->set("name", gb.string("hello"));
    root->set("flag", true);
    auto a = gb.flatten({root}, 10);
    openib::nib::Writer w;
    openib::nib::Reader r;
    auto bytes = w.write_bytes(a);
    auto b = r.read_bytes(bytes);
    require(a.objects.size() == b.objects.size(), "NIB roundtrip object count");
    require(a.keys.size() == b.keys.size(), "NIB roundtrip key count");
    require(b.coder_version == 10, "NIB coder version");
    auto changed=b;changed.values.back().type=openib::nib::ValueType::False;changed.values.back().payload=std::monostate{};require(!openib::diff_archives(a,changed).equivalent,"semantic diff detects scalar changes");
    auto rewired = [](bool swap) {
        openib::nib::GraphBuilder graph;
        auto root = graph.object("NSObject");
        auto first = graph.object("UIView");
        auto second = graph.object("UIView");
        first->set("id", std::int64_t(1));
        second->set("id", std::int64_t(2));
        auto left = graph.object("UILabel");
        auto right = graph.object("UILabel");
        left->set("text", graph.string("left"));
        right->set("text", graph.string("right"));
        first->set("child", swap ? right : left);
        second->set("child", swap ? left : right);
        root->set("first", first);
        root->set("second", second);
        return graph.flatten({root});
    };
    require(!openib::diff_archives(rewired(false),rewired(true)).equivalent,"semantic diff detects rewired references with identical histograms");
    auto wrap_nested=[&](const openib::nib::Archive& archive){openib::nib::GraphBuilder outer;auto data=outer.object("NSData");openib::nib::RawBytes raw;raw.data=w.write_bytes(archive);data->set("NS.bytes",std::move(raw));return outer.flatten({data});};
    require(!openib::diff_archives(wrap_nested(rewired(false)),wrap_nested(rewired(true))).equivalent,"nested NIB diff detects rewired references");
    auto ordered_constraints = [](bool reverse, bool changed_value, bool constraints) {
        openib::nib::GraphBuilder graph;
        auto set = graph.object("NSOrderedSet");
        auto first = graph.object(constraints ? "NSLayoutConstraint" : "NSObject");
        auto second = graph.object(constraints ? "NSLayoutConstraint" : "NSObject");
        first->set("NSConstant", 1.0);
        second->set("NSConstant", changed_value ? 3.0 : 2.0);
        set->set("NS.object.0", reverse ? second : first);
        set->set("NS.object.1", reverse ? first : second);
        return graph.flatten({set});
    };
    require(openib::diff_archives(ordered_constraints(false,false,true),ordered_constraints(true,false,true)).equivalent,"constraint activation order is not a semantic graph difference");
    require(!openib::diff_archives(ordered_constraints(false,false,true),ordered_constraints(true,true,true)).equivalent,"constraint set still detects changed constraint values");
    require(!openib::diff_archives(ordered_constraints(false,false,false),ordered_constraints(true,false,false)).equivalent,"non-constraint ordered set remains order-sensitive");
    openib::xml::Parser xml_parser;auto normalized_xml=xml_parser.parse_string("<root>one\r\ntwo\rthree</root>");require(normalized_xml.root->text=="one\ntwo\nthree","XML line endings normalize to LF");
    // A prototype cell NIB may be encoded with different table ordering.
    // Compare its decoded graph, but still reject a changed nested value.
    auto embedded = [&](bool reverse, bool changed_value) {
        openib::nib::GraphBuilder inner;
        auto object = inner.object("UIView");
        if (reverse) {
            object->set("second", changed_value ? std::int64_t(3) : std::int64_t(2));
            object->set("first", std::int64_t(1));
        } else {
            object->set("first", std::int64_t(1));
            object->set("second", std::int64_t(2));
        }
        auto inner_bytes = w.write_bytes(inner.flatten({object}));
        openib::nib::GraphBuilder outer;
        auto data = outer.object("NSData");
        openib::nib::RawBytes raw;
        raw.data = std::move(inner_bytes);
        data->set("NS.bytes", std::move(raw));
        return outer.flatten({data});
    };
    require(openib::diff_archives(embedded(false,false),embedded(true,false)).equivalent,"nested NIB table ordering is ignored");
    require(!openib::diff_archives(embedded(false,false),embedded(true,true)).equivalent,"nested NIB changes are detected");
    if(auto height=openib::measure_text_height("XXXXXXXX YYYYYYYY","Menlo-Regular",26,365,false)){
        require(std::abs(*height-31.0)<0.5,"installed Menlo and CoreText measure the one-line text");
        auto system=openib::measure_text_height("Short line.","",15,365,true);
        if(system)require(*system>0,"installed SF system font is measurable");
    }

    const fs::path source=fs::path(OPENIB_SOURCE_DIR)/"tests/fixtures/delta/LaunchScreen.storyboard";
    openib::Diagnostics d;openib::IBParser parser;auto doc=parser.parse(source,d);require(doc.is_storyboard,"LaunchScreen recognized as storyboard");require(doc.scenes.size()==1,"LaunchScreen scene count");require(doc.initial_view_controller=="dkK-ii-Bx4","LaunchScreen entry point");

    const fs::path out = fs::temp_directory_path() / "openib-test-LaunchScreen.storyboardc";
    std::error_code ec;
    fs::remove_all(out, ec);
    openib::Compiler compiler;
    openib::CompileOptions opts;
    auto cr = compiler.compile(source, out, opts, d);
    require(cr.files_written == 3, "LaunchScreen writes controller/view/plist");
    require(fs::exists(out / "Info.plist"), "Info.plist exists");
    require(fs::exists(out / "UIViewController-dkK-ii-Bx4.nib"), "controller nib exists");
    require(fs::exists(out / "dkK-ii-Bx4-view-8Uu-wz-ps8.nib"), "view nib exists");
    auto generated = r.read_file(out / "UIViewController-dkK-ii-Bx4.nib");
    require(generated.objects.size() == 19, "LaunchScreen controller matches golden object count");
    require(generated.values.size() == 43, "LaunchScreen controller matches golden value count");
    auto generated_view = r.read_file(out / "dkK-ii-Bx4-view-8Uu-wz-ps8.nib");
    require(generated_view.objects.size() == 43, "LaunchScreen view matches golden object count");
    require(generated_view.values.size() == 229, "LaunchScreen view matches golden value count");
    fs::remove_all(out, ec);

    // Storyboard references belong in Info.plist. References with explicit
    // controller identifiers do not get synthetic local controller NIBs.
    const fs::path main_source=fs::path(OPENIB_SOURCE_DIR)/"tests/fixtures/delta/Main.storyboard";
    const fs::path main_out = fs::temp_directory_path() / "openib-test-Main.storyboardc";
    fs::remove_all(main_out, ec);
    openib::Diagnostics md;
    auto mr = compiler.compile(main_source, main_out, opts, md);
    require(mr.success, "Main storyboard compiles");
    std::ifstream plist(main_out / "Info.plist", std::ios::binary);
    std::string plist_text((std::istreambuf_iterator<char>(plist)), {});
    require(plist_text.find("UIViewControllerIdentifiersToExternalStoryboardReferences") != std::string::npos,
            "external storyboard map emitted");
    require(plist_text.find("dsSettingsViewController") != std::string::npos,
            "referenced controller identifier emitted");
    require(!fs::exists(main_out / "UIViewController-cFV-KV-B18.nib"), "explicit external reference has no local NIB");
    require(fs::exists(main_out / "UIViewController-ibA-aC-X3M.nib"), "entry-point external reference has proxy NIB");
    fs::remove_all(main_out, ec);
    const fs::path sync_source=fs::path(OPENIB_SOURCE_DIR)/"tests/fixtures/delta/SyncResultsViewController.storyboard";
    const fs::path sync_out = fs::temp_directory_path() / "openib-test-SyncResultsViewController.storyboardc";
    fs::remove_all(sync_out, ec);
    openib::Diagnostics sync_d;
    auto sync_result = compiler.compile(sync_source, sync_out, opts, sync_d);
    require(sync_result.success && sync_result.files_written == 5, "nonlocalized storyboard compiles every archive");
    require(fs::exists(sync_out / "syncResultViewController.nib"),
            "addressable relationship child has independent NIB");
    auto sync_controller = r.read_file(sync_out / "syncResultViewController.nib");
    for (const auto& object : sync_controller.objects)
        require(sync_controller.classes[object.class_index].name != "NSLocalizableString",
                "nonlocalized storyboard uses plain strings");
    auto sync_view = r.read_file(sync_out / "Vv7-67-y3h-view-Mge-4Z-RnG.nib");
    bool legacy_system_color = false;
    for (const auto& key : sync_view.keys)
        if (key == "UISystemColorName") legacy_system_color = true;
    require(legacy_system_color, "legacy Cocoa Touch system color is archived");
    fs::remove_all(sync_out, ec);

    // XIB File's Owner outlets cross from a placeholder into the view graph.
    const fs::path xib_source=fs::path(OPENIB_SOURCE_DIR)/"tests/fixtures/delta/PausePresentationControllerContentView.xib";
    const fs::path xib_out = fs::temp_directory_path() / "openib-test-PausePresentationControllerContentView.nib";
    fs::remove(xib_out, ec);
    openib::Diagnostics xd;
    auto xr = compiler.compile(xib_source, xib_out, opts, xd);
    require(xr.success, "XIB compiles");
    auto xib_archive = r.read_file(xib_out);
    std::size_t outlet_count = 0, trait_list_count = 0, trait_record_count = 0;
    for (const auto& object : xib_archive.objects) {
        const auto& name = xib_archive.classes[object.class_index].name;
        if (name == "UIRuntimeOutletConnection") ++outlet_count;
        if (name == "_UITraitStorageList") ++trait_list_count;
        if (name == "_UIAttributeTraitStorageRecord") ++trait_record_count;
    }
    require(outlet_count == 3, "XIB File's Owner outlets are archived");
    require(trait_list_count == 1 && trait_record_count == 4, "XIB size-class constraint variations are archived");
    fs::remove(xib_out, ec);

    const fs::path settings_source=fs::path(OPENIB_SOURCE_DIR)/"tests/fixtures/delta/Settings.storyboard";
    const fs::path settings_out = fs::temp_directory_path() / "openib-test-Settings.storyboardc";
    fs::remove_all(settings_out, ec);
    openib::Diagnostics sd;
    auto sr = compiler.compile(settings_source, settings_out, opts, sd);
    require(sr.success, "Settings storyboard compiles");
    auto licenses = r.read_file(settings_out / "Vew-Fv-phU-view-OFY-Qi-vAX.nib");
    std::size_t guide_count = 0, attributed_count = 0;
    for (const auto& object : licenses.objects) {
        const auto& name = licenses.classes[object.class_index].name;
        if (name == "UILayoutGuide") ++guide_count;
        if (name == "NSAttributedString") ++attributed_count;
    }
    require(guide_count == 2, "safe area includes runtime guide and archived placeholder");
    require(attributed_count == 1, "text view archives attributed text");
    fs::remove_all(settings_out, ec);
    auto content_height = [](const openib::nib::Archive& archive) -> std::optional<double> {
        for (const auto& value : archive.values)
            if (value.key_index < archive.keys.size() && archive.keys[value.key_index] == "UIContentSize" &&
                value.type == openib::nib::ValueType::Bytes) {
                const auto& bytes = std::get<openib::nib::Bytes>(value.payload).data;
                if (bytes.size() == 17 && bytes[0] == 7) {
                    double height;
                    std::memcpy(&height, bytes.data() + 9, sizeof height);
                    return height;
                }
            }
        return std::nullopt;
    };
    if(openib::measure_text_height("Short line.","",15,365,true)){auto height=content_height(licenses);require(height&&std::abs(*height-2476)<=8,"license scene archives a measured content size near the official NIB");}
    const fs::path pause_source=fs::path(OPENIB_SOURCE_DIR)/"tests/fixtures/delta/PauseMenu.storyboard";
    const fs::path pause_out = fs::temp_directory_path() / "openib-test-PauseMenu.storyboardc";
    fs::remove_all(pause_out, ec);
    openib::Diagnostics pd;
    auto pause_result = compiler.compile(pause_source, pause_out, opts, pd);
    require(pause_result.success, "PauseMenu storyboard compiles");
    auto pause_view = r.read_file(pause_out / "jTR-Oe-YUJ-view-BV9-ff-x83.nib");
    bool modern_grouped_color = false;
    for (const auto& value : pause_view.values)
        if (value.type == openib::nib::ValueType::Bytes) {
            const auto& bytes = std::get<openib::nib::Bytes>(value.payload).data;
            modern_grouped_color |= std::string(bytes.begin(), bytes.end()) == "systemGroupedBackgroundColor";
        }
    require(modern_grouped_color, "modern grouped-table background uses modern system color identity");
    fs::remove_all(pause_out, ec);
    if(openib::measure_text_height("XXXXXXXX YYYYYYYY","Menlo-Regular",26,365,false)){auto height=content_height(pause_view);require(height&&*height==47,"cheat text view archives the official one-line content height");}

    // Independent inputs for deriving UIKit layout rules. These are smoke
    // tests, not golden layout assertions until ibtool references exist.
    for(const auto& probe: {"TextLayoutProbe", "TableFooterProbe"}){
        const fs::path probe_source=fs::path(OPENIB_SOURCE_DIR)/"tests/fixtures/layout"/(std::string(probe)+".storyboard");
        const fs::path probe_out=fs::temp_directory_path()/(std::string("openib-test-")+probe+".storyboardc");
        fs::remove_all(probe_out,ec);
        openib::Diagnostics probe_d;auto result=compiler.compile(probe_source,probe_out,opts,probe_d);
        require(result.success,"independent layout probe compiles");
        require(result.files_written==(std::string(probe)=="TextLayoutProbe"?3:7),"layout probe archive count");
        for(const auto& entry:fs::directory_iterator(probe_out))if(entry.path().extension()==".nib")require(!r.read_file(entry.path()).objects.empty(),"layout probe archive decodes");
        if(std::string(probe)=="TableFooterProbe")for(const auto* view_name:{"Prb-Ftr-Vc1-view-Prb-Ftr-Tb1.nib","Prb-Ftr-Vc2-view-Prb-Ftr-Tb2.nib"}){
            auto archive=r.read_file(probe_out/view_name);bool found=false;
            for(const auto& object:archive.objects)if(archive.classes[object.class_index].name=="UILabel")for(std::uint32_t index=0;index<object.value_count;++index){
                const auto& value=archive.values[object.value_start+index];
                if(archive.keys[value.key_index]!="UICenter"||value.type!=openib::nib::ValueType::Bytes)continue;
                const auto& bytes=std::get<openib::nib::Bytes>(value.payload).data;
                require(bytes.size()==17&&bytes[0]==7,"footer center is a CGPoint");
                double y=0;std::memcpy(&y,bytes.data()+9,sizeof y);require(y==75.0,"grouped footer ignores editor-canvas Y coordinate");found=true;
            }
            require(found,"grouped footer center is archived");
        }
        fs::remove_all(probe_out,ec);
    }

    std::cout<<"All OpenIB tests passed.\n";return 0;
}catch(const std::exception&e){std::cerr<<"TEST FAILURE: "<<e.what()<<"\n";return 1;}}
