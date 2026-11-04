#include "openib/compiler.hpp"
#include "openib/text_layout.hpp"
#include "openib/xml.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace openib {
namespace {

using nib::GraphRef;
using nib::GraphValue;

struct PendingReference { GraphRef owner; std::string key; std::string target_id; };
struct PendingConnection {
    std::string kind;
    std::string label;
    std::string destination_id;
    GraphRef source;
    std::int64_t event_mask{0};
    const xml::Node* xml_node{nullptr};
};
struct PendingSegue {
    GraphRef template_object;
    std::string destination_id;
    std::string kind;
    GraphRef trigger;
    const xml::Node* xml_node{nullptr};
};
struct SceneWork {
    bool standalone_xib{false};
    struct ConstraintVariation { GraphRef constraint; std::string trait; double value; double fallback; };
    std::vector<ConstraintVariation> constraint_variations;
    struct RelationshipVariation { GraphRef top; GraphRef owner; std::vector<GraphRef> candidates; std::vector<GraphRef> removed; std::vector<GraphRef> descendants; };
    std::vector<RelationshipVariation> relationship_variations;
    const IBScene* scene{nullptr};
    GraphRef controller;
    GraphRef root_view;
    GraphRef static_data_source;
    std::string controller_id;
    std::string controller_base_class;
    std::string controller_nib_name;
    std::string view_nib_name;
    bool is_external_storyboard_reference{false};
    std::string external_storyboard_name;
    std::string external_controller_identifier;
    std::unordered_map<std::string, GraphRef> objects;
    std::unordered_map<std::string, bool> view_side;
    std::vector<GraphRef> scene_extras;
    std::vector<GraphRef> view_extras;
    std::vector<GraphRef> view_tops;
    std::vector<GraphRef> view_key_value_pairs;
    std::vector<std::pair<std::string,GraphRef>> table_prototype_segues;
    std::vector<std::pair<std::string,GraphRef>> table_prototype_externals;
    GraphRef vibrancy_tint_color;
    std::map<std::pair<std::string,double>,GraphRef> standard_table_fonts;
    GraphRef table_label_color;
    GraphRef table_plain_background_color;
    GraphRef table_clear_color;
    std::vector<GraphRef> scene_connections;
    std::vector<GraphRef> view_connections;
    std::vector<GraphRef> layout_guides;
    std::vector<std::pair<GraphRef, std::string>> typed_layout_guides;
    std::vector<PendingReference> references;
    std::vector<PendingConnection> connections;
    std::vector<PendingSegue> segues;
    std::vector<std::pair<std::string, std::string>> relationships;
};

std::optional<double> to_double(std::optional<std::string_view> v) {
    if (!v) return std::nullopt;
    try { return std::stod(std::string(*v)); } catch (...) { return std::nullopt; }
}
std::optional<std::int64_t> to_int(std::optional<std::string_view> v) {
    if (!v) return std::nullopt;
    try { return std::stoll(std::string(*v)); } catch (...) { return std::nullopt; }
}

std::string base_class_for_tag(std::string_view tag) {
    static const std::unordered_map<std::string, std::string> map = {
        {"viewController", "UIViewController"},
        {"navigationController", "UINavigationController"},
        {"tableViewController", "UITableViewController"},
        {"collectionViewController", "UICollectionViewController"},
        {"pageViewController", "UIPageViewController"},
        {"splitViewController", "UISplitViewController"},
        {"tabBarController", "UITabBarController"},
        {"viewControllerPlaceholder", "UIViewController"},
        {"view", "UIView"},
        {"containerView", "UIView"},
        {"stackView", "UIStackView"},
        {"imageView", "UIImageView"},
        {"label", "UILabel"},
        {"button", "UIButton"},
        {"switch", "UISwitch"},
        {"searchBar", "UISearchBar"},
        {"textView", "UITextView"},
        {"textField", "UITextField"},
        {"scrollView", "UIScrollView"},
        {"visualEffectView", "UIVisualEffectView"},
        {"tableView", "UITableView"},
        {"tableViewCell", "UITableViewCell"},
        {"tableViewCellContentView", "UITableViewCellContentView"},
        {"collectionView", "UICollectionView"},
        {"collectionViewCell", "UICollectionViewCell"},
        {"collectionReusableView", "UICollectionReusableView"},
        {"collectionViewFlowLayout", "UICollectionViewFlowLayout"},
        {"collectionViewCellContentView", "UIView"},
        {"navigationBar", "UINavigationBar"},
        {"navigationItem", "UINavigationItem"},
        {"barButtonItem", "UIBarButtonItem"},
        {"toolbar", "UIToolbar"},
        {"segmentedControl", "UISegmentedControl"},
        {"activityIndicatorView", "UIActivityIndicatorView"},
        {"slider", "UISlider"},
        {"tapGestureRecognizer", "UITapGestureRecognizer"},
        {"viewLayoutGuide", "UILayoutGuide"},
        {"pageControl", "UIPageControl"},
        {"progressView", "UIProgressView"},
        {"refreshControl", "UIRefreshControl"},
        {"tabBar", "UITabBar"},
        {"tabBarItem", "UITabBarItem"},
        {"wkWebView", "WKWebView"},
        {"datePicker", "UIDatePicker"},
        {"pickerView", "UIPickerView"},
        {"stepper", "UIStepper"},
        {"colorWell", "UIColorWell"}};
    auto it = map.find(std::string(tag)); return it == map.end() ? std::string{} : it->second;
}

// Target module of the resource being compiled (CompileOptions::target_module).
thread_local std::string compiling_target_module;

std::string runtime_custom_class_name(const xml::Node& node, std::string_view custom) {
    std::optional<std::string> module;
    if(auto stored=node.attr("customModule"))module=std::string(*stored);
    if(node.attr_or("customModuleProvider","")=="target"&&!compiling_target_module.empty())module=compiling_target_module;
    if(!module||custom.find('.')!=std::string_view::npos||custom.rfind("_Tt",0)==0)return std::string(custom);
    // Interface Builder stores Swift runtime class names in the archive. The
    // legacy _TtC form is length-prefixed by module and nominal type.
    return "_TtC"+std::to_string(module->size())+*module+std::to_string(custom.size())+std::string(custom);
}

GraphRef class_swapped(nib::GraphBuilder& gb, const xml::Node& node, std::string base) {
    auto custom = node.attr("customClass");
    if (!custom) return gb.object(std::move(base));
    auto o = gb.object("UIClassSwapper");
    o->set("UIOriginalClassName", gb.string(std::move(base)));
    o->set("UIClassName", gb.string(runtime_custom_class_name(node,*custom)));
    return o;
}

GraphRef controller_class_swapped(nib::GraphBuilder& gb, const xml::Node& node, const std::string& base) {
    auto o = gb.object("UIClassSwapper");
    auto original = gb.string(base);
    o->set("UIOriginalClassName", original);
    auto custom = node.attr_or("customClass", base);
    o->set("UIClassName", custom == base ? original : gb.string(runtime_custom_class_name(node,custom)));
    return o;
}


using NamedColors=std::unordered_map<std::string,const xml::Node*>;
GraphRef make_color(nib::GraphBuilder& gb, const xml::Node& node,const NamedColors* named_colors=nullptr) {
    auto o = gb.object("UIColor");
    double r=0,g=0,b=0,a=1;
    const xml::Node* components=&node;
    if(auto name=node.attr("name")){
        if(named_colors){auto found=named_colors->find(std::string(*name));if(found!=named_colors->end())components=found->second;}
        o->set("UIDynamicCatalogName",gb.string(std::string(*name)));
        o->set("UIDynamicCatalogUseNibBundle",true);
    }
    auto system=node.attr("systemColor");if(!system)system=node.attr("cocoaTouchSystemColor");
    if(system){
        static const std::unordered_map<std::string,std::array<double,3>> colors={
            {"systemRedColor",{1.0,0.23137254901960785,0.18823529411764706}},
            {"systemGreenColor",{0.20392156862745098,0.7803921568627451,0.34901960784313724}},
            {"systemBlueColor",{0.0,0.47843137254901963,1.0}},
            {"systemOrangeColor",{1.0,0.5843137254901961,0.0}},
            {"systemYellowColor",{1.0,0.8,0.0}},
            {"systemPinkColor",{1.0,0.17647058823529413,0.3333333333333333}},
            {"systemPurpleColor",{0.6862745098039216,0.3215686274509804,0.8705882352941177}},
            {"systemTealColor",{0.35294117647058826,0.7843137254901961,0.9803921568627451}},
            {"systemIndigoColor",{0.34509803921568627,0.33725490196078434,0.8392156862745098}},
            {"groupTableViewBackgroundColor",{0.9490196078431372,0.9490196078431372,0.9686274509803922}},
            {"systemGroupedBackgroundColor",{0.9490196078431372,0.9490196078431372,0.9686274509803922}},
            {"separatorColor",{0.23529411764705882,0.23529411764705882,0.2627450980392157}},
            {"secondaryLabelColor",{0.23529411764705882,0.23529411764705882,0.2627450980392157}}
        };auto found=colors.find(std::string(*system));if(found!=colors.end()){r=found->second[0];g=found->second[1];b=found->second[2];}o->set("UISystemColorName",gb.string(std::string(*system)));
    }
    if (node.attr_or("systemColor")=="systemBackgroundColor"||node.attr_or("systemColor")=="labelColor"||node.attr_or("systemColor")=="tableCellPlainBackgroundColor"||node.attr_or("systemColor")=="clearColor") {
        bool white=node.attr_or("systemColor")=="systemBackgroundColor"||node.attr_or("systemColor")=="tableCellPlainBackgroundColor";
        bool clear=node.attr_or("systemColor")=="clearColor";
        o->set("UIColorComponentCount",std::int64_t(2));
        o->set("UIWhite",nib::RawFloat{white?1.0f:0.0f});
        o->set("UIAlpha",nib::RawFloat{clear?0.0f:1.0f});
        nib::RawBytes bytes;auto white_text=clear?"0 0":white?"1":"0";bytes.data.assign(white_text,white_text+std::strlen(white_text));o->set("NSWhite",std::move(bytes));
        o->set("NSColorSpace",std::int64_t(4));
        return o;
    }
    if (auto w=to_double(node.attr("white"))) {
        // calibratedWhite is Generic Gray Gamma 1.8. UIKit archives the
        // equivalent extended-sRGB component, not the source scalar.
        double linear = std::pow(std::clamp(*w, 0.0, 1.0), 1.8);
        double converted = linear <= 0.0031308 ? 12.92 * linear
                                               : 1.055 * std::pow(linear, 1.0 / 2.4) - 0.055;
        r=g=b=converted;
        a=to_double(node.attr("alpha")).value_or(1);
        o->set("UIColorComponentCount",std::int64_t(2));
        o->set("UIWhite",nib::RawFloat{static_cast<float>(r)});
        o->set("UIAlpha",nib::RawFloat{static_cast<float>(a)});
        std::string white_text;
        if((*w==0.0||*w==1.0) && a==1.0){white_text=*w==0.0?"0":"1";o->set("UISystemColorName",gb.string(*w==0.0?"blackColor":"whiteColor"));}
        else{std::ostringstream white;white.setf(std::ios::fixed);white.precision(3);white<<r;white_text=white.str();}
        nib::RawBytes bytes; bytes.data.assign(white_text.begin(),white_text.end()); o->set("NSWhite",std::move(bytes));
        o->set("NSColorSpace",std::int64_t(4));
        return o;
    }
    else if(!system) { r=to_double(components->attr("red")).value_or(0); g=to_double(components->attr("green")).value_or(0); b=to_double(components->attr("blue")).value_or(0); }
    a=to_double(components->attr("alpha")).value_or(system&&*system=="secondaryLabelColor"?0.6:system&&*system=="separatorColor"?0.29:1.0);
    o->set("UIColorComponentCount", std::int64_t(4));
    o->set("UIRed", nib::RawFloat{static_cast<float>(r)});
    o->set("UIGreen", nib::RawFloat{static_cast<float>(g)});
    o->set("UIBlue", nib::RawFloat{static_cast<float>(b)});
    o->set("UIAlpha", nib::RawFloat{static_cast<float>(a)});
    o->set("NSColorSpace", std::int64_t(2));
    auto component_text=[&](double value){std::ostringstream out;out.setf(std::ios::fixed);out.precision(3);out<<value;auto s=out.str();while(s.size()>1&&s.back()=='0')s.pop_back();if(!s.empty()&&s.back()=='.')s.pop_back();return s;};
    auto s=component_text(r)+" "+component_text(g)+" "+component_text(b);if(a!=1.0||node.attr_or("customColorSpace")=="calibratedRGB")s+=" "+component_text(a);
    nib::RawBytes bytes; bytes.data.assign(s.begin(),s.end()); o->set("NSRGB",std::move(bytes));
    auto preserve_double=[&](std::string key,double value){if(static_cast<double>(static_cast<float>(value))!=value)o->set(std::move(key)+"-Double",value);};preserve_double("UIRed",r);preserve_double("UIGreen",g);preserve_double("UIBlue",b);preserve_double("UIAlpha",a);
    return o;
}

std::string property_key_for_color(std::string_view key) {
    static const std::unordered_map<std::string,std::string> m={
        {"backgroundColor","UIBackgroundColor"},{"textColor","UITextColor"},{"titleShadowColor","UIShadowColor"},
        {"titleColor","UITitleColor"},{"barTintColor","UIBarTintColor"},{"separatorColor","UISeparatorColor"},
        {"tintColor","UITintColor"},{"onTintColor","UISwitchOnTintColor"},
        {"pageIndicatorTintColor","UIPageIndicatorTintColor"},{"currentPageIndicatorTintColor","UICurrentPageIndicatorTintColor"},
        {"progressTintColor","UIProgressTintColor"},{"trackTintColor","UITrackTintColor"},{"thumbTintColor","UIThumbTintColor"},
        {"selectedImageTintColor","UISelectedImageTintColor"},{"unselectedItemTintColor","UIUnselectedItemTintColor"}
    };
    auto it=m.find(std::string(key));return it==m.end()?std::string{}:it->second;
}

GraphRef make_image_placeholder(nib::GraphBuilder& gb, std::string name) {
    auto o=gb.object("UIImageNibPlaceholder");
    o->set("UIImageWidth",nib::RawFloat{1.0f});
    o->set("UIImageHeight",nib::RawFloat{1.0f});
    o->set("UIResourceName",gb.string(std::move(name)));
    o->set("UISystemSymbolResourceName",std::monostate{});
    o->set("UISymbolImageConfiguration",std::monostate{});
    o->set("UIResourceCatalogName",std::monostate{});
    return o;
}

GraphRef make_image_or_symbol(nib::GraphBuilder& gb, std::string name, std::string_view catalog, std::string_view scale = "", const xml::Node* preferred_config = nullptr) {
    if (catalog == "system") {
        auto o = gb.object("UIImageNibPlaceholder");
        o->set("UIImageWidth", nib::RawFloat{0.0f});
        o->set("UIImageHeight", nib::RawFloat{0.0f});
        o->set("UIResourceName", std::monostate{});
        o->set("UISystemSymbolResourceName", gb.string(std::move(name)));
        o->set("UIResourceCatalogName", std::monostate{});

        std::string effective_scale(scale);
        std::optional<double> point_size;
        if (preferred_config) {
            if (auto s = preferred_config->attr("scale")) effective_scale = *s;
            point_size = to_double(preferred_config->attr("pointSize"));
        }
        if (!effective_scale.empty() || point_size.has_value()) {
            auto config = gb.object("UIImageSymbolConfiguration");
            if (point_size) {
                config->set("UIImageSymbolPointSize", *point_size);
            }
            if (!effective_scale.empty()) {
                std::int64_t scale_val = effective_scale == "large" ? 3 : effective_scale == "medium" ? 2 : effective_scale == "small" ? 1 : 0;
                config->set("UIImageSymbolScale", scale_val);
            }
            o->set("UISymbolImageConfiguration", config);
        } else {
            o->set("UISymbolImageConfiguration", std::monostate{});
        }
        return o;
    }
    return make_image_placeholder(gb, std::move(name));
}

GraphRef make_localizable_string(nib::GraphBuilder& gb, std::string value, std::string key) {
    auto localized=gb.object("NSLocalizableString");
    nib::RawBytes bytes; bytes.data.assign(value.begin(),value.end());
    localized->set("NS.bytes",std::move(bytes));
    localized->set("NSKey",gb.string(std::move(key)));
    localized->set("NSDev",gb.string(std::move(value)));
    return localized;
}

std::int64_t content_mode(std::string_view mode) {
    static const std::vector<std::string> modes={"scaleToFill","scaleAspectFit","scaleAspectFill","redraw","center","top","bottom","left","right","topLeft","topRight","bottomLeft","bottomRight"};
    auto it=std::find(modes.begin(),modes.end(),mode);return it==modes.end()?0:static_cast<std::int64_t>(it-modes.begin());
}

std::int64_t constraint_attr(std::optional<std::string_view> attr) {
    static const std::unordered_map<std::string, std::int64_t> m = {{"left", 1},
                                                                    {"right", 2},
                                                                    {"top", 3},
                                                                    {"bottom", 4},
                                                                    {"leading", 5},
                                                                    {"trailing", 6},
                                                                    {"width", 7},
                                                                    {"height", 8},
                                                                    {"centerX", 9},
                                                                    {"centerY", 10},
                                                                    {"baseline", 11},
                                                                    {"firstBaseline", 12},
                                                                    {"leftMargin", 13},
                                                                    {"rightMargin", 14},
                                                                    {"topMargin", 15},
                                                                    {"bottomMargin", 16},
                                                                    {"leadingMargin", 17},
                                                                    {"trailingMargin", 18},
                                                                    {"centerXWithinMargins", 19},
                                                                    {"centerYWithinMargins", 20},
                                                                    {"lastBaseline", 11}};
    if(!attr) return 0;
    auto it=m.find(std::string(*attr));
    return it==m.end()?0:it->second;
}

GraphRef make_constraint(nib::GraphBuilder& gb, SceneWork& sw, const xml::Node& n, const GraphRef& parent) {
    auto c=gb.object("NSLayoutConstraint");
    auto id=n.attr_or("id");if(!id.empty()){sw.objects[id]=c;sw.view_side[id]=true;}
    auto first=n.attr("firstItem"); if(first) sw.references.push_back({c,"NSFirstItem",std::string(*first)}); else c->set("NSFirstItem",parent);
    if(auto second=n.attr("secondItem")) sw.references.push_back({c,"NSSecondItem",std::string(*second)});
    auto fa=constraint_attr(n.attr("firstAttribute")),sa=constraint_attr(n.attr("secondAttribute"));
    c->set("NSFirstAttributeV2",fa);c->set("NSFirstAttribute",fa>=13&&fa<=18?fa-12:fa);
    if (n.attr("secondAttribute")) { c->set("NSSecondAttributeV2",sa);c->set("NSSecondAttribute",sa>=13&&sa<=18?sa-12:sa); }
    double constant=to_double(n.attr("constant")).value_or(0);
    if(n.attr_is_yes("symbolic"))constant=0;
    if(sa>=13&&sa<=18)constant+=(sa%2==0?-8.0:8.0);
    if(fa>=13&&fa<=18)constant+=(fa%2==0?8.0:-8.0);
    if(constant!=0){c->set("NSConstant",constant);if(sw.standalone_xib||(n.attr("constant")&&!n.attr_is_yes("symbolic"))||(!n.attr("secondItem")&&(fa==7||fa==8)))c->set("NSConstantV2",constant);}
    if(n.attr_is_yes("symbolic"))c->set("NSSymbolicConstant",gb.string("NSSpace"));
    c->set("NSShouldBeArchived",true);
    if(auto p=to_int(n.attr("priority")))c->set("NSPriority",*p);
    auto relation=n.attr_or("relation","equal");
    if (relation=="lessThanOrEqual")c->set("NSRelation",nib::RawInt64{-1});else if(relation!="equal")c->set("NSRelation",std::int64_t(1));
    if(auto mult=to_double(n.attr("multiplier")))c->set("NSMultiplier",*mult);
    if(auto ident=n.attr("identifier"))c->set("NSIdentifier",gb.string(std::string(*ident)));
    if(sw.standalone_xib)for(const auto& child:n.children)if(child->name=="variation")if(auto varied=to_double(child->attr("constant")))sw.constraint_variations.push_back({c,child->attr_or("key"),*varied,constant});
    return c;
}

void add_rect(const GraphRef& o,const xml::Node& n) {
    if(n.attr_or("key")!="frame") return;
    double x=to_double(n.attr("x")).value_or(0),y=to_double(n.attr("y")).value_or(0),w=to_double(n.attr("width")).value_or(0),h=to_double(n.attr("height")).value_or(0);
    nib::RawBytes bounds,center;bounds.data.push_back(0x07);center.data.push_back(0x07);
    auto appendd=[](std::vector<std::uint8_t>& d,double v){std::uint64_t u;std::memcpy(&u,&v,8);for(int i=0;i<8;++i)d.push_back((u>>(8*i))&0xff);};
    appendd(bounds.data,0);appendd(bounds.data,0);appendd(bounds.data,w);appendd(bounds.data,h);appendd(center.data,x+w/2);appendd(center.data,y+h/2);
    o->set("UIBounds",std::move(bounds));o->set("UICenter",std::move(center));
}

std::optional<std::pair<double,double>> storyboard_canvas_size(const IBDocument& doc) {
    const auto* root=doc.xml_document.root.get();
    const auto* device=root?root->first_child("device"):nullptr;
    if(!device)return std::nullopt;
    static const std::unordered_map<std::string,std::pair<double,double>> sizes={
        {"retina3_5",{320,480}},{"retina4",{320,568}},{"retina4_7",{375,667}},
        {"retina5_5",{414,736}},{"retina6_1",{414,896}},{"retina6_5",{414,896}}
    };
    auto found=sizes.find(device->attr_or("id"));if(found==sizes.end())return std::nullopt;
    auto size=found->second;if(device->attr_or("orientation")=="landscape")std::swap(size.first,size.second);
    return size;
}

std::int64_t autoresize_mask(const xml::Node& n){std::int64_t mask=0;const char* attrs[]={"flexibleMinX","widthSizable","flexibleMaxX","flexibleMinY","heightSizable","flexibleMaxY"};for(int i=0;i<6;++i)if(n.attr_is_yes(attrs[i]))mask|=(1<<i);return mask;}

struct BuilderContext {
    nib::GraphBuilder gb;
    Diagnostics& diagnostics;
    std::string file;
    NamedColors named_colors;
    bool standalone_xib{false};
    bool localized_source{false};
    bool legacy_styled_fonts{false};
    bool modern_system_colors{false};
    std::unordered_map<std::string,GraphRef> color_cache;
    BuilderContext(Diagnostics& d, std::string f) : diagnostics(d), file(std::move(f)), localized_source(std::filesystem::path(file).parent_path().extension()==".lproj") {}
    GraphRef localizable_string(std::string value,std::string key){return localized_source?make_localizable_string(gb,std::move(value),std::move(key)):gb.string(std::move(value));}
    std::unordered_map<std::string, SceneWork*> global_owner;
    std::unordered_map<std::string, GraphRef> global_objects;
    std::unordered_map<std::string, std::string> controller_id_to_nib;
    std::vector<std::unique_ptr<SceneWork>> scenes;
};

GraphRef parse_element(BuilderContext&, SceneWork&, const xml::Node&, const GraphRef&, bool);
GraphRef make_prototype_nib(BuilderContext&, const xml::Node&);

void parse_connections(BuilderContext& bc,SceneWork& sw,const xml::Node& connections,const GraphRef& source,bool segues_only=false){
    for(const auto& cptr:connections.children){const auto& n=*cptr;if(segues_only&&n.name!="segue")continue;if(n.name=="outlet"){sw.connections.push_back({"outlet",n.attr_or("property"),n.attr_or("destination"),source,0,&n});}
        else if(n.name=="outletCollection"){sw.connections.push_back({"outlet_collection",n.attr_or("property"),n.attr_or("destination"),source,0,&n});
        } else if (n.name == "action") {
            static const std::unordered_map<std::string, std::int64_t> masks = {{"touchDown", 1LL << 0},
                                                                                {"touchDownRepeat", 1LL << 1},
                                                                                {"touchDragInside", 1LL << 2},
                                                                                {"touchDragOutside", 1LL << 3},
                                                                                {"touchDragEnter", 1LL << 4},
                                                                                {"touchDragExit", 1LL << 5},
                                                                                {"touchUpInside", 1LL << 6},
                                                                                {"touchUpOutside", 1LL << 7},
                                                                                {"touchCancel", 1LL << 8},
                                                                                {"valueChanged", 1LL << 12},
                                                                                {"primaryActionTriggered", 1LL << 13},
                                                                                {"editingDidBegin", 1LL << 16},
                                                                                {"editingChanged", 1LL << 17},
                                                                                {"editingDidEnd", 1LL << 18},
                                                                                {"editingDidEndOnExit", 1LL << 19}};
            auto e = n.attr_or("eventType", "touchUpInside");
            auto it = masks.find(e);
            sw.connections.push_back({"action", n.attr_or("selector"), n.attr_or("destination"), source,
                                      it == masks.end() ? 0 : it->second, &n});
        } else if (n.name == "segue") {
            auto kind=n.attr_or("kind"); if(kind=="relationship"){sw.relationships.emplace_back(n.attr_or("relationship"),n.attr_or("destination"));continue;}
            std::string cls = "UIStoryboardSegueTemplate";
            if (kind == "show")
                cls = "UIStoryboardShowSegueTemplate";
            else if (kind == "showDetail")
                cls = "UIStoryboardShowSegueTemplate";
            else if (kind == "presentation")
                cls = "UIStoryboardPresentationSegueTemplate";
            else if (kind == "push")
                cls = "UIStoryboardPushSegueTemplate";
            else if (kind == "modal")
                cls = "UIStoryboardModalSegueTemplate";
            else if (kind == "replace")
                cls = "UIStoryboardReplaceSegueTemplate";
            else if (kind == "embed")
                cls = "UIStoryboardEmbedSegueTemplate";
            else if (kind == "unwind")
                cls = "UIStoryboardUnwindSegueTemplate";
            auto t = bc.gb.object(cls);
            if (auto id = n.attr("identifier")) t->set("UIIdentifier", bc.gb.string(std::string(*id)));
            if (n.attr("customClass"))
                t->set("UISegueClassName", bc.gb.string(runtime_custom_class_name(n, *n.attr("customClass"))));
            if (kind == "show") t->set("UIActionName", bc.gb.string("showViewController:sender:"));
            if (kind == "showDetail") t->set("UIActionName", bc.gb.string("showDetailViewController:sender:"));
            if (auto style = n.attr("modalPresentationStyle")) {
                static const std::unordered_map<std::string, std::int64_t> styles = {
                    {"fullScreen", 0}, {"pageSheet", 1},      {"formSheet", 2},          {"currentContext", 3},
                    {"custom", 4},     {"overFullScreen", 5}, {"overCurrentContext", 6}, {"popover", 7}};
                auto found = styles.find(std::string(*style));
                if (found != styles.end()) t->set("UIModalPresentationStyle", found->second);
            }
            if (kind == "embed") {
                t->set("UIPerformOnViewLoad", true);
                t->set("UIContainerView", std::monostate{});
            }
            if (kind == "unwind") {
                t->set("UIDestinationViewControllerIdentifier", std::monostate{});
                if (auto action = n.attr("unwindAction")) t->set("UIAction", bc.gb.string(std::string(*action)));
            }
            sw.segues.push_back({t,n.attr_or("destination"),kind,source,&n});sw.scene_extras.push_back(t);
        }
    }
}

void parse_common_children(BuilderContext& bc,SceneWork& sw,const xml::Node& node,const GraphRef& obj,bool view_side){
    std::vector<GraphRef> subviews,constraints,view_layout_guides;
    for(const auto& cp:node.children){const auto& c=*cp;
        if(c.name=="rect")add_rect(obj,c);
        else if(c.name=="autoresizingMask")obj->set("UIAutoresizingMask",autoresize_mask(c));
        else if(c.name=="color"){auto k=property_key_for_color(c.attr_or("key"));if(k.empty()&&obj->class_name=="UIActivityIndicatorView"&&c.attr_or("key")=="color")k="UIColor";if(!k.empty()){
            auto color_name=c.attr_or("systemColor");if(color_name.empty())color_name=c.attr_or("cocoaTouchSystemColor");if(color_name.empty())color_name=c.attr_or("name");
            if(color_name.empty())obj->set(k,make_color(bc.gb,c,&bc.named_colors));
            else {
                auto cache_key = (c.attr("systemColor") || c.attr("cocoaTouchSystemColor") ? "system:" : "named:") +
                                 color_name + ":" + c.attr_or("alpha");
                auto found = bc.color_cache.find(cache_key);
                if (found == bc.color_cache.end())
                    found = bc.color_cache.emplace(cache_key, make_color(bc.gb, c, &bc.named_colors)).first;
                obj->set(k, found->second);
            }
            if(k=="UIColor"&&obj->class_name=="UIActivityIndicatorView")if(auto value=obj->get(k))if(auto color=std::get_if<GraphRef>(&*value)){obj->set("UITintColor",*color);obj->set("UIDisableUpdateColorOnTraitCollectionChange",true);}
        }}
        else if(c.name=="subviews"){for(const auto& sp:c.children){auto child=parse_element(bc,sw,*sp,obj,view_side);if(child)subviews.push_back(child);}}
            else if(c.name=="constraints"){for(const auto& xp:c.children)if(xp->name=="constraint"&&!xp->attr_is_yes("placeholder")){auto constraint=make_constraint(bc.gb,sw,*xp,obj);constraints.push_back(constraint);sw.view_extras.push_back(constraint);}}
        else if(c.name=="connections")parse_connections(bc,sw,c,obj);
        else if(c.name=="fontDescription"){
            auto f = bc.gb.object("UIFont");
            double sz = to_double(c.attr("pointSize")).value_or(17);
            f->set("UIFontPointSize", sz);
            f->set("NSSize", sz);
            auto type = c.attr_or("type", "system");
            std::string name = type == "boldSystem"     ? ".SFUI-Semibold"
                               : type == "italicSystem" ? ".SFUI-RegularItalic"
                                                        : ".SFUI-Regular";
            if (auto custom = c.attr("name")) name = std::string(*custom);
            f->set("UIFontName", bc.gb.string(name));
            f->set("NSName", bc.gb.string(name));
            f->set("UISystemFont", type != "custom" && !c.attr("name"));
            obj->set("UIFont", f);
            if(bc.legacy_styled_fonts)if(auto style=c.attr("style")){
                    static const std::unordered_map<std::string, double> sizes = {
                        {"UICTFontTextStyleLargeTitle", 34}, {"UICTFontTextStyleTitle1", 25},
                        {"UICTFontTextStyleTitle2", 22},     {"UICTFontTextStyleTitle3", 20},
                        {"UICTFontTextStyleHeadline", 14},   {"UICTFontTextStyleBody", 17},
                        {"UICTFontTextStyleCallout", 16},    {"UICTFontTextStyleSubhead", 15},
                        {"UICTFontTextStyleFootnote", 12},   {"UICTFontTextStyleCaption1", 12},
                        {"UICTFontTextStyleCaption2", 11}};
                    if (auto found = sizes.find(std::string(*style)); found != sizes.end())
                        f->set("NSSize", found->second);
                    if (*style == "UICTFontTextStyleHeadline") {
                        auto semibold = bc.gb.string(".SFUI-Semibold");
                        f->set("UIFontName", semibold);
                        f->set("NSName", semibold);
                    }
                    f->set("UIFontPointSize", 0.0);
                    f->set("UIIBTextStyle", bc.gb.string(std::string(*style)));
                    f->set("UIFontTextStyleForScaling", std::monostate{});
                    f->set("UIFontPointSizeForScaling", 0.0);
                    f->set("UIFontMaximumPointSizeAfterScaling", 0.0);
                    f->set("UIFontTraits", std::int64_t(*style == "UICTFontTextStyleHeadline" ? 2 : 0));
            }
        }
        else if(c.name=="blurEffect"&&obj->class_name=="UIVisualEffectView"){
            auto effect = bc.gb.object("UIBlurEffect");
            auto style = c.attr_or("style", "regular");
            static const std::unordered_map<std::string, std::int64_t> styles = {{"extraLight", 0},
                                                                                 {"light", 1},
                                                                                 {"dark", 2},
                                                                                 {"regular", 4},
                                                                                 {"prominent", 5},
                                                                                 {"systemUltraThinMaterial", 6},
                                                                                 {"systemThinMaterial", 7},
                                                                                 {"systemMaterial", 8},
                                                                                 {"systemThickMaterial", 9},
                                                                                 {"systemChromeMaterial", 10}};
            auto found = styles.find(style);
            effect->set("UIBlurEffectStyle", found == styles.end() ? std::int64_t(4) : found->second);
            obj->set("UIVisualEffectViewEffect", effect);
        }
        else if(c.name=="vibrancyEffect"&&obj->class_name=="UIVisualEffectView"){
            auto effect=bc.gb.object("UIVibrancyEffect");auto blur=c.first_child("blurEffect");auto style=blur?blur->attr_or("style"):"regular";effect->set("UIVibrancyEffectBlurStyle",std::int64_t(style=="dark"?2:style=="light"?1:0));obj->set("UIVisualEffectViewEffect",effect);
            if(auto content=obj->get("UIVisualEffectViewContentView"))if(auto view=std::get_if<GraphRef>(&*content)){
                if(!sw.vibrancy_tint_color){if(auto background=(*view)->get("UIBackgroundColor"))if(auto color=std::get_if<GraphRef>(&*background))sw.vibrancy_tint_color=*color;}
                if(!sw.vibrancy_tint_color){xml::Node white;white.name="color";white.attributes={{"systemColor","systemBackgroundColor"}};sw.vibrancy_tint_color=make_color(bc.gb,white);sw.vibrancy_tint_color->set("UISystemColorName",bc.gb.string("whiteColor"));}
                (*view)->set("UITintColor",sw.vibrancy_tint_color);
            }
        }
        else if(c.name=="state"&&obj->class_name.find("UIButton")!=std::string::npos){
            auto state_key=c.attr_or("key","normal");
            std::string state_code="0";
            if(state_key=="highlighted")state_code="1";
            else if(state_key=="disabled")state_code="2";
            else if(state_key=="selected")state_code="4";

            auto content=bc.gb.object("UIButtonContent");
            if(auto title=c.attr("title"))content->set("UITitle",bc.gb.string(std::string(*title)));

            const xml::Node* img_ref=c.first_child("imageReference");
            const xml::Node* pref_cfg=c.first_child("preferredSymbolConfiguration");
            if(!pref_cfg)pref_cfg=node.first_child("preferredSymbolConfiguration");

            if(img_ref){
                auto img_name=img_ref->attr_or("image");
                auto catalog=img_ref->attr_or("catalog");
                auto symbol_scale=img_ref->attr_or("symbolScale");
                if(!img_name.empty()){
                    content->set("UIImage",make_image_or_symbol(bc.gb,std::string(img_name),catalog,symbol_scale,pref_cfg));
                }
            }else if(auto img_name=c.attr("image")){
                content->set("UIImage",make_image_or_symbol(bc.gb,std::string(*img_name),c.attr_or("catalog"),"",pref_cfg));
            }

            for(const auto& sc:c.children){
                if(sc->name=="color"){
                    auto key=sc->attr_or("key");
                    if(key=="titleColor")content->set("UITitleColor",make_color(bc.gb,*sc,&bc.named_colors));
                    else if(key=="titleShadowColor")content->set("UIShadowColor",make_color(bc.gb,*sc,&bc.named_colors));
                }
            }

            if(auto existing=obj->get("UIButtonStatefulContent")){
                if(auto dict=std::get_if<GraphRef>(&*existing)){
                    (*dict)->properties.emplace_back("UINibEncoderEmptyKey",bc.gb.string(state_code));
                    (*dict)->properties.emplace_back("UINibEncoderEmptyKey",content);
                }
            }else{
                obj->set("UIButtonStatefulContent",bc.gb.dictionary({{bc.gb.string(state_code),content}}));
            }
        }
        else if(c.name=="imageReference"){
            auto key=c.attr_or("key");
            auto img_name=c.attr_or("image");
            auto catalog=c.attr_or("catalog");
            auto symbol_scale=c.attr_or("symbolScale");
            const xml::Node* pref_cfg=node.first_child("preferredSymbolConfiguration");
            if(!img_name.empty()&&(key=="image"||key.empty())){
                obj->set("UIImage",make_image_or_symbol(bc.gb,std::string(img_name),catalog,symbol_scale,pref_cfg));
            }
        }
        else if(c.name=="image"&&c.attr("key")){obj->set("UIImage",make_image_or_symbol(bc.gb,c.attr_or("name"),c.attr_or("catalog")));}
        else if(c.name=="layoutGuides"){for(const auto& gp:c.children){auto g=parse_element(bc,sw,*gp,obj,true);if(g)sw.layout_guides.push_back(g);}}
        else if(c.name=="navigationItem"||c.name=="navigationBar"||c.name=="barButtonItem"){parse_element(bc,sw,c,obj,view_side);}
        else if(c.name=="sections"&&node.name=="tableView"&&node.attr_or("dataMode")=="static"){
            auto data_source=bc.gb.object("UITableViewDataSource");std::vector<GraphRef> sections;
            sw.view_extras.push_back(data_source);sw.view_tops.push_back(data_source);sw.static_data_source=data_source;
            for(const auto& section_node:c.children){if(section_node->name!="tableViewSection")continue;auto section=bc.gb.object("UITableViewSection");sw.view_extras.push_back(section);std::vector<GraphRef> rows;
                auto section_id = section_node->attr_or("id");
                if (auto title = section_node->attr("headerTitle"))
                    section->set("UITableSectionHeaderTitle",
                                 title->empty()
                                     ? bc.gb.string("")
                                     : bc.localizable_string(std::string(*title), section_id + ".headerTitle"));
                if (auto title = section_node->attr("footerTitle"))
                    section->set("UITableSectionFooterTitle",
                                 title->empty()
                                     ? bc.gb.string("")
                                     : bc.localizable_string(std::string(*title), section_id + ".footerTitle"));
                for(const auto& value:section_node->children)if(value->name=="string"){
                    if(value->attr_or("key")=="headerTitle")section->set("UITableSectionHeaderTitle",bc.localizable_string(value->text,section_id+".headerTitle"));
                    if(value->attr_or("key")=="footerTitle")section->set("UITableSectionFooterTitle",bc.localizable_string(value->text,section_id+".footerTitle"));
                }
                for (const auto& holder : section_node->children) {
                    if (holder->name != "cells") continue;
                    for (const auto& cell_node : holder->children) {
                        auto cell = parse_element(bc, sw, *cell_node, obj, view_side);
                        if (!cell) continue;
                        auto row = bc.gb.object("UITableViewRow");
                        row->set("UITableRowCell", cell);
                        row->set("UITableRowHeight", nib::RawFloat{static_cast<float>(
                                                         to_double(cell_node->attr("rowHeight")).value_or(-1))});
                        rows.push_back(row);
                    }
                }
                section->set("UITableSectionRows",bc.gb.array(rows));sections.push_back(section);
            }
            data_source->set("UITableSections",bc.gb.array(sections));
        }
        else if(c.name=="segments"&&node.name=="segmentedControl"){
            std::vector<GraphRef> segments;auto control_id=node.attr_or("id");std::size_t index=0;
            for (const auto& segment_node : c.children) {
                if (segment_node->name != "segment") continue;
                auto segment = bc.gb.object("UISegment");
                segment->set("UIDeepDrawRect", true);
                segment->set("UIAutoresizeSubviews", true);
                segment->set("UIViewSemanticContentAttribute", std::int64_t(0));
                segment->set("UIViewLargeContentStoredProperties", std::monostate{});
                segment->set("UISegmentStyle", std::int64_t(5));
                xml::Node frame;
                frame.attributes = {{"key", "frame"}, {"x", "0"}, {"y", "0"}, {"width", "0"}, {"height", "32"}};
                add_rect(segment, frame);
                if (auto title = segment_node->attr("title"))
                    segment->set("UISegmentInfo",
                                 bc.localizable_string(std::string(*title),
                                                       control_id + ".segmentTitles[" + std::to_string(index) + "]"));
                segments.push_back(segment);
                ++index;
            }
            if(!segments.empty()){segments.back()->set("UISegmentPosition",std::int64_t(3));auto reversed=segments;std::reverse(reversed.begin(),reversed.end());obj->set("UISubviews",bc.gb.mutable_array(reversed));obj->set("UISegments",bc.gb.mutable_array(segments));}
        }
        else if(c.name=="cells"&&node.name=="collectionView"){
            std::vector<std::pair<GraphRef,GraphRef>> registered,external;
            for (const auto& cell : c.children) {
                if (cell->name != "collectionViewCell") continue;
                auto reuse = cell->attr_or("reuseIdentifier");
                if (reuse.empty()) continue;
                auto key = bc.gb.string(reuse);
                registered.push_back({key, make_prototype_nib(bc, *cell)});
                external.push_back({key, bc.gb.mutable_dictionary({})});
            }
            if(!registered.empty()){obj->set("UICollectionViewCellPrototypeNibExternalObjects",bc.gb.mutable_dictionary(external));obj->set("UICollectionViewCellNibDict",bc.gb.mutable_dictionary(registered));}
        }
        else if(c.name=="collectionReusableView"&&node.name=="collectionView"){
            auto reuse=c.attr_or("reuseIdentifier");
            if(!reuse.empty()){
                std::string kind="UICollectionElementKindSectionHeader";
                if(c.attr_or("key")=="sectionFooterView")kind="UICollectionElementKindSectionFooter";
                auto key=bc.gb.string(kind+"/"+reuse);
                obj->set("UICollectionViewSupplementaryViewPrototypeNibExternalObjects",bc.gb.mutable_dictionary({{key,bc.gb.mutable_dictionary({})}}));
                obj->set("UICollectionViewSupplementaryViewNibDict",bc.gb.mutable_dictionary({{key,make_prototype_nib(bc,c)}}));
            }
        }
        else if(c.name=="prototypes"&&node.name=="tableView"){
            auto has_unsupported_connections=[&](const xml::Node& cell,const auto& self)->bool{
                if(cell.name=="connections")for(const auto& connection:cell.children){
                    if(connection->name=="segue")continue;
                    auto destination=connection->attr_or("destination");
                    if(destination==sw.controller_id)continue;
                    auto contains_id=[&](const xml::Node& root,const auto& recurse)->bool{if(root.attr_or("id")==destination)return true;for(const auto& child:root.children)if(recurse(*child,recurse))return true;return false;};
                    if(!contains_id(c,contains_id))return true;
                }
                for(const auto& child:cell.children)if(self(*child,self))return true;
                return false;
            };
            bool unsupported_connections=false;for(const auto& cell:c.children)if(has_unsupported_connections(*cell,has_unsupported_connections))unsupported_connections=true;
            if(unsupported_connections){for(const auto& cell:c.children)(void)parse_element(bc,sw,*cell,obj,view_side);}
            else{
                std::vector<std::pair<GraphRef,GraphRef>> registered,external;
                for(const auto& cell:c.children){if(cell->name!="tableViewCell")continue;auto reuse=cell->attr_or("reuseIdentifier");if(reuse.empty())continue;auto key=bc.gb.string(reuse);registered.push_back({key,make_prototype_nib(bc,*cell)});external.push_back({key,bc.gb.mutable_dictionary({})});
                    if(const auto* connections=cell->first_child("connections")){auto before=sw.segues.size();parse_connections(bc,sw,*connections,sw.controller,true);for(std::size_t i=before;i<sw.segues.size();++i)sw.table_prototype_segues.push_back({reuse,sw.segues[i].template_object});}
                    auto collect_externals = [&](const xml::Node& root, const auto& self) -> void {
                        if (root.name == "connections")
                            for (const auto& connection : root.children)
                                if (connection->name != "segue" &&
                                    connection->attr_or("destination") == sw.controller_id) {
                                    sw.table_prototype_externals.push_back({reuse, sw.controller});
                                    return;
                                }
                        for (const auto& child : root.children) self(*child, self);
                    };
                    collect_externals(*cell,collect_externals);
                }
                if(!registered.empty()){obj->set("UITableViewCellPrototypeNibs",bc.gb.mutable_dictionary(registered));obj->set("UITableViewCellPrototypeNibExternalObjects",bc.gb.mutable_dictionary(external));}
            }
        }
        else if(c.name=="rightBarButtonItems"){
            std::vector<GraphRef> items;for(const auto& xp:c.children){auto item=parse_element(bc,sw,*xp,obj,view_side);if(item)items.push_back(item);}if(!items.empty()){obj->set("UIRightBarButtonItem",items.front());obj->set("UIRightBarButtonItems",bc.gb.array(items));}
        }
        else if(c.name=="prototypes"||c.name=="cells"||c.name=="tableViewSection"||c.name=="items"||c.name=="toolbarItems"||c.name=="segments"||c.name=="gestureRecognizers"){
            for(const auto& xp:c.children) (void)parse_element(bc,sw,*xp,obj,view_side);
        }
        else if(c.name=="textInputTraits"){
        } else if (c.name == "variation" || c.name == "userDefinedRuntimeAttributes" || c.name == "nil" ||
                   c.name == "point" || c.name == "size" || c.name == "simulatedNavigationBarMetrics" ||
                   c.name == "simulatedTabBarMetrics" || c.name == "simulatedToolbarMetrics" ||
                   c.name == "listContentConfiguration" || c.name == "textAttributes" ||
                   c.name == "directionalEdgeInsets" || c.name == "imageReference" || c.name == "segment" ||
                   c.name == "string" || c.name == "value" || c.name == "accessibility" ||
                   c.name == "buttonConfiguration" || c.name == "preferredSymbolConfiguration" ||
                   c.name == "wkWebViewConfiguration" || c.name == "wkPreferences" ||
                   c.name == "audiovisualMediaTypes" || c.name == "designables" || c.name == "designable" ||
                   c.name == "hierarchicalColors" || c.name == "integer" || c.name == "real") {
        } else if (!base_class_for_tag(c.name).empty()) {
            auto child=parse_element(bc,sw,c,obj,view_side);
            if(child&&c.name=="viewLayoutGuide"&&c.attr_or("key")=="safeArea")view_layout_guides.push_back(child);
            if(child&&node.name=="tableView"&&c.attr_or("key")=="tableFooterView"){
                // Grouped tables archive their footer at the initial table
                // content origin; the storyboard canvas Y is only an editor
                // placement. The static rows are installed after this view.
                auto style=node.attr_or("style","plain");
                if(style=="grouped"||style=="insetGrouped")if(const auto* footer_frame=c.first_child("rect")){
                    const auto* table_frame=node.first_child("rect");
                    xml::Node frame;frame.attributes={{"key","frame"},{"x","0"},{"y","53"},{"width",table_frame?table_frame->attr_or("width","0"):footer_frame->attr_or("width","0")},{"height",footer_frame->attr_or("height","0")}};
                    add_rect(child,frame);
                }
                obj->set("UITableFooterView",child);subviews.push_back(child);
            }
        } else if (!compiler_knows_tag(c.name)) {
            bc.diagnostics.warn("OPENIB-W1200", "Unsupported child element <" + c.name + ">", bc.file, c.line);
        }
    }
    if(node.attr_or("key")=="view" && !sw.layout_guides.empty()) subviews.insert(subviews.end(), sw.layout_guides.begin(), sw.layout_guides.end());
    if(!subviews.empty()){obj->set("UISubviews",bc.gb.mutable_array(subviews));if(node.name=="stackView")obj->set("UIStackViewArrangedSubviews",bc.gb.array(subviews));}
    if(!view_layout_guides.empty())obj->set("UIViewLayoutGuides",bc.gb.mutable_array(view_layout_guides));
    if(const auto* variation=node.first_child("variation"))if(variation->attr_or("key")=="default")if(const auto* mask=variation->first_child("mask"))if(mask->attr_or("key")=="constraints"){
        std::unordered_set<std::uint64_t> excluded;for(const auto& child:mask->children)if(child->name=="exclude")if(auto found=sw.objects.find(child->attr_or("reference"));found!=sw.objects.end())excluded.insert(found->second->serial);
        std::erase_if(constraints,[&](const GraphRef& constraint){return excluded.contains(constraint->serial);});
    }
    if(!constraints.empty())obj->set("UIViewAutolayoutConstraints",bc.gb.mutable_array(constraints));
}

GraphRef parse_element(BuilderContext& bc,SceneWork& sw,const xml::Node& n,const GraphRef& parent,bool view_side){
    if(n.name=="viewLayoutGuide"&&n.attr_or("key")=="safeArea"&&parent){
        auto guide = bc.gb.object("UILayoutGuide");
        guide->set("UILayoutGuideOwningView", parent);
        guide->set("UILayoutGuideIdentifier", bc.gb.string("UIViewSafeAreaLayoutGuide"));
        guide->set("UILayoutGuideOwningViewIsLocked", true);
        guide->set("UILayoutGuideShouldBeArchived", true);
        guide->set("UILayoutGuideAllowsNegativeDimensions", true);
        std::vector<GraphRef> system_constraints;
        for(const auto& [attribute,name,guide_first]:std::vector<std::tuple<std::int64_t,const char*,bool>>{{3,"top",true},{1,"left",true},{4,"bottom",false},{2,"right",false}}){
            auto constraint = bc.gb.object("NSLayoutConstraint");
            constraint->set("NSFirstItem", guide_first ? guide : parent);
            constraint->set("NSFirstAttributeV2", attribute);
            constraint->set("NSFirstAttribute", attribute);
            constraint->set("NSSecondItem", guide_first ? parent : guide);
            constraint->set("NSSecondAttributeV2", attribute);
            constraint->set("NSSecondAttribute", attribute);
            constraint->set("NSShouldBeArchived", false);
            constraint->set("NSLayoutIdentifier", bc.gb.string(std::string("UIViewSafeAreaLayoutGuide-") + name));
            system_constraints.push_back(constraint);
        }
        guide->set("UILayoutGuideSystemConstraints",bc.gb.array(system_constraints));
        auto id=n.attr_or("id");if(!id.empty()){sw.objects[id]=guide;sw.view_side[id]=true;bc.global_objects[id]=guide;bc.global_owner[id]=&sw;}
        auto placeholder = bc.gb.object("UILayoutGuide");
        placeholder->set("UILayoutGuideOwningView", std::monostate{});
        placeholder->set("UILayoutGuideIdentifier", bc.gb.string(""));
        placeholder->set("UILayoutGuideOwningViewIsLocked", false);
        placeholder->set("UILayoutGuideShouldBeArchived", false);
        placeholder->set("UILayoutGuideAllowsNegativeDimensions", false);
        sw.view_extras.push_back(placeholder);
        return guide;
    }
    if (n.name == "placeholder") {
        auto o = bc.gb.proxy(n.attr_or("placeholderIdentifier"));
        auto id = n.attr_or("id");
        if (!id.empty()) {
            sw.objects[id] = o;
            sw.view_side[id] = false;
            bc.global_objects[id] = o;
            bc.global_owner[id] = &sw;
        }
        if (const auto* connections = n.first_child("connections")) parse_connections(bc, sw, *connections, o);
        return o;
    }
    if(n.name=="exit"){auto o=bc.gb.object("UIStoryboardExitPlaceholder");auto id=n.attr_or("id");if(!id.empty()){sw.objects[id]=o;sw.view_side[id]=false;bc.global_objects[id]=o;bc.global_owner[id]=&sw;}return o;}
    if (n.name == "viewControllerLayoutGuide") {
        auto o = bc.gb.object("_UILayoutGuide");
        o->set("UIDeepDrawRect", true);
        o->set("UIOpaque", true);
        o->set("UIHidden", true);
        o->set("UIAutoresizeSubviews", true);
        o->set("UIViewDoesNotTranslateAutoresizingMaskIntoConstraints", true);
        o->set("UIViewSemanticContentAttribute", std::int64_t(0));
        o->set("UIViewLargeContentStoredProperties", std::monostate{});
        auto t = n.attr_or("type");
        if (t == "top")
            o->set("_UILayoutGuideIdentifier", bc.gb.string("_UIViewControllerTop"));
        else if (t == "bottom")
            o->set("_UILayoutGuideIdentifier", bc.gb.string("_UIViewControllerBottom"));
        auto id = n.attr_or("id");
        if (!id.empty()) {
            sw.objects[id] = o;
            sw.view_side[id] = true;
            bc.global_objects[id] = o;
            bc.global_owner[id] = &sw;
        }
        sw.typed_layout_guides.push_back({o, t});
        sw.view_extras.push_back(o);
        return o;
    }
    auto base=base_class_for_tag(n.name); if(base.empty()) return nullptr;GraphRef o;if(n.name=="view"&&n.attr_or("key")=="contentView"&&parent&&parent->class_name=="UIVisualEffectView")o=bc.gb.object("_UIVisualEffectContentView");else o=class_swapped(bc.gb,n,base);
    auto id=n.attr_or("id");if(!id.empty()){sw.objects[id]=o;sw.view_side[id]=view_side;bc.global_objects[id]=o;bc.global_owner[id]=&sw;}
    if(view_side)sw.view_extras.push_back(o);else sw.scene_extras.push_back(o);
    if(view_side&&n.name!="collectionViewFlowLayout"){
        o->set("UIDeepDrawRect",true);
        if(n.attr_or("opaque")!="NO")o->set("UIOpaque",true);
        if(n.attr_is_yes("hidden"))o->set("UIHidden",true);
        o->set("UIViewSemanticContentAttribute",std::int64_t(0));
        o->set("UIViewLargeContentStoredProperties",std::monostate{});
    }
    if(n.attr_is_yes("preservesSuperviewLayoutMargins")){o->set("UIViewPreservesSuperviewMargins",true);o->set("UIViewPreservesSpecificSuperviewMargins",std::int64_t(15));}
    if(n.attr_or("insetsLayoutMarginsFromSafeArea")=="NO")o->set("UIViewInsetsLayoutMarginsFromSafeArea",std::int64_t(0));
    if(n.attr_is_yes("translatesAutoresizingMaskIntoConstraints")==false && n.attr("translatesAutoresizingMaskIntoConstraints")&&n.attr_or("fixedFrame")!="YES"&&!n.first_child("autoresizingMask"))o->set("UIViewDoesNotTranslateAutoresizingMaskIntoConstraints",true);
    if (n.name == "tapGestureRecognizer") {
        if (n.attr_is_yes("delaysTouchesBegan")) o->set("UIGestureRecognizer.delaysTouchesBegan", true);
        o->set("UIGestureRecognizer.allowedTouchTypes", std::int64_t(15));
        o->set("UIGestureRecognizer.requiresExclusiveTouchType", true);
        o->set("UITapGestureRecognizer._imp", bc.gb.object("UITapRecognizer"));
    }
    if (auto cm = n.attr("contentMode")) {
        auto v = content_mode(*cm);
        if (v) o->set("UIContentMode", v);
    }
    if (n.attr_or("clipsSubviews") == "YES") o->set("UIClipsToBounds", true);
    if (n.attr_or("userInteractionEnabled") == "NO") o->set("UIUserInteractionDisabled", true);
    if (n.attr_is_yes("multipleTouchEnabled")) o->set("UIMultipleTouchEnabled", true);
    if (n.name != "navigationItem" && n.name != "barButtonItem" && n.name != "tapGestureRecognizer" &&
        n.name != "collectionViewFlowLayout")
        o->set("UIAutoresizeSubviews", true);
    if(o->class_name=="_UIVisualEffectContentView"&&parent)parent->set("UIVisualEffectViewContentView",o);if(n.name=="visualEffectView")o->set("UIVisualEffectViewGroupName",std::monostate{});
    if (n.name == "label" && n.attr("text")) {
        auto id = n.attr_or("id");
        o->set("UIText", bc.localizable_string(std::string(*n.attr("text")), id + ".text"));
        bool nil_text_color = false;
        for (const auto& child : n.children)
            if (child->name == "nil" && child->attr_or("key") == "textColor") nil_text_color = true;
        o->set("UIDisableUpdateTextColorOnTraitCollectionChange", !nil_text_color);
        if (nil_text_color) {
            if (!sw.table_label_color) {
                xml::Node color;
                color.name = "color";
                color.attributes = {{"systemColor", "labelColor"}};
                sw.table_label_color = make_color(bc.gb, color);
            }
            o->set("UITextColor", sw.table_label_color);
        }
        auto alignment = n.attr_or("textAlignment", "natural");
        o->set("UITextAlignment", std::int64_t(alignment == "right"    ? 2
                                               : alignment == "center" ? 1
                                               : alignment == "left"   ? 0
                                                                       : 4));
        nib::RawBytes offset;
        offset.data.assign(17, 0);
        offset.data[0] = 7;
        offset.data[15] = 0xf0;
        offset.data[16] = 0xbf;
        o->set("UIShadowOffset", std::move(offset));
        if (auto font_value = o->get("UIFont"))
            if (auto font_ref = std::get_if<GraphRef>(&*font_value)) {
                auto font = *font_ref;
                if (!font->get("UIIBTextStyle")) {
                    auto size_value = font->get("UIFontPointSize");
                    double size = size_value ? std::get<double>(*size_value) : 17.0;
                    auto font_type = n.first_child("fontDescription")
                                         ? n.first_child("fontDescription")->attr_or("type", "system")
                                         : "system";
                    auto identity = std::make_pair(font_type, size);
                    if (auto existing = sw.standard_table_fonts.find(identity);
                        existing != sw.standard_table_fonts.end())
                        o->set("UIFont", existing->second);
                    else {
                        auto number = bc.gb.object("NSNumber");
                        number->set("NS.dblval", size);
                        auto attrs = bc.gb.dictionary(
                            {{bc.gb.string("NSCTFontUIUsageAttribute"),
                              bc.gb.string(font_type == "boldSystem" ? "CTFontEmphasizedUsage" : "CTFontRegularUsage")},
                             {bc.gb.string("NSFontSizeAttribute"), number}});
                        auto descriptor = bc.gb.object("UIFontDescriptor");
                        descriptor->set("UIFontDescriptorAttributes", attrs);
                        descriptor->set("UIFontDescriptorOptions", std::int64_t(2147517444));
                        font->set("UIFontDescriptor", descriptor);
                        font->set("UIFontTextStyleForScaling", std::monostate{});
                        font->set("UIFontPointSizeForScaling", 0.0);
                        font->set("UIFontMaximumPointSizeAfterScaling", 0.0);
                        font->set("UIFontTraits", std::int64_t(0));
                        sw.standard_table_fonts[identity] = font;
                    }
                }
            }
    } else if (auto text = n.attr("text"))
        o->set("UIText", bc.gb.string(std::string(*text)));
    if(auto image=n.attr("image")){const auto* pref=n.first_child("preferredSymbolConfiguration");o->set("UIImage",make_image_or_symbol(bc.gb,std::string(*image),n.attr_or("catalog"),"",pref));}
    if(n.name=="navigationItem"){
        if(auto title=n.attr("title"))o->set("UITitle",bc.localizable_string(std::string(*title),id+".title"));
        o->set("UICenterItemGroups",bc.gb.array({}));
        auto large=n.attr_or("largeTitleDisplayMode","automatic");
        o->set("UILargeTitleDisplayMode",std::int64_t(large=="always"?1:large=="never"?2:0));
        if(parent)parent->set("UINavigationItem",o);
    }
    if(n.name=="segmentedControl"){
        if(parent&&n.attr_or("key")=="titleView")parent->set("UITitleView",o);
        o->set("UIDeepDrawRect",true);o->set("UIViewSemanticContentAttribute",std::int64_t(0));o->set("UIViewLargeContentStoredProperties",std::monostate{});
        o->set("UIContentHorizontalAlignment", std::int64_t(1));
        o->set("UIContentVerticalAlignment", std::int64_t(1));
        o->set("UIContentVerticalAlignment2", std::int64_t(1));
        o->set("UIPointerInteractionEnabled", true);
        o->set("UIViewContentHuggingPriority", bc.gb.string("{250, 250}"));
        o->set("UISelectedSegmentIndex", std::int64_t(to_int(n.attr("selectedSegmentIndex")).value_or(0)));
    }
    if(n.name=="barButtonItem"){
        if(auto title=n.attr("title"))o->set("UITitle",bc.localizable_string(std::string(*title),id+".title"));
        if(n.attr_or("enabled")!="NO")o->set("UIEnabled",true);
        auto explicit_style=n.attr_or("style");if(explicit_style.empty())o->set("UIStyle",std::int64_t(1));else if(explicit_style=="done")o->set("UIStyle",std::int64_t(2));else if(explicit_style!="plain")o->set("UIStyle",std::int64_t(1));
        if (auto system = n.attr("systemItem")) {
            static const std::unordered_map<std::string, std::int64_t> items = {
                {"done", 0},          {"cancel", 1},     {"edit", 2},    {"save", 3},      {"add", 4},
                {"flexibleSpace", 5}, {"fixedSpace", 6}, {"compose", 7}, {"reply", 8},     {"action", 9},
                {"organize", 10},     {"bookmarks", 11}, {"search", 12}, {"refresh", 13},  {"stop", 14},
                {"camera", 15},       {"trash", 16},     {"play", 17},   {"pause", 18},    {"rewind", 19},
                {"fastForward", 20},  {"undo", 21},      {"redo", 22},   {"pageCurl", 23}, {"close", 24}};
            auto found = items.find(std::string(*system));
            if (found != items.end()) o->set("UISystemItem", found->second);
            o->set("UIIsSystemItem", true);
        }
        if (parent) {
            auto key = n.attr_or("key");
            if (key == "rightBarButtonItem") {
                parent->set("UIRightBarButtonItem", o);
                parent->set("UIRightBarButtonItems", bc.gb.array({o}));
            } else if (key == "leftBarButtonItem") {
                parent->set("UILeftBarButtonItem", o);
                parent->set("UILeftBarButtonItems", bc.gb.array({o}));
            } else if (key == "backBarButtonItem")
                parent->set("UIBackBarButtonItem", o);
        }
        if(n.attr_or("catalog")=="system")if(auto image=o->get("UIImage"))if(auto ref=std::get_if<GraphRef>(&*image)){(*ref)->set("UIImageWidth",nib::RawFloat{0});(*ref)->set("UIImageHeight",nib::RawFloat{0});(*ref)->set("UISystemSymbolResourceName",bc.gb.string(n.attr_or("image")));}
    }
    if(n.name=="navigationBar"&&parent){parent->set("UINavigationBar",o);o->set("UIDelegate",parent);}
    if(n.name=="toolbar"&&parent)parent->set("UIToolbar",o);
    if(n.name=="navigationBar"){
        o->set("UIBarPosition",std::int64_t(2));o->set("UIBarTranslucence",std::int64_t(1));o->set("UIDeepDrawRect",true);o->set("UIIsLocked",true);
        o->set("UIViewSemanticContentAttribute",std::int64_t(0));o->set("UIViewLargeContentStoredProperties",std::monostate{});
        o->set("UIViewContentHuggingPriority",bc.gb.string("{250, 250}"));o->set("UIAutoresizingMask",std::int64_t(2));
        if(n.attr_is_yes("largeTitles"))o->set("UIBarPrefersLargeTitles",true);
        if(n.attr_or("barStyle")=="black")o->set("UIBarStyle",std::int64_t(1));
        if(n.attr_or("insetsLayoutMarginsFromSafeArea")=="NO")o->set("UIViewInsetsLayoutMarginsFromSafeArea",std::int64_t(0));
        auto source_frame=n.first_child("rect");auto frame_y=source_frame?source_frame->attr_or("y","0"):"0";xml::Node frame;frame.attributes={{"key","frame"},{"x","0"},{"y",frame_y},{"width","0"},{"height","50"}};add_rect(o,frame);
    }
    if(n.name=="toolbar"){
        o->set("UIBarPosition", std::int64_t(1));
        o->set("UIBarTranslucence", std::int64_t(1));
        o->set("UIDeepDrawRect", true);
        o->set("UIViewSemanticContentAttribute", std::int64_t(0));
        o->set("UIViewLargeContentStoredProperties", std::monostate{});
        o->set("UIViewContentHuggingPriority", bc.gb.string("{250, 250}"));
        o->set("UIItems", bc.gb.array({}));
        if (n.attr_or("clearsContextBeforeDrawing") == "NO") o->set("UIClearsContextBeforeDrawing", false);
    }
    if(n.name=="tableView"&&parent&&parent->class_name.find("TableViewController")!=std::string::npos)parent->set("UITableView",o);
    if(n.name=="collectionViewFlowLayout"&&parent&&parent->class_name=="UICollectionView")parent->set("UICollectionLayout",o);
    if(n.name=="collectionView"||n.name=="scrollView"){
        if(n.attr_is_yes("pagingEnabled"))o->set("UIPagingEnabled",true);
        if(n.attr_or("showsHorizontalScrollIndicator")=="NO")o->set("UIShowsHorizontalScrollIndicator",false);
        if(n.attr_or("showsVerticalScrollIndicator")=="NO")o->set("UIShowsVerticalScrollIndicator",false);
        if(n.attr_or("scrollEnabled")=="NO")o->set("UIScrollEnabled",false);
        if(n.attr_or("bounces")=="NO")o->set("UIBounces",false);
        if(n.attr_is_yes("alwaysBounceHorizontal"))o->set("UIAlwaysBounceHorizontal",true);
    }
    if(n.name=="collectionView"){
        o->set("UIScrollViewIndicatorInsetAdjustmentBehavior", std::int64_t(1));
        o->set("UIBouncesZoom", true);
        o->set("UIDelegate", std::monostate{});
        o->set("UIScrollViewContentInsetAdjustmentBehavior", std::int64_t(0));
        o->set("UIAllowsUserInitiatedMultipleSelection", true);
        o->set("UICollectionViewPrefetchingEnabled", true);
        if(n.attr_is_yes("alwaysBounceVertical"))o->set("UIAlwaysBounceVertical",true);
        if(n.attr_or("indicatorStyle")=="white")o->set("UIIndicatorStyle",std::int64_t(2));if(n.attr_or("delaysContentTouches")=="NO")o->set("UIDelaysContentTouches",false);
    }
    if(n.name=="collectionViewFlowLayout"){
        if(n.attr_or("scrollDirection")=="horizontal")o->set("UIScrollDirection",std::int64_t(1));
        auto encode_geometry=[](std::initializer_list<double> values){nib::RawBytes raw;raw.data.push_back(0x07);for(double value:values){std::uint64_t bits;std::memcpy(&bits,&value,8);for(int byte=0;byte<8;++byte)raw.data.push_back(static_cast<std::uint8_t>(bits>>(byte*8)));}return raw;};
        if(auto spacing=to_double(n.attr("minimumLineSpacing"));spacing&&*spacing!=10)o->set("UILineSpacing",nib::RawFloat{static_cast<float>(*spacing)});
        if(auto spacing=to_double(n.attr("minimumInteritemSpacing"));spacing&&*spacing!=10)o->set("UIInteritemSpacing",nib::RawFloat{static_cast<float>(*spacing)});
        if (n.attr_is_yes("automaticEstimatedItemSize")) {
            auto size = bc.gb.object("NSValue");
            size->set("NS.special", std::int64_t(2));
            size->set("NS.sizeval", bc.gb.string("{1.7976931348623157e+308, 1.7976931348623157e+308}"));
            auto pair = bc.gb.object("UINibKeyValuePair");
            pair->set("UIObject", o);
            pair->set("UIValue", size);
            pair->set("UIKeyPath", bc.gb.string("estimatedItemSize"));
            sw.view_key_value_pairs.push_back(pair);
        }
        for (const auto& child : n.children) {
            if (child->name == "size" && child->attr_or("key") == "itemSize") {
                auto width = to_double(child->attr("width")).value_or(0),
                     height = to_double(child->attr("height")).value_or(0);
                if (width != 50 || height != 50) o->set("UIItemSize", encode_geometry({width, height}));
            }
            if (child->name == "size" && child->attr_or("key") == "headerReferenceSize") {
                auto width = to_double(child->attr("width")).value_or(0),
                     height = to_double(child->attr("height")).value_or(0);
                if (width || height) o->set("UIHeaderReferenceSize", encode_geometry({width, height}));
            }
            if (child->name == "inset" && child->attr_or("key") == "sectionInset") {
                auto left = to_double(child->attr("minX")).value_or(0),
                     top = to_double(child->attr("minY")).value_or(0),
                     right = to_double(child->attr("maxX")).value_or(0),
                     bottom = to_double(child->attr("maxY")).value_or(0);
                if (left || top || right || bottom)
                    o->set("UISectionInset", encode_geometry({top, left, bottom, right}));
            }
        }
    }
    if(n.name=="tableView"){
        if(n.attr_is_yes("alwaysBounceVertical"))o->set("UIAlwaysBounceVertical",true);
        if(n.attr_or("keyboardDismissMode")=="interactive")o->set("UIKeyboardDismissMode",std::int64_t(2));else if(n.attr_or("keyboardDismissMode")=="onDrag")o->set("UIKeyboardDismissMode",std::int64_t(1));
        o->set("UIBouncesZoom",true);
        auto float_property=[&](std::string key,std::string_view attribute,double fallback){o->set(std::move(key),nib::RawFloat{static_cast<float>(to_double(n.attr(attribute)).value_or(fallback))});};
        float_property("UIEstimatedRowHeight","estimatedRowHeight",0);
        float_property("UIEstimatedSectionFooterHeight","estimatedSectionFooterHeight",0);
        float_property("UIEstimatedSectionHeaderHeight","estimatedSectionHeaderHeight",0);
        float_property("UIRowHeight","rowHeight",-1);
        float_property("UISectionFooterHeight","sectionFooterHeight",0);
        float_property("UISectionHeaderHeight","sectionHeaderHeight",0);
        o->set("UIFillerRowHeight",0.0);
        o->set("UIInsetsContentViewsToSafeArea",true);
        o->set("UIPrefetchingEnabled",true);
        o->set("UIScrollViewContentInsetAdjustmentBehavior",std::int64_t(0));
        o->set("UIScrollViewIndicatorInsetAdjustmentBehavior",std::int64_t(1));
        o->set("UISectionHeaderTopPadding",-1.0);
        o->set("UISeparatorInsetReference",std::int64_t(0));
        auto separator=n.attr_or("separatorStyle","default");auto separator_value=separator=="none"?0:1;
        o->set("UISeparatorStyle",std::int64_t(separator_value));o->set("UISeparatorStyleIOS5AndLater",std::int64_t(separator_value));
        auto style=n.attr_or("style","plain");auto style_value=style=="grouped"?1:style=="insetGrouped"?2:0;
        o->set("UIStyle",std::int64_t(style_value==2?1:style_value));o->set("UITableViewStyle",std::int64_t(style_value));
        bool has_explicit_background=false;for(const auto& child:n.children)if(child->name=="color"&&child->attr_or("key")=="backgroundColor")has_explicit_background=true;
        if(style_value==2&&!has_explicit_background){xml::Node background;background.name="color";background.attributes={{"systemColor","systemGroupedBackgroundColor"}};o->set("UIBackgroundColor",make_color(bc.gb,background));}
    }
    if(n.name=="tableViewCell"||n.name=="collectionReusableView"){if(auto reuse=n.attr("reuseIdentifier"))o->set("UIReuseIdentifier",bc.gb.string(std::string(*reuse)));}
    if(n.name=="collectionViewCell"){if(auto reuse=n.attr("reuseIdentifier"))o->set("UIReuseIdentifier",bc.gb.string(std::string(*reuse)));o->set("UISystemBackgroundView",std::monostate{});o->set("UIContentConfigurationView",std::monostate{});}
    if(n.name=="view"&&n.attr_or("key")=="contentView"&&parent&&parent->class_name=="UIClassSwapper"){
        if (auto original = parent->get("UIOriginalClassName"))
            if (auto ref = std::get_if<GraphRef>(&*original))
                if (auto bytes = (*ref)->get("NS.bytes"))
                    if (auto raw = std::get_if<nib::RawBytes>(&*bytes)) {
                        std::string name(raw->data.begin(), raw->data.end());
                        if (name == "UICollectionViewCell") {
                            parent->set("UIContentView", o);
                            parent->set("UISubviews", bc.gb.mutable_array({o}));
                            o->set("UIOpaque", true);
                        }
                    }
    }
    if(n.name=="view"&&n.attr_or("key")=="contentView"&&parent&&parent->class_name=="UICollectionViewCell"){parent->set("UIContentView",o);parent->set("UISubviews",bc.gb.mutable_array({o}));o->set("UIOpaque",true);}
    if(n.name=="tableViewCellContentView"&&parent){parent->set("UIContentView",o);parent->set("UISubviews",bc.gb.mutable_array({o}));}
    if(n.name=="button"){o->set("UIAdjustsImageWhenHighlighted",true);o->set("UIAdjustsImageWhenDisabled",true);}
    if(n.name=="slider"){
        o->set("UIViewContentHuggingPriority",bc.gb.string("{250, 250}"));o->set("UIBehavioralStyle",std::int64_t(0));
        if(auto value=to_double(n.attr("value")))o->set("UIValue",nib::RawFloat{static_cast<float>(*value)});
    }
    if(n.name=="switch"){
        o->set("UISwitchEnabled",true);if(n.attr_is_yes("on"))o->set("UISwitchOn",true);
        if(n.attr_or("translatesAutoresizingMaskIntoConstraints")=="NO")if(const auto* rect=n.first_child("rect")){
            auto bounds="{{"+rect->attr_or("x","0")+", "+rect->attr_or("y","0")+"}, {"+rect->attr_or("width","0")+", "+rect->attr_or("height","0")+"}}";
            auto value=bc.gb.object("NSValue");value->set("NS.special",std::int64_t(3));value->set("NS.rectval",bc.gb.string(bounds));
            auto pair=bc.gb.object("UINibKeyValuePair");pair->set("UIObject",o);pair->set("UIValue",value);pair->set("UIKeyPath",bc.gb.string("frame"));sw.view_key_value_pairs.push_back(pair);
        }
    }
    if(n.name=="activityIndicatorView"){
        auto style=n.attr_or("style");auto value=style=="whiteLarge"||style=="large"?0:style=="white"||style=="medium"?1:2;
        o->set("UIActivityIndicatorViewStyle",std::int64_t(value));o->set("UIActivityIndicatorViewStyle-Modern",std::int64_t(style=="medium"?100:style=="large"?101:value));
        if(!n.attr_is_yes("hidesWhenStopped"))o->set("UIHidesWhenStopped",false);
        if(n.attr_is_yes("animating"))o->set("UIAnimating",true);
        if(n.attr_is_yes("hidden"))o->set("UIHidden",true);
        o->set("UIColor",std::monostate{});
    }
    if((n.name=="imageView"||n.name=="label") && n.attr("horizontalHuggingPriority") && n.attr("verticalHuggingPriority"))o->set("UIViewContentHuggingPriority",bc.gb.string("{"+n.attr_or("horizontalHuggingPriority")+", "+n.attr_or("verticalHuggingPriority")+"}"));
    if ((n.name == "imageView" || n.name == "label") &&
        (n.attr("horizontalCompressionResistancePriority") || n.attr("verticalCompressionResistancePriority")))
        o->set("UIViewContentCompressionResistancePriority",
               bc.gb.string("{" + n.attr_or("horizontalCompressionResistancePriority", "750") + ", " +
                            n.attr_or("verticalCompressionResistancePriority", "750") + "}"));
    if(n.name=="label"){
        if(auto lines=to_int(n.attr("numberOfLines")))o->set("UINumberOfLines",*lines);
        if(bc.legacy_styled_fonts&&n.attr_is_yes("adjustsFontForContentSizeCategory"))o->set("UIAdjustsFontForContentSizeCategory",true);
        if(auto scale=to_double(n.attr("minimumScaleFactor"))){o->set("UIAdjustsFontSizeToFit",true);o->set("UIMinimumScaleFactor",nib::RawFloat{static_cast<float>(*scale)});o->set("UIMinimumFontSize",nib::RawFloat{static_cast<float>(to_double(n.attr("minimumFontSize")).value_or(14))});}
    }
    if(n.name=="stackView"){
        o->set("UIStackViewAxis",std::int64_t(n.attr_or("axis")=="vertical"?1:0));
        auto distribution=n.attr_or("distribution");o->set("UIStackViewDistribution",std::int64_t(distribution=="fillEqually"?1:distribution=="fillProportionally"?2:distribution=="equalSpacing"?3:distribution=="equalCentering"?4:0));
        auto alignment=n.attr_or("alignment");o->set("UIStackViewAlignment",std::int64_t(alignment=="fill"||alignment.empty()?0:alignment=="leading"?1:alignment=="firstBaseline"?2:alignment=="center"?3:alignment=="trailing"?4:alignment=="lastBaseline"?5:0));
        o->set("UIStackViewSpacing",to_double(n.attr("spacing")).value_or(0));
        o->set("UIStackViewBaselineRelative",n.attr_is_yes("baselineRelativeArrangement"));
        o->set("UIStackViewLayoutMarginsRelative",n.attr_is_yes("layoutMarginsRelativeArrangement"));
        nib::RawBytes margins;margins.data.assign(33,0);margins.data[0]=7;o->set("UIViewLayoutMargins",std::move(margins));
    }
    if(n.name=="imageView" && !n.first_child("autoresizingMask"))o->set("UIAutoresizingMask",std::int64_t(36));
    if(n.name=="pageControl"){
        o->set("UIViewContentHuggingPriority",bc.gb.string("{250, 250}"));
        if(auto pages=to_int(n.attr("numberOfPages")))o->set("UINumberOfPages",*pages);
        if(auto curr=to_int(n.attr("currentPage")))o->set("UICurrentPage",*curr);
        if(n.attr_is_yes("hidesForSinglePage"))o->set("UIHidesForSinglePage",true);
        if(n.attr_is_yes("defersCurrentPageDisplay"))o->set("UIDefersCurrentPageDisplay",true);
    }
    if(n.name=="progressView"){
        o->set("UIViewContentHuggingPriority",bc.gb.string("{250, 250}"));
        if(auto p=to_double(n.attr("progress")))o->set("UIProgress",nib::RawFloat{static_cast<float>(*p)});
        auto style=n.attr_or("progressViewStyle","default");
        o->set("UIProgressViewStyle",std::int64_t(style=="bar"?1:0));
    }
    if(n.name=="refreshControl"){
        o->set("UIOpaque",false);
        o->set("UIHidden",true);
        if(parent)parent->set("UIRefreshControl",o);
    }
    if(n.name=="tabBar"){
        if(parent)parent->set("UITabBar",o);
        o->set("UIBarPosition",std::int64_t(1));
        o->set("UIBarTranslucence",std::int64_t(1));
        o->set("UIDeepDrawRect",true);
        o->set("UIViewSemanticContentAttribute",std::int64_t(0));
        o->set("UIViewLargeContentStoredProperties",std::monostate{});
        o->set("UIViewContentHuggingPriority",bc.gb.string("{250, 250}"));
        o->set("UIItems",bc.gb.array({}));
        if(n.attr_or("translucent")=="NO")o->set("UITranslucent",false);
    }
    if(n.name=="tabBarItem"){
        if(auto title=n.attr("title"))o->set("UITitle",bc.localizable_string(std::string(*title),id+".title"));
        if(auto image=n.attr("image"))o->set("UIImage",make_image_placeholder(bc.gb,std::string(*image)));
        if(auto sel=n.attr("selectedImage"))o->set("UISelectedImage",make_image_placeholder(bc.gb,std::string(*sel)));
        if(parent)parent->set("UITabBarItem",o);
    }
    if(n.name=="stepper"){
        o->set("UIViewContentHuggingPriority",bc.gb.string("{250, 250}"));
        if(auto val=to_double(n.attr("value")))o->set("UIValue",*val);
        if(auto step=to_double(n.attr("stepValue")))o->set("UIStepValue",*step);
        if(auto mn=to_double(n.attr("minimumValue")))o->set("UIMinimumValue",*mn);
        if(auto mx=to_double(n.attr("maximumValue")))o->set("UIMaximumValue",*mx);
    }
    if(n.name=="datePicker"||n.name=="pickerView"||n.name=="colorWell"){
        o->set("UIViewContentHuggingPriority",bc.gb.string("{250, 250}"));
    }
    parse_common_children(bc,sw,n,o,view_side);
    if(n.name=="label"&&n.attr("text")&&!o->get("UITextColor")){
        if(!sw.table_label_color){xml::Node color;color.name="color";color.attributes={{"systemColor","labelColor"}};sw.table_label_color=make_color(bc.gb,color);}
        o->set("UITextColor",sw.table_label_color);
    }
    if(n.name=="tableViewCellContentView"&&parent)if(const auto* variation=n.first_child("variation"))if(variation->attr_or("key")=="default")if(const auto* mask=variation->first_child("mask"))if(mask->attr_or("key")=="constraints"){
        SceneWork::RelationshipVariation relationship;relationship.top=parent;relationship.owner=o;relationship.descendants.push_back(o);
        if(const auto* subviews=n.first_child("subviews"))for(const auto& child:subviews->children)if(auto found=sw.objects.find(child->attr_or("id"));found!=sw.objects.end())relationship.descendants.insert(relationship.descendants.begin(),found->second);
        if(const auto* all=n.first_child("constraints"))for(const auto& child:all->children)if(auto found=sw.objects.find(child->attr_or("id"));found!=sw.objects.end())relationship.candidates.push_back(found->second);
        for(const auto& child:mask->children)if(child->name=="exclude")if(auto found=sw.objects.find(child->attr_or("reference"));found!=sw.objects.end())relationship.removed.push_back(found->second);
        sw.relationship_variations.push_back(std::move(relationship));
    }
    if((n.name=="textField"||n.name=="textView"))if(const auto* traits=n.first_child("textInputTraits")){
            auto capitalization = traits->attr_or("autocapitalizationType");
            if (capitalization == "none")
                o->set("UIAutocapitalizationType", std::int64_t(0));
            else if (capitalization == "words")
                o->set("UIAutocapitalizationType", std::int64_t(1));
            else if (capitalization == "allCharacters")
                o->set("UIAutocapitalizationType", std::int64_t(3));
            if (traits->attr_or("autocorrectionType") == "no") o->set("UIAutocorrectionType", std::int64_t(1));
            if (traits->attr_or("spellCheckingType") == "no") o->set("UISpellCheckingType", std::int64_t(1));
            if (traits->attr_or("returnKeyType") == "done") o->set("UIReturnKeyType", std::int64_t(9));
    }
    if(n.name=="textField"){
        o->set("UIContentHorizontalAlignment",std::int64_t(1));o->set("UITextAlignment",std::int64_t(0));
        if(auto placeholder=n.attr("placeholder"))o->set("UIPlaceholder",bc.localizable_string(std::string(*placeholder),id+".placeholder"));
        if(auto minimum=to_double(n.attr("minimumFontSize"))){o->set("UIAdjustsFontSizeToFit",true);o->set("UIMinimumFontSize",nib::RawFloat{static_cast<float>(*minimum)});}
        if(n.attr_or("clearButtonMode")=="whileEditing"){
            o->set("UIClearButtonMode", std::int64_t(1));
            nib::RawBytes offset;
            offset.data.push_back(7);
            for (double number : {3.0, 1.0}) {
                std::uint64_t bits;
                std::memcpy(&bits, &number, 8);
                for (int byte = 0; byte < 8; ++byte)
                    offset.data.push_back(static_cast<std::uint8_t>(bits >> (byte * 8)));
            }
            o->set("UIClearButtonOffset", std::move(offset));
        }
        if (!o->get("UITextColor")) {
            auto found = bc.color_cache.find("system:labelColor:");
            if (found == bc.color_cache.end()) {
                xml::Node color;
                color.name = "color";
                color.attributes = {{"systemColor", "labelColor"}};
                found = bc.color_cache.emplace("system:labelColor:", make_color(bc.gb, color)).first;
            }
            o->set("UITextColor", found->second);
        }
        o->set("UIDisableTextColorUpdateOnTraitCollectionChange",true);
        if(auto value=o->get("UIFont"))if(auto font=std::get_if<GraphRef>(&*value)){
            auto size_value=(*font)->get("UIFontPointSize");double size=size_value?std::get<double>(*size_value):17.0;auto number=bc.gb.object("NSNumber");number->set("NS.dblval",size);
            auto attrs =
                bc.gb.dictionary({{bc.gb.string("NSCTFontUIUsageAttribute"), bc.gb.string("CTFontRegularUsage")},
                                  {bc.gb.string("NSFontSizeAttribute"), number}});
            auto descriptor = bc.gb.object("UIFontDescriptor");
            descriptor->set("UIFontDescriptorAttributes", attrs);
            descriptor->set("UIFontDescriptorOptions", std::int64_t(2147517444));
            (*font)->set("UIFontDescriptor", descriptor);
            (*font)->set("UIFontTextStyleForScaling", std::monostate{});
            (*font)->set("UIFontPointSizeForScaling", 0.0);
            (*font)->set("UIFontMaximumPointSizeAfterScaling", 0.0);
            (*font)->set("UIFontTraits", std::int64_t(0));
        }
    }
    if(n.name=="textView"){
        o->set("UIScrollViewIndicatorInsetAdjustmentBehavior",std::int64_t(1));o->set("UIBouncesZoom",true);o->set("UIScrollViewContentInsetAdjustmentBehavior",std::int64_t(0));
        o->set("UITextAlignment",std::int64_t(n.attr_or("textAlignment")=="center"?1:n.attr_or("textAlignment")=="right"?2:0));
        if(n.attr_or("editable")=="NO")o->set("UIEditable",false);
        if(n.attr_is_yes("layoutMarginsFollowReadableWidth"))o->set("UIViewLayoutMarginsFollowReadableWidth",true);
        if(const auto* margins=n.first_child("edgeInsets"))if(margins->attr_or("key")=="layoutMargins"){
                nib::RawBytes bytes;
                bytes.data.push_back(7);
                for (const char* key : {"top", "left", "bottom", "right"}) {
                    double number = to_double(margins->attr(key)).value_or(0);
                    std::uint64_t bits;
                    std::memcpy(&bits, &number, 8);
                    for (int byte = 0; byte < 8; ++byte)
                        bytes.data.push_back(static_cast<std::uint8_t>(bits >> (byte * 8)));
                }
                o->set("UIViewLayoutMargins", std::move(bytes));
        }
        const auto* source=n.first_child("string");std::string content=source&&source->attr_or("key")=="text"?source->text:n.attr_or("text");
        if((source||n.attr("text"))&&n.attr_or("scrollEnabled")!="NO")if(const auto* frame=n.first_child("rect"))if(const auto* font=n.first_child("fontDescription")){
            auto width=to_double(frame->attr("width"));auto point_size=to_double(font->attr("pointSize"));
            auto name=font->attr_or("name");bool system_font=name.empty()&&font->attr_or("type","system")=="system";
            if(width&&point_size&&*width>10){
                if(auto height=measure_text_height(content,name,*point_size,*width-10,system_font)){
                    nib::RawBytes size;size.data.push_back(7);
                    for(double value:{*width,std::round(*height+16)}){std::uint64_t bits;std::memcpy(&bits,&value,8);for(int byte=0;byte<8;++byte)size.data.push_back(static_cast<std::uint8_t>(bits>>(byte*8)));}
                    o->set("UIContentSize",std::move(size));
                }else bc.diagnostics.warn("OPENIB-W1401","UITextView content size could not be measured with installed fonts and CoreText",bc.file,n.line);
            }
        }
        if(source||n.attr("text")){
            GraphRef attributed_text_string;
            if(source){o->set("UIText",bc.localizable_string(content,id+".text"));auto mutable_text=bc.gb.object("NSMutableString");nib::RawBytes bytes;bytes.data.assign(content.begin(),content.end());mutable_text->set("NS.bytes",std::move(bytes));attributed_text_string=mutable_text;}
            else if(auto existing=o->get("UIText"))if(auto text=std::get_if<GraphRef>(&*existing))attributed_text_string=*text;
            std::vector<std::pair<GraphRef,GraphRef>> attributes;
            if(auto color=o->get("UITextColor"))if(auto ref=std::get_if<GraphRef>(&*color))attributes.push_back({bc.gb.string("NSColor"),*ref});
            if(auto font_value=o->get("UIFont"))if(auto font=std::get_if<GraphRef>(&*font_value)){
                auto size_value=(*font)->get("UIFontPointSize");double size=size_value?std::get<double>(*size_value):17.0;
                auto number=bc.gb.object("NSNumber");number->set("NS.dblval",size);auto description=n.first_child("fontDescription");auto custom_name=description?description->attr("name"):std::nullopt;
                auto descriptor_attributes =
                    custom_name ? bc.gb.dictionary(
                                      {{bc.gb.string("NSFontNameAttribute"), bc.gb.string(std::string(*custom_name))},
                                       {bc.gb.string("NSFontSizeAttribute"), number}})
                                : bc.gb.dictionary(
                                      {{bc.gb.string("NSCTFontUIUsageAttribute"), bc.gb.string("CTFontRegularUsage")},
                                       {bc.gb.string("NSFontSizeAttribute"), number}});
                auto descriptor=bc.gb.object("UIFontDescriptor");descriptor->set("UIFontDescriptorAttributes",descriptor_attributes);descriptor->set("UIFontDescriptorOptions",std::int64_t(custom_name?2147483648:2147517444));
                (*font)->set("UIFontDescriptor",descriptor);(*font)->set("UIFontTextStyleForScaling",std::monostate{});(*font)->set("UIFontPointSizeForScaling",0.0);(*font)->set("UIFontMaximumPointSizeAfterScaling",0.0);(*font)->set("UIFontTraits",std::int64_t(0));
                attributes.push_back({bc.gb.string("NSFont"),*font});
            }
            auto paragraph=bc.gb.object("NSMutableParagraphStyle");paragraph->set("NSTabStops",std::monostate{});attributes.push_back({bc.gb.string("NSParagraphStyle"),paragraph});
            auto attributed=bc.gb.object("NSAttributedString");attributed->set("NSString",attributed_text_string);attributed->set("NSAttributes",bc.gb.dictionary(attributes));o->set("UIAttributedText",attributed);
        }
    }
    if(n.name=="label")if(auto value=o->get("UIFont"))if(auto font=std::get_if<GraphRef>(&*value);font&&!(*font)->get("UIIBTextStyle")){
        auto size_value=(*font)->get("UIFontPointSize");double size=size_value?std::get<double>(*size_value):17.0;
        auto description=n.first_child("fontDescription");auto type=description?description->attr_or("type","system"):"system";
        auto identity=std::make_pair(type,size);
        if(auto existing=sw.standard_table_fonts.find(identity);existing!=sw.standard_table_fonts.end())o->set("UIFont",existing->second);
        else if(!description||(!description->attr("style")&&type!="custom")){
            auto number=bc.gb.object("NSNumber");number->set("NS.dblval",size);
            auto attrs=bc.gb.dictionary({{bc.gb.string("NSCTFontUIUsageAttribute"),bc.gb.string(type=="boldSystem"?"CTFontEmphasizedUsage":"CTFontRegularUsage")},{bc.gb.string("NSFontSizeAttribute"),number}});
            auto descriptor=bc.gb.object("UIFontDescriptor");descriptor->set("UIFontDescriptorAttributes",attrs);descriptor->set("UIFontDescriptorOptions",std::int64_t(2147517444));
            (*font)->set("UIFontDescriptor", descriptor);
            (*font)->set("UIFontTextStyleForScaling", std::monostate{});
            (*font)->set("UIFontPointSizeForScaling", 0.0);
            (*font)->set("UIFontMaximumPointSizeAfterScaling", 0.0);
            (*font)->set("UIFontTraits", std::int64_t(0));
            sw.standard_table_fonts[identity] = *font;
        }
    }
    if (n.name == "switch")
        if (const auto* rect = n.first_child("rect"))
            if (auto width = to_double(rect->attr("width")); width && *width < 51) {
                xml::Node normalized;
                normalized.name = "rect";
                normalized.attributes = {{"key", "frame"},
                                         {"x", rect->attr_or("x", "0")},
                                         {"y", rect->attr_or("y", "0")},
                                         {"width", "51"},
                                         {"height", rect->attr_or("height", "31")}};
                add_rect(o, normalized);
            }
    if(n.name=="view"&&n.attr_or("key")=="contentView"&&parent)if(auto content=parent->get("UIContentView"))if(auto ref=std::get_if<GraphRef>(&*content))if(*ref==o){o->erase("UIAutoresizingMask");o->erase("UIClipsToBounds");o->erase("UIContentMode");o->erase("UIMultipleTouchEnabled");}
    if((n.name=="tableViewCell"||n.name=="tableViewCellContentView")&&n.first_child("autoresizingMask")&&autoresize_mask(*n.first_child("autoresizingMask"))==0)o->erase("UIAutoresizingMask");
    if(n.name=="collectionReusableView"&&n.first_child("autoresizingMask")&&autoresize_mask(*n.first_child("autoresizingMask"))==0)o->erase("UIAutoresizingMask");
    if(n.name=="tableViewCell"){
        if (auto background = o->get("UIBackgroundColor")) {
            o->set("UITableCellBackgroundColorSet", true);
            if (auto content = o->get("UIContentView"))
                if (auto view = std::get_if<GraphRef>(&*content))
                    if (auto inner_background = (*view)->get("UIBackgroundColor"))
                        if (auto shared = std::get_if<GraphRef>(&*inner_background))
                            o->set("UIBackgroundColor", *shared);
        }
        if(auto indentation=to_int(n.attr("indentationLevel"));indentation&&*indentation)o->set("UIIndentationLevel",*indentation);
        if(n.attr_or("accessoryType")=="disclosureIndicator")o->set("UIAccessoryType",std::int64_t(1));
        o->set("UIIndentationWidth",nib::RawFloat{static_cast<float>(to_double(n.attr("indentationWidth")).value_or(10))});
        o->set("UISystemBackgroundView",std::monostate{});o->set("UIContentConfigurationView",std::monostate{});
        o->set("UITextLabel",std::monostate{});o->set("UIDetailTextLabel",std::monostate{});o->set("UIImageView",std::monostate{});
        if(auto content=o->get("UIContentView"))if(auto ref=std::get_if<GraphRef>(&*content)){
                auto separator = bc.gb.object("_UITableViewCellSeparatorView");
                separator->set("UIDeepDrawRect", true);
                separator->set("UIOpaque", true);
                separator->set("UIAutoresizeSubviews", true);
                separator->set("UIViewSemanticContentAttribute", std::int64_t(0));
                separator->set("UIViewLargeContentStoredProperties", std::monostate{});
                if (auto rect = n.first_child("rect")) {
                    auto width = to_double(rect->attr("width")).value_or(0),
                         height = to_double(rect->attr("height")).value_or(0);
                    xml::Node frame;
                    frame.attributes = {{"key", "frame"},
                                        {"x", "8"},
                                        {"y", std::to_string(height - 1)},
                                        {"width", std::to_string(width - 8)},
                                        {"height", "1"}};
                    add_rect(separator, frame);
                }
            o->set("UISubviews",bc.gb.mutable_array({*ref,separator}));
        }
        if(parent&&parent->class_name=="UITableView"){
            auto selection=n.attr_or("selectionStyle");
            if(selection=="none"||selection=="gray"){
                auto system_color=[&](const char* name){xml::Node color;color.name="color";color.attributes={{"systemColor",name}};return make_color(bc.gb,color);};
                if(!sw.table_plain_background_color)sw.table_plain_background_color=system_color("tableCellPlainBackgroundColor");
                if(!sw.table_clear_color)sw.table_clear_color=system_color("clearColor");
                auto background=sw.table_plain_background_color,clear=sw.table_clear_color;
                o->set("UIBackgroundColor",background);o->set("UIDidEncodeCompatibilityBackgroundColor",true);o->set("UISelectionStyle",std::int64_t(selection=="gray"?2:0));
                auto configuration = bc.gb.object("UIBackgroundConfiguration");
                configuration->set("customView", std::monostate{});
                configuration->set("cornerRadius", 0.0);
                configuration->set("maskedCorners", std::int64_t(15));
                configuration->set("backgroundColor", background);
                configuration->set("backgroundColorTransformerIdentifier", std::int64_t(0));
                configuration->set("visualEffect", std::monostate{});
                configuration->set("visualEffectGroupName", std::monostate{});
                configuration->set("visualEffectAllowsTransparentBlurring", true);
                configuration->set("image", std::monostate{});
                configuration->set("imageContentMode", std::int64_t(0));
                configuration->set("backgroundInsets", bc.gb.string("{0, 0, 0, 0}"));
                configuration->set("edgesAddingLayoutMarginsToBackgroundInsets", std::int64_t(0));
                configuration->set("strokeColor", clear);
                configuration->set("strokeColorTransformerIdentifier", std::int64_t(0));
                configuration->set("strokeWidth", 0.0);
                configuration->set("strokeOutset", 0.0);
                configuration->set("strokeLocation", std::int64_t(0));
                configuration->set("shadowType", std::int64_t(0));
                configuration->set("defaultStyle", std::int64_t(1));
                for (const char* name :
                     {"customView", "cornerRadius", "backgroundInsets", "edgesAddingLayoutMarginsToBackgroundInsets",
                      "backgroundColor", "backgroundColorTransformerIdentifier", "visualEffect",
                      "visualEffectGroupName", "image", "imageContentMode", "strokeColor",
                      "strokeColorTransformerIdentifier", "strokeWidth", "strokeOutset", "maskedCorners"})
                    configuration->set(std::string("hasCustomized-") + name, false);
                auto system_view = bc.gb.object("_UISystemBackgroundView");
                system_view->set("UIDeepDrawRect", true);
                system_view->set("UIOpaque", true);
                system_view->set("UIAutoresizeSubviews", true);
                system_view->set("UIViewSemanticContentAttribute", std::int64_t(0));
                system_view->set("UIViewLargeContentStoredProperties", std::monostate{});
                system_view->set("configurationAPI", configuration);
                if (const auto* rect = n.first_child("rect")) {
                    xml::Node local;
                    local.name = "rect";
                    local.attributes = {
                        {"key", "frame"},
                        {"x", "0"},
                        {"y", "0"},
                        {"width", rect->attr_or("width")},
                        {"height", std::to_string(std::ceil(to_double(rect->attr("height")).value_or(0)))}};
                    add_rect(system_view, local);
                }
                o->set("UISystemBackgroundView", system_view);
                if (const auto* content = n.first_child("tableViewCellContentView"))
                    for (const auto& child : content->children)
                        if (child->name == "color" && child->attr_or("key") == "backgroundColor" &&
                            to_double(child->attr("white")).value_or(1) == 0 &&
                            to_double(child->attr("alpha")).value_or(1) == 0)
                            if (auto found = sw.objects.find(content->attr_or("id")); found != sw.objects.end())
                                found->second->set("UIBackgroundColor", clear);
            }
            auto style = n.attr_or("style");
            if (style == "IBUITableViewCellStyleValue1")
                o->set("UITableViewCellStyle", std::int64_t(1));
            else if (style == "IBUITableViewCellStyleValue2")
                o->set("UITableViewCellStyle", std::int64_t(2));
            else if (style == "IBUITableViewCellStyleSubtitle")
                o->set("UITableViewCellStyle", std::int64_t(3));
            if(const auto* content=n.first_child("tableViewCellContentView"))if(const auto* subviews=content->first_child("subviews"))for(const auto& child:subviews->children){
                if(child->name!="label")continue;auto label_it=sw.objects.find(child->attr_or("id"));if(label_it==sw.objects.end())continue;auto label=label_it->second;auto id=child->attr_or("id");
                if(n.attr_or("textLabel")==id)o->set("UITextLabel",label);else if(n.attr_or("detailTextLabel")==id)o->set("UIDetailTextLabel",label);else continue;
                label->class_name="UITableViewLabel";if(auto mask=label->get("UIAutoresizingMask"))if(auto value=std::get_if<std::int64_t>(&*mask))if(*value==0)label->erase("UIAutoresizingMask");
                if(auto text=child->attr("text"))label->set("UIText",text->empty()?bc.gb.string(""):bc.localizable_string(std::string(*text),id+".text"));
                bool nil_text=false;for(const auto& detail:child->children)if(detail->name=="nil"&&detail->attr_or("key")=="textColor")nil_text=true;
                label->set("UIDisableUpdateTextColorOnTraitCollectionChange",!nil_text);
                auto alignment=child->attr_or("textAlignment","natural");label->set("UITextAlignment",std::int64_t(alignment=="right"?2:alignment=="center"?1:alignment=="left"?0:4));
                nib::RawBytes offset;offset.data.assign(17,0);offset.data[0]=7;offset.data[15]=0xf0;offset.data[16]=0xbf;label->set("UIShadowOffset",std::move(offset));
                if(!label->get("UITextColor")){if(!sw.table_label_color){xml::Node color;color.name="color";color.attributes={{"systemColor","labelColor"}};sw.table_label_color=make_color(bc.gb,color);}label->set("UITextColor",sw.table_label_color);}
                if(auto font_value=label->get("UIFont"))if(auto font_ref=std::get_if<GraphRef>(&*font_value)){
                        auto font = *font_ref;
                        auto size_value = font->get("UIFontPointSize");
                        double size = size_value ? std::get<double>(*size_value) : 17.0;
                        auto font_type = child->first_child("fontDescription")
                                             ? child->first_child("fontDescription")->attr_or("type", "system")
                                             : "system";
                        auto identity = std::make_pair(font_type, size);
                        if (auto existing = sw.standard_table_fonts.find(identity);
                            existing != sw.standard_table_fonts.end())
                            label->set("UIFont", existing->second);
                        else {
                            auto number = bc.gb.object("NSNumber");
                            number->set("NS.dblval", size);
                            auto attrs =
                                bc.gb.dictionary({{bc.gb.string("NSCTFontUIUsageAttribute"),
                                                   bc.gb.string(font_type == "boldSystem" ? "CTFontEmphasizedUsage"
                                                                                          : "CTFontRegularUsage")},
                                                  {bc.gb.string("NSFontSizeAttribute"), number}});
                            auto descriptor = bc.gb.object("UIFontDescriptor");
                            descriptor->set("UIFontDescriptorAttributes", attrs);
                            descriptor->set("UIFontDescriptorOptions", std::int64_t(2147517444));
                            font->set("UIFontDescriptor", descriptor);
                            font->set("UIFontTextStyleForScaling", std::monostate{});
                            font->set("UIFontPointSizeForScaling", 0.0);
                            font->set("UIFontMaximumPointSizeAfterScaling", 0.0);
                            font->set("UIFontTraits", std::int64_t(0));
                            sw.standard_table_fonts[identity] = font;
                        }
                }
            }
        }
    }
    if(n.name=="tableView")if(auto color=o->get("UIBackgroundColor"))if(auto ref=std::get_if<GraphRef>(&*color))for(const auto& child:n.children)if(child->name=="color"&&child->attr_or("key")=="backgroundColor"){
        if(child->attr("white"))(*ref)->set("UISystemColorName",bc.gb.string("tableBackgroundColor"));
        else if(n.attr_or("style")=="grouped"){
            auto red=to_double(child->attr("red")),green=to_double(child->attr("green")),blue=to_double(child->attr("blue"));
            if(red&&green&&blue&&std::abs(*red-0.9490196078431372)<0.00001&&std::abs(*green-0.9490196078431372)<0.00001&&std::abs(*blue-0.9686274509803922)<0.00001)(*ref)->set("UISystemColorName",bc.gb.string(bc.modern_system_colors?"systemGroupedBackgroundColor":"groupTableViewBackgroundColor"));
        }
    }
    if(n.name=="navigationBar"){
        o->set("UIAutoresizingMask",std::int64_t(2));
        auto source_frame=n.first_child("rect");auto frame_y=source_frame?source_frame->attr_or("y","0"):"0";xml::Node frame;frame.attributes={{"key","frame"},{"x","0"},{"y",frame_y},{"width","0"},{"height","50"}};add_rect(o,frame);
    }
    if(n.name=="toolbar"){
        o->set("UIAutoresizingMask",std::int64_t(10));auto source_frame=n.first_child("rect");auto frame_y=source_frame?source_frame->attr_or("y","0"):"0";xml::Node frame;frame.attributes={{"key","frame"},{"x","0"},{"y",frame_y},{"width","0"},{"height","50"}};add_rect(o,frame);
    }
    if(view_side&&!n.first_child("autoresizingMask")&&n.name!="viewLayoutGuide"&&n.name!="collectionViewFlowLayout"&&!(n.name=="view"&&n.attr_or("key")=="contentView"&&parent&&parent->get("UIContentView")))o->set("UIAutoresizingMask",std::int64_t(36));
    return o;
}

GraphRef connection_object(nib::GraphBuilder& gb, const PendingConnection& pc, GraphRef source, GraphRef dest) {
    auto cls = pc.kind == "action"              ? "UIRuntimeEventConnection"
               : pc.kind == "outlet_collection" ? "UIRuntimeOutletCollectionConnection"
                                                : "UIRuntimeOutletConnection";
    auto c = gb.object(cls);
    c->set("UILabel", gb.string(pc.label));
    c->set("UISource", source);
    c->set("UIDestination", pc.kind == "outlet_collection" ? gb.mutable_array({dest}) : dest);
    if (pc.kind == "outlet_collection") {
        c->set("runtimeCollectionClassName", gb.string("NSArray"));
        if (pc.xml_node && pc.xml_node->attr_is_yes("appends")) c->set("addsContentToExistingCollection", true);
    }
    if (pc.kind == "action" && source->class_name != "UIBarButtonItem" &&
        source->class_name != "UITapGestureRecognizer")
        c->set("UIEventMask", pc.event_mask);
    return c;
}
bool is_table_cell(const GraphRef& object){
    if(object->class_name=="UITableViewCell")return true;
    if(object->class_name!="UIClassSwapper")return false;
    if(auto original=object->get("UIOriginalClassName"))if(auto ref=std::get_if<GraphRef>(&*original))if(auto bytes=(*ref)->get("NS.bytes"))if(auto raw=std::get_if<nib::RawBytes>(&*bytes))return std::string(raw->data.begin(),raw->data.end())=="UITableViewCell";
    return false;
}

std::vector<GraphRef> unique_refs(const std::vector<GraphRef>& in){
    std::vector<GraphRef> out; std::unordered_set<std::uint64_t> seen;
    for(const auto& x:in) if(x && seen.insert(x->serial).second) out.push_back(x);
    return out;
}

GraphRef nib_root(nib::GraphBuilder& gb, const std::vector<GraphRef>& top, const std::vector<GraphRef>& cons,
                  const std::vector<GraphRef>& objects, bool live_nib = false,
                  const std::vector<GraphRef>& key_value_pairs = {},
                  const std::vector<GraphRef>& trait_storage_lists = {}) {
    auto r = gb.object("NSObject");
    auto empty = gb.array({});
    r->set("UINibTopLevelObjectsKey", gb.array(unique_refs(top)));
    r->set("UINibObjectsKey", gb.array(unique_refs(objects)));
    r->set("UINibConnectionsKey", gb.array(unique_refs(cons)));
    r->set("UINibVisibleWindowsKey", empty);
    r->set("UINibAccessibilityConfigurationsKey", empty);
    r->set("UINibTraitStorageListsKey", trait_storage_lists.empty() ? empty : gb.array(trait_storage_lists));
    r->set("UINibKeyValuePairsKey", gb.array(key_value_pairs));
    if (live_nib) r->set("IBUINibLNEVersionKey", std::int64_t(1));
    return r;
}

std::vector<GraphRef> make_relationship_trait_lists(nib::GraphBuilder& gb,const SceneWork& sw){
    std::vector<GraphRef> lists;
    auto object_set=[&](std::string class_name,const std::vector<GraphRef>& objects){auto set=gb.object(std::move(class_name));for(std::size_t i=0;i<objects.size();++i)set->set("NS.object."+std::to_string(i),objects[i]);return set;};
    for(const auto& variation:sw.relationship_variations){
        auto record=gb.object("_UIRelationshipTraitStorageRecord");record->set("UITraitCollection",gb.object("UITraitCollection"));record->set("UIAddedObjects",object_set("NSSet",{}));record->set("UIRemovedObjects",object_set("NSSet",variation.removed));
        auto storage = gb.object("_UIRelationshipTraitStorage");
        storage->set("UIObject", variation.owner);
        storage->set("UIKeyPath", gb.string("traitStorageConstraints"));
        storage->set("UIRecords", gb.mutable_array({record}));
        storage->set("UIRelationshipCandidates", object_set("NSOrderedSet", variation.candidates));
        auto list=gb.object("_UITraitStorageList");list->set("UITopLevelObject",variation.top);list->set("UITraitStorages",gb.array({storage}));list->set("UIDescendants",object_set("NSSet",variation.descendants));lists.push_back(list);
    }
    return lists;
}

GraphRef make_prototype_nib(BuilderContext& parent_context,const xml::Node& cell_node){
    BuilderContext nested(parent_context.diagnostics,parent_context.file);SceneWork work;
    nested.named_colors=parent_context.named_colors;
    nested.legacy_styled_fonts=parent_context.legacy_styled_fonts;
    nested.modern_system_colors=parent_context.modern_system_colors;
    auto cell=parse_element(nested,work,cell_node,nullptr,true);
    auto owner=nested.gb.proxy("IBFilesOwner"),responder=nested.gb.proxy("IBFirstResponder");
    std::vector<GraphRef> objects={owner,responder,cell};
    std::vector<GraphRef> connections;
    std::unordered_map<std::string,GraphRef> external_proxies;
    if(cell_node.name=="tableViewCell"){
        if(const auto* cell_connections=cell_node.first_child("connections"))for(const auto& connection:cell_connections->children)if(connection->name=="segue"){
            auto proxy=nested.gb.proxy("UpstreamPlaceholder-1");objects.push_back(proxy);
            external_proxies.emplace("<selection-segue>",proxy);
            auto outlet=nested.gb.object("UIRuntimeOutletConnection");outlet->set("UILabel",nested.gb.string("selectionSegueTemplate"));outlet->set("UISource",cell);outlet->set("UIDestination",proxy);connections.push_back(outlet);
        }
        std::map<std::pair<std::string,double>,GraphRef> standard_fonts;
        GraphRef default_label_color;
        auto selection=cell_node.attr_or("selectionStyle");
        if(selection=="none"||selection=="gray"){
            auto system_color=[&](const char* name){xml::Node color;color.name="color";color.attributes={{"systemColor",name}};return make_color(nested.gb,color);};
            auto background=system_color("tableCellPlainBackgroundColor");
            cell->set("UIBackgroundColor",background);cell->set("UIDidEncodeCompatibilityBackgroundColor",true);cell->set("UISelectionStyle",std::int64_t(selection=="gray"?2:0));
            auto configuration=nested.gb.object("UIBackgroundConfiguration");
            configuration->set("customView",std::monostate{});configuration->set("cornerRadius",0.0);configuration->set("maskedCorners",std::int64_t(15));configuration->set("backgroundColor",background);
            configuration->set("backgroundColorTransformerIdentifier",std::int64_t(0));configuration->set("visualEffect",std::monostate{});configuration->set("visualEffectGroupName",std::monostate{});configuration->set("visualEffectAllowsTransparentBlurring",true);
            configuration->set("image",std::monostate{});configuration->set("imageContentMode",std::int64_t(0));configuration->set("backgroundInsets",nested.gb.string("{0, 0, 0, 0}"));configuration->set("edgesAddingLayoutMarginsToBackgroundInsets",std::int64_t(0));
            auto clear_color = system_color("clearColor");
            configuration->set("strokeColor", clear_color);
            configuration->set("strokeColorTransformerIdentifier", std::int64_t(0));
            configuration->set("strokeWidth", 0.0);
            configuration->set("strokeOutset", 0.0);
            configuration->set("strokeLocation", std::int64_t(0));
            configuration->set("shadowType", std::int64_t(0));
            configuration->set("defaultStyle", std::int64_t(1));
            if (const auto* content = cell_node.first_child("tableViewCellContentView"))
                for (const auto& child : content->children)
                    if (child->name == "color" && child->attr_or("key") == "backgroundColor" &&
                        to_double(child->attr("white")).value_or(1) == 0 &&
                        to_double(child->attr("alpha")).value_or(1) == 0)
                        if (auto found = work.objects.find(content->attr_or("id")); found != work.objects.end())
                            found->second->set("UIBackgroundColor", clear_color);
            for (const char* name :
                 {"customView", "cornerRadius", "backgroundInsets", "edgesAddingLayoutMarginsToBackgroundInsets",
                  "backgroundColor", "backgroundColorTransformerIdentifier", "visualEffect", "visualEffectGroupName",
                  "image", "imageContentMode", "strokeColor", "strokeColorTransformerIdentifier", "strokeWidth",
                  "strokeOutset", "maskedCorners"})
                configuration->set(std::string("hasCustomized-") + name, false);
            auto system_view = nested.gb.object("_UISystemBackgroundView");
            system_view->set("UIDeepDrawRect", true);
            system_view->set("UIOpaque", true);
            system_view->set("UIAutoresizeSubviews", true);
            system_view->set("UIViewSemanticContentAttribute", std::int64_t(0));
            system_view->set("UIViewLargeContentStoredProperties", std::monostate{});
            system_view->set("configurationAPI", configuration);
            if(const auto* rect=cell_node.first_child("rect")){xml::Node local;local.name="rect";local.attributes={{"key","frame"},{"x","0"},{"y","0"},{"width",rect->attr_or("width")},{"height",std::to_string(std::ceil(to_double(rect->attr("height")).value_or(0)))}};add_rect(system_view,local);}
            cell->set("UISystemBackgroundView",system_view);
        }
        if(cell_node.attr_or("accessoryType")=="disclosureIndicator")cell->set("UIAccessoryType",std::int64_t(1));
        auto style=cell_node.attr_or("style");
        if(style=="IBUITableViewCellStyleValue1")cell->set("UITableViewCellStyle",std::int64_t(1));
        else if(style=="IBUITableViewCellStyleValue2")cell->set("UITableViewCellStyle",std::int64_t(2));
        else if(style=="IBUITableViewCellStyleSubtitle")cell->set("UITableViewCellStyle",std::int64_t(3));
        if(const auto* content=cell_node.first_child("tableViewCellContentView")){
            if(auto found=work.objects.find(content->attr_or("id"));found!=work.objects.end())objects.push_back(found->second);
            if(const auto* subviews=content->first_child("subviews"))for(const auto& label_node:subviews->children){
                if(label_node->name!="label")continue;
                auto id=label_node->attr_or("id");auto found=work.objects.find(id);if(found==work.objects.end())continue;
                auto label=found->second;
                bool standard=false;
                if(cell_node.attr_or("textLabel")==id){cell->set("UITextLabel",label);objects.push_back(label);standard=true;}
                else if(cell_node.attr_or("detailTextLabel")==id){cell->set("UIDetailTextLabel",label);objects.push_back(label);standard=true;}
                if(!standard)continue;
                label->class_name="UITableViewLabel";
                if(auto mask=label->get("UIAutoresizingMask"))if(auto value=std::get_if<std::int64_t>(&*mask))if(*value==0)label->erase("UIAutoresizingMask");
                if(auto text=label_node->attr("text"))label->set("UIText",text->empty()?nested.gb.string(""):nested.localizable_string(std::string(*text),id+".text"));
                bool explicit_nil_text_color=false;for(const auto& child:label_node->children)if(child->name=="nil"&&child->attr_or("key")=="textColor")explicit_nil_text_color=true;
                label->set("UIDisableUpdateTextColorOnTraitCollectionChange",!explicit_nil_text_color);
                auto alignment=label_node->attr_or("textAlignment","natural");label->set("UITextAlignment",std::int64_t(alignment=="right"?2:alignment=="center"?1:alignment=="left"?0:4));
                nib::RawBytes offset;offset.data.assign(17,0);offset.data[0]=7;offset.data[16]=0xbf;offset.data[15]=0xf0;label->set("UIShadowOffset",std::move(offset));
                if(!label->get("UITextColor")){if(!default_label_color){xml::Node color;color.name="color";color.attributes={{"systemColor","labelColor"}};default_label_color=make_color(nested.gb,color);}label->set("UITextColor",default_label_color);}
                if(auto font_value=label->get("UIFont"))if(auto font_ref=std::get_if<GraphRef>(&*font_value)){
                    auto font=*font_ref;auto size_value=font->get("UIFontPointSize");double size=size_value?std::get<double>(*size_value):17.0;
                    auto font_name=label_node->first_child("fontDescription")?label_node->first_child("fontDescription")->attr_or("type","system"):"system";
                    auto identity=std::make_pair(font_name,size);
                    if(auto existing=standard_fonts.find(identity);existing!=standard_fonts.end()){label->set("UIFont",existing->second);}
                    else{
                        auto number=nested.gb.object("NSNumber");number->set("NS.dblval",size);
                        auto attrs=nested.gb.dictionary({{nested.gb.string("NSCTFontUIUsageAttribute"),nested.gb.string(font_name=="boldSystem"?"CTFontEmphasizedUsage":"CTFontRegularUsage")},{nested.gb.string("NSFontSizeAttribute"),number}});
                        auto descriptor=nested.gb.object("UIFontDescriptor");descriptor->set("UIFontDescriptorAttributes",attrs);descriptor->set("UIFontDescriptorOptions",std::int64_t(2147517444));
                        font->set("UIFontDescriptor",descriptor);font->set("UIFontTextStyleForScaling",std::monostate{});font->set("UIFontPointSizeForScaling",0.0);font->set("UIFontMaximumPointSizeAfterScaling",0.0);font->set("UIFontTraits",std::int64_t(0));
                        standard_fonts[identity]=font;
                    }
                }
            }
        }
        for(const auto& extra:work.view_extras)if(std::find(objects.begin(),objects.end(),extra)==objects.end())objects.push_back(extra);
    }
    for(auto& reference:work.references)if(auto found=work.objects.find(reference.target_id);found!=work.objects.end())reference.owner->set(reference.key,found->second);
    for (const auto& pending : work.connections) {
        GraphRef destination;
        auto found = work.objects.find(pending.destination_id);
        if (found != work.objects.end())
            destination = found->second;
        else {
            auto proxy = external_proxies.find(pending.destination_id);
            if (proxy == external_proxies.end()) {
                auto id = "UpstreamPlaceholder-" + std::to_string(external_proxies.size() + 1);
                proxy = external_proxies.emplace(pending.destination_id, nested.gb.proxy(id)).first;
                objects.push_back(proxy->second);
            }
            destination = proxy->second;
        }
        connections.push_back(connection_object(nested.gb, pending, pending.source, destination));
    }
    std::vector<GraphRef> top={owner,responder,cell};
    if(!connections.empty())for(const auto& object:objects)if(object->class_name=="UIProxyObject"&&object!=owner&&object!=responder)top.push_back(object);
    auto root=nib_root(nested.gb,top,connections,objects,false,work.view_key_value_pairs);
    auto archive=nib::Writer().write_bytes(nested.gb.flatten({root}));
    auto data=parent_context.gb.object("NSData");nib::RawBytes bytes;bytes.data=std::move(archive);data->set("NS.bytes",std::move(bytes));
    auto result=parent_context.gb.object("UINib");result->set("captureEnclosingNIBBundleOnDecode",true);result->set("archiveData",data);return result;
}

GraphRef synthetic_constraint(nib::GraphBuilder& gb, const GraphRef& first, std::int64_t first_attr,
                              const GraphRef& second = {}, std::int64_t second_attr = 0) {
    auto c = gb.object("NSLayoutConstraint");
    c->set("NSFirstItem", first);
    c->set("NSFirstAttributeV2", first_attr);
    c->set("NSFirstAttribute", first_attr);
    if (second) {
        c->set("NSSecondItem", second);
        c->set("NSSecondAttributeV2", second_attr);
        c->set("NSSecondAttribute", second_attr);
    }
    c->set("NSShouldBeArchived", true);
    return c;
}

void add_layout_guide_constraints(nib::GraphBuilder& gb,SceneWork& sw){
    if(!sw.root_view)return;
    std::vector<GraphRef> root_constraints;
    if(auto current=sw.root_view->get("UIViewAutolayoutConstraints")){if(auto array=std::get_if<GraphRef>(&*current)){for(const auto& [key,value]:(*array)->properties)if(key=="UINibEncoderEmptyKey")if(auto item=std::get_if<GraphRef>(&value))root_constraints.push_back(*item);}}
    std::vector<GraphRef> synthesized;
    for(const auto& [guide,type]:sw.typed_layout_guides){
        auto support = gb.object("_UILayoutSupportConstraint");
        support->set("NSFirstItem", guide);
        support->set("NSFirstAttributeV2", std::int64_t(7));
        support->set("NSFirstAttribute", std::int64_t(7));
        support->set("NSShouldBeArchived", true);
        support->set("NSPriority", std::int64_t(999));
        guide->set("UIViewAutolayoutConstraints", gb.mutable_array({support}));
        auto leading=synthetic_constraint(gb,guide,5,sw.root_view,5);
        GraphRef vertical=type=="top"?synthetic_constraint(gb,guide,3,sw.root_view,3):synthetic_constraint(gb,sw.root_view,4,guide,4);
        auto height=synthetic_constraint(gb,guide,8);
        guide->set("_UILayoutGuideConstraintsToRemove",gb.array({leading,vertical,height}));
        synthesized.insert(synthesized.end(),{leading,vertical,height});
    }
    // Xcode places its six synthetic guide constraints before XML constraints.
    synthesized.insert(synthesized.end(),root_constraints.begin(),root_constraints.end());
    if(!synthesized.empty())sw.root_view->set("UIViewAutolayoutConstraints",gb.mutable_array(synthesized));
}

struct ExternalStoryboardReference { std::string storyboard_name; std::string controller_identifier; };

void write_plist(const std::filesystem::path& path, const std::map<std::string, std::string>& idmap,
                 const std::map<std::string, ExternalStoryboardReference>& external_refs, const std::string& initial) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw OpenIBError("Unable to write storyboard Info.plist");
    f << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n";
    if (!initial.empty())
        f << "  <key>UIStoryboardDesignatedEntryPointIdentifier</key>\n  <string>" << xml::escape(initial)
          << "</string>\n";
    f << "  <key>UIStoryboardVersion</key>\n  <integer>1</integer>\n";
    if (!external_refs.empty()) {
        f << "  <key>UIViewControllerIdentifiersToExternalStoryboardReferences</key>\n  <dict>\n";
        for (const auto& [identifier, reference] : external_refs) {
            f << "    <key>" << xml::escape(identifier)
              << "</key>\n    <dict>\n      <key>UIReferencedStoryboardName</key>\n      <string>"
              << xml::escape(reference.storyboard_name) << "</string>\n";
            if (!reference.controller_identifier.empty())
                f << "      <key>UIReferencedControllerIdentifier</key>\n      <string>"
                  << xml::escape(reference.controller_identifier) << "</string>\n";
            f << "    </dict>\n";
        }
        f << "  </dict>\n";
    }
    f << "  <key>UIViewControllerIdentifiersToNibNames</key>\n  <dict>\n";
    for (auto& [k, v] : idmap)
        f << "    <key>" << xml::escape(k) << "</key>\n    <string>" << xml::escape(v) << "</string>\n";
    f << "  </dict>\n</dict>\n</plist>\n";
}

std::string make_upstream_id(std::size_t n){return "UpstreamPlaceholder-"+std::to_string(n);}

CompileResult compile_storyboard(const IBDocument& doc,const std::filesystem::path& out,const CompileOptions& options,Diagnostics& diagnostics){
    BuilderContext bc(diagnostics,doc.xml_document.source_path);
    if(const auto* root=doc.xml_document.root.get())if(const auto* resources=root->first_child("resources"))for(const auto& resource:resources->children)if(resource->name=="namedColor")if(const auto* color=resource->first_child("color"))bc.named_colors[resource->attr_or("name")]=color;
    auto canvas_size=storyboard_canvas_size(doc);
    bool emit_live_nib_version=false,legacy_controller_swapper=false;try{auto tools=std::stod(doc.tools_version);emit_live_nib_version=tools>=30000.0;legacy_controller_swapper=tools<16000.0;bc.legacy_styled_fonts=tools<16000.0;bc.modern_system_colors=tools>=30000.0;}catch(...){}
    for (const auto& scene : doc.scenes) {
        if (!scene.controller_node) continue;
        auto sw = std::make_unique<SceneWork>();
        sw->scene = &scene;
        sw->controller_id = scene.controller_node->attr_or("id");
        sw->controller_base_class = base_class_for_tag(scene.controller_node->name);
        bool archives_view_controllers = false, has_local_relationship_child = false;
        for (const auto& child : scene.controller_node->children)
            if (child->name == "nil" && child->attr_or("name") == "viewControllers") archives_view_controllers = true;
        if (auto connections = scene.controller_node->first_child("connections")) {
            for (const auto& candidate : connections->children) {
                if (candidate->name != "segue" || candidate->attr_or("kind") != "relationship") continue;
                auto destination = candidate->attr_or("destination");
                for (const auto& target : doc.scenes)
                    if (target.controller_node && target.controller_node->attr_or("id") == destination &&
                        target.controller_node->name != "viewControllerPlaceholder")
                        has_local_relationship_child = true;
            }
        }
        if (scene.controller_node->name == "viewControllerPlaceholder") {
            sw->is_external_storyboard_reference=true;
            sw->external_storyboard_name=scene.controller_node->attr_or("storyboardName");
            sw->external_controller_identifier=scene.controller_node->attr_or("referencedIdentifier");
            sw->controller=bc.gb.object("UIStoryboardViewControllerPlaceholder");
        } else {
            bool prefers_large_titles=false;for(const auto& child:scene.controller_node->children)if(child->name=="navigationBar"&&child->attr_is_yes("largeTitles"))prefers_large_titles=true;
            if (!scene.controller_node->attr("customClass") && !scene.controller_node->attr("storyboardIdentifier") &&
                sw->controller_base_class != "UIViewController" && !legacy_controller_swapper &&
                !(archives_view_controllers && has_local_relationship_child && prefers_large_titles))
                sw->controller = bc.gb.object(sw->controller_base_class);
            else sw->controller=controller_class_swapped(bc.gb,*scene.controller_node,sw->controller_base_class);
            if(scene.controller_node->name=="pageViewController"){
                sw->controller->set("UITransitionStyle",std::int64_t(scene.controller_node->attr_or("transitionStyle")=="scroll"?1:0));
                sw->controller->set("UINavigationOrientation",std::int64_t(scene.controller_node->attr_or("navigationOrientation")=="vertical"?1:0));
                sw->controller->set("UISpineLocation",std::int64_t(0));
                sw->controller->set("UIPageSpacing",std::int64_t(to_int(scene.controller_node->attr("pageSpacing")).value_or(0)));
                sw->controller->set("UIAutoresizesArchivedViewToFullSize",false);
            }
        }
        sw->scene_extras.push_back(sw->controller);if(!sw->controller_id.empty()){sw->objects[sw->controller_id]=sw->controller;sw->view_side[sw->controller_id]=false;bc.global_objects[sw->controller_id]=sw->controller;bc.global_owner[sw->controller_id]=sw.get();}
        if(auto title=scene.controller_node->attr("title"))sw->controller->set("UITitle",bc.localizable_string(std::string(*title),sw->controller_id+".title"));
        for(const auto& child:scene.controller_node->children)if(child->name=="value"&&child->attr_or("key")=="contentSizeForViewInPopover"&&child->attr_or("type")=="size"){
                nib::RawBytes size;
                size.data.push_back(0x07);
                for (auto dimension :
                     {to_double(child->attr("width")).value_or(0), to_double(child->attr("height")).value_or(0)}) {
                    std::uint64_t bits;
                    std::memcpy(&bits, &dimension, 8);
                    for (int byte = 0; byte < 8; ++byte)
                        size.data.push_back(static_cast<std::uint8_t>(bits >> (byte * 8)));
                }
                sw->controller->set("UIPreferredContentSize", std::move(size));
        }
        if(scene.controller_node->attr_or("clearsSelectionOnViewWillAppear")=="NO")sw->controller->set("UIClearsSelectionOnViewWillAppear",false);
        if(scene.controller_node->attr_or("automaticallyAdjustsScrollViewInsets")=="NO")sw->controller->set("UIKeyAutomaticallyAdjustsScrollViewInsets",std::int64_t(0));
        if (auto style = scene.controller_node->attr("modalPresentationStyle")) {
            static const std::unordered_map<std::string, std::int64_t> styles = {
                {"fullScreen", 0}, {"pageSheet", 1},      {"formSheet", 2},          {"currentContext", 3},
                {"custom", 4},     {"overFullScreen", 5}, {"overCurrentContext", 6}, {"popover", 7}};
            auto found = styles.find(std::string(*style));
            if (found != styles.end()) sw->controller->set("UIModalPresentationStyle", found->second);
        }
        if(auto sid=scene.controller_node->attr("storyboardIdentifier"))sw->controller->set("UIStoryboardIdentifier",bc.gb.string(std::string(*sid)));
        // Register other scene-level placeholders/exits so segue and outlet destinations can resolve.
        for(const auto& top:scene.objects_node->children){if(top.get()==scene.controller_node)continue;if(top->name=="placeholder"||top->name=="exit"||!base_class_for_tag(top->name).empty()) (void)parse_element(bc,*sw,*top,nullptr,false);}
        for (const auto& cp : scene.controller_node->children) {
            const auto& c = *cp;
            if (c.name == "layoutGuides") {
                for (const auto& gp : c.children) {
                    auto g = parse_element(bc, *sw, *gp, sw->controller, true);
                    if (g) sw->layout_guides.push_back(g);
                }
            } else if (c.name == "connections")
                parse_connections(bc, *sw, c, sw->controller);
            else if (c.name == "navigationItem" || c.name == "navigationBar" || c.name == "toolbar" ||
                     c.name == "tabBar" || c.name == "tabBarItem" || c.name == "refreshControl") {
                auto el = parse_element(bc, *sw, c, sw->controller, false);
                if (c.name == "refreshControl" && sw->root_view) sw->root_view->set("UIRefreshControl", el);
            } else if (c.attr_or("key") == "view" && !base_class_for_tag(c.name).empty()) {
                sw->root_view = parse_element(bc, *sw, c, sw->controller, true);
                if (canvas_size) {
                    auto rect = c.first_child("rect");
                    auto width = std::max(canvas_size->first, rect ? to_double(rect->attr("width")).value_or(0) : 0.0),
                         height =
                             std::max(canvas_size->second, rect ? to_double(rect->attr("height")).value_or(0) : 0.0);
                    xml::Node frame;
                    frame.attributes = {{"key", "frame"},
                                        {"x", "0"},
                                        {"y", "0"},
                                        {"width", std::to_string(width)},
                                        {"height", std::to_string(height)}};
                    add_rect(sw->root_view, frame);
                }
                sw->controller->set("UIView", sw->root_view);
                if (c.name == "tableView")
                    sw->controller->set("UITableView", sw->root_view);
                else if (c.name == "collectionView")
                    sw->controller->set("UICollectionView", sw->root_view);
            } else if (!compiler_knows_tag(c.name))
                diagnostics.warn("OPENIB-W1201", "Unsupported controller child <" + c.name + ">", bc.file, c.line);
        }
        auto storyboard_id = scene.controller_node->attr_or("storyboardIdentifier");
        sw->controller_nib_name =
            !storyboard_id.empty() ? storyboard_id : sw->controller_base_class + "-" + sw->controller_id;
        if (sw->root_view) {
            std::string rootId;
            for (const auto& [oid, o] : sw->objects)
                if (o == sw->root_view) {
                    rootId = oid;
                    break;
                }
            sw->view_nib_name = sw->controller_id + "-view-" + rootId;
        }
        if (sw->is_external_storyboard_reference)
            sw->controller->set("UIStoryboardIdentifier", bc.gb.string(sw->controller_nib_name));
        bc.controller_id_to_nib[sw->controller_id] = sw->controller_nib_name;
        bc.scenes.push_back(std::move(sw));
    }
    // Some objects (notably NSLayoutConstraint) are registered locally during parsing.
    // Promote all scene IDs into the document-wide lookup before resolving cross references.
    for(auto& swp:bc.scenes){ for(auto& [id,obj]:swp->objects){ bc.global_objects[id]=obj; bc.global_owner[id]=swp.get(); } }
    // Resolve constraint object references and storyboard segue destinations.
    for(auto& swp:bc.scenes){auto& sw=*swp;for(auto& pr:sw.references){auto it=bc.global_objects.find(pr.target_id);if(it!=bc.global_objects.end())pr.owner->set(pr.key,it->second);else diagnostics.warn("OPENIB-W1301","Unresolved object reference: "+pr.target_id,bc.file);}
        if (!sw.segues.empty()) {
            std::vector<GraphRef> ts;
            for (auto& sg : sw.segues) {
                if (sg.kind != "unwind") {
                    auto it = bc.controller_id_to_nib.find(sg.destination_id);
                    if (it != bc.controller_id_to_nib.end())
                        sg.template_object->set("UIDestinationViewControllerIdentifier", bc.gb.string(it->second));
                    else
                        diagnostics.warn("OPENIB-W1302", "Unresolved segue destination: " + sg.destination_id, bc.file,
                                         sg.xml_node ? sg.xml_node->line : 0);
                }
                ts.push_back(sg.template_object);
            }
            sw.controller->set("UIStoryboardSegueTemplates", bc.gb.array(ts));
        }
    }
    // Relationship destinations are encoded inside the owning container's
    // controller NIB rather than receiving a second standalone controller NIB.
    std::unordered_set<SceneWork*> embedded_children;
    std::unordered_map<SceneWork*,std::vector<SceneWork*>> embedded_by_parent;
    std::unordered_set<SceneWork*> external_placeholders_requiring_nibs;
    for(auto& swp:bc.scenes){for(const auto& segue:swp->segues){auto owner=bc.global_owner.find(segue.destination_id);if(owner!=bc.global_owner.end()&&owner->second->is_external_storyboard_reference)external_placeholders_requiring_nibs.insert(owner->second);}}
    for (auto& swp : bc.scenes) {
        auto& sw = *swp;
        std::vector<GraphRef> children, navigation_items;
        for (const auto& [relationship, destination] : sw.relationships) {
            (void)relationship;
            auto owner = bc.global_owner.find(destination);
            if (owner == bc.global_owner.end() || owner->second == &sw) continue;
            auto* child = owner->second;
            children.push_back(child->controller);
            embedded_children.insert(child);
            embedded_by_parent[&sw].push_back(child);
            child->controller->set("UIParentViewController", sw.controller);
            std::vector<GraphRef> gestures;
            for (const auto& extra : child->scene_extras)
                if (extra->class_name == "UITapGestureRecognizer") gestures.push_back(extra);
            if (!gestures.empty())
                child->controller->set("UITopLevelObjectsToKeepAliveFromStoryboard", bc.gb.array(gestures));
            if (auto value = child->controller->get("UINavigationItem"))
                if (auto item = std::get_if<GraphRef>(&*value)) {
                    navigation_items.push_back(*item);
                    if (auto bar_value = sw.controller->get("UINavigationBar"))
                        if (auto bar = std::get_if<GraphRef>(&*bar_value)) (*item)->set("UINavigationBar", *bar);
                    if (child->is_external_storyboard_reference) child->controller->erase("UINavigationItem");
                }
        }
        if (!children.empty()) {
            sw.controller->set("UIChildViewControllers", bc.gb.mutable_array(children));
            sw.controller->set("UIViewControllers", bc.gb.mutable_array(children));
        }
        if (!navigation_items.empty())
            if (auto bar_value = sw.controller->get("UINavigationBar"))
                if (auto bar = std::get_if<GraphRef>(&*bar_value))
                    (*bar)->set("UIItems", bc.gb.mutable_array(navigation_items));
        add_layout_guide_constraints(bc.gb, sw);
    }
    std::filesystem::remove_all(out);std::filesystem::create_directories(out);nib::Writer writer;std::map<std::string,std::string> idmap;std::map<std::string,ExternalStoryboardReference> external_refs;std::size_t files=0;
    // Prepare every scene and write every split view archive first. Container
    // controller archives can then reference fully prepared child controllers
    // regardless of scene order in the XML document.
    for (auto& swp : bc.scenes) {
        auto& sw = *swp;
        if (sw.is_external_storyboard_reference) {
            external_refs[sw.controller_nib_name] = {sw.external_storyboard_name, sw.external_controller_identifier};
            continue;
        }
        std::unordered_map<std::uint64_t, GraphRef> proxy_for_external;
        std::vector<std::pair<GraphRef, GraphRef>> external_pairs;
        std::vector<GraphRef> view_external_proxies;
        std::size_t proxy_counter = 1;
        auto proxyFor = [&](const GraphRef& external) {
            auto it = proxy_for_external.find(external->serial);
            if (it != proxy_for_external.end()) return it->second;
            auto id = make_upstream_id(proxy_counter++);
            auto p = bc.gb.proxy(id);
            proxy_for_external[external->serial] = p;
            external_pairs.push_back({bc.gb.string(id), external});
            view_external_proxies.push_back(p);
            return p;
        };
        for (auto& pc : sw.connections) {
            auto dit = bc.global_objects.find(pc.destination_id);
            if (dit == bc.global_objects.end()) {
                diagnostics.warn("OPENIB-W1303", "Unresolved connection destination: " + pc.destination_id, bc.file,
                                 pc.xml_node ? pc.xml_node->line : 0);
                continue;
            }
            auto dest = dit->second;
            bool srcView = false, dstView = false;
            for (auto& [id, obj] : sw.objects)
                if (obj == pc.source) {
                    srcView = sw.view_side[id];
                    break;
                }
            auto dOwn = bc.global_owner.find(pc.destination_id);
            if (dOwn != bc.global_owner.end() && dOwn->second == &sw) dstView = sw.view_side[pc.destination_id];
            if(srcView||dstView){auto src=srcView?pc.source:proxyFor(pc.source);auto dd=dstView?dest:proxyFor(dest);sw.view_connections.push_back(connection_object(bc.gb,pc,src,dd));}else sw.scene_connections.push_back(connection_object(bc.gb,pc,pc.source,dest));
        }
        for (auto& sg : sw.segues) {
            if (!sg.trigger) continue;
            PendingConnection ownerConnection{"outlet", "viewController", {}, sg.template_object, 0, sg.xml_node};
            sw.scene_connections.push_back(
                connection_object(bc.gb, ownerConnection, sg.template_object, sw.controller));
            if (sg.trigger == sw.controller) continue;
            bool triggerView = false;
            for (auto& [id, obj] : sw.objects)
                if (obj == sg.trigger) {
                    triggerView = sw.view_side[id];
                    break;
                }
            if (triggerView) {
                auto ph = proxyFor(sg.template_object);
                if (sg.kind == "embed") {
                    PendingConnection pc{"outlet", "containerView", {}, ph, 0, sg.xml_node};
                    sw.view_connections.push_back(connection_object(bc.gb, pc, ph, sg.trigger));
                } else if (is_table_cell(sg.trigger)) {
                    PendingConnection pc{"outlet", "selectionSegueTemplate", {}, sg.trigger, 0, sg.xml_node};
                    sw.view_connections.push_back(connection_object(bc.gb, pc, sg.trigger, ph));
                } else {
                    PendingConnection pc{"action", "perform:", {}, sg.trigger, 64, sg.xml_node};
                    sw.view_connections.push_back(connection_object(bc.gb, pc, sg.trigger, ph));
                }
            } else {
                PendingConnection pc{"action", "perform:", {}, sg.trigger, 64, sg.xml_node};
                sw.scene_connections.push_back(connection_object(bc.gb, pc, sg.trigger, sg.template_object));
            }
        }
        if(sw.root_view&&(!sw.table_prototype_segues.empty()||!sw.table_prototype_externals.empty())){
            std::map<std::string,std::vector<std::pair<GraphRef,GraphRef>>> per_reuse;
            // The dictionary key is the placeholder identifier within the
            // prototype cell NIB; its value is a proxy from this view NIB.
            // These are distinct identifier namespaces.
            for(const auto& [reuse,segue]:sw.table_prototype_segues){auto proxy=proxyFor(segue);auto& pairs=per_reuse[reuse];pairs.push_back({bc.gb.string(make_upstream_id(pairs.size()+1)),proxy});}
            for(const auto& [reuse,external_object]:sw.table_prototype_externals){auto proxy=proxyFor(external_object);auto& pairs=per_reuse[reuse];pairs.push_back({bc.gb.string(make_upstream_id(pairs.size()+1)),proxy});}
            std::vector<std::pair<GraphRef,GraphRef>> external;
            for(auto& [reuse,pairs]:per_reuse)external.push_back({bc.gb.string(reuse),bc.gb.mutable_dictionary(pairs)});
            sw.root_view->set("UITableViewCellPrototypeNibExternalObjects",bc.gb.mutable_dictionary(external));
        }
        if(sw.root_view)sw.controller->set("UIExternalObjectsTableForViewLoading",bc.gb.dictionary(external_pairs));
        if (sw.root_view) {
            auto owner = bc.gb.proxy("IBFilesOwner");
            auto first = bc.gb.proxy("IBFirstResponder");
            auto vc = bc.gb.object("UIRuntimeOutletConnection");
            vc->set("UILabel", bc.gb.string("view"));
            vc->set("UISource", owner);
            vc->set("UIDestination", sw.root_view);
            std::vector<GraphRef> cons = {vc};
            if (sw.static_data_source) {
                PendingConnection data_source_connection{"outlet", "staticDataSource", {}, owner, 0, nullptr};
                cons.push_back(connection_object(bc.gb, data_source_connection, owner, sw.static_data_source));
            }
            cons.insert(cons.end(), sw.view_connections.begin(), sw.view_connections.end());
            std::vector<GraphRef> tops = {owner, first, sw.root_view};
            tops.insert(tops.end(), view_external_proxies.begin(), view_external_proxies.end());
            tops.insert(tops.end(), sw.view_tops.begin(), sw.view_tops.end());
            std::vector<GraphRef> objs = tops;
            objs.insert(objs.end(), sw.view_extras.begin(), sw.view_extras.end());
            auto root = nib_root(bc.gb, tops, cons, objs, false, sw.view_key_value_pairs,
                                 make_relationship_trait_lists(bc.gb, sw));
            writer.write_file(bc.gb.flatten({root}, options.nib_coder_version), out / (sw.view_nib_name + ".nib"));
            ++files;
            sw.controller->erase("UIView");
            sw.controller->erase("UITableView");
            sw.controller->erase("UICollectionView");
            sw.controller->set("UINibName", bc.gb.string(sw.view_nib_name));
        }
    }
    // Emit controller archives after all child controllers have their view NIB
    // names and external-object tables. A relationship child with its own
    // storyboard identifier is also independently instantiable and needs a
    // standalone controller archive in addition to the embedded copy.
    for (auto& swp : bc.scenes) {
        auto& sw = *swp;
        if (sw.is_external_storyboard_reference && !sw.external_controller_identifier.empty() &&
            !external_placeholders_requiring_nibs.contains(&sw))
            continue;
        if (sw.is_external_storyboard_reference) {
            auto owner = bc.gb.proxy("IBFilesOwner");
            auto first = bc.gb.proxy("IBFirstResponder");
            auto storyboard = bc.gb.proxy("UIStoryboardPlaceholder");
            auto connection = bc.gb.object("UIRuntimeOutletConnection");
            connection->set("UILabel", bc.gb.string("sceneViewController"));
            connection->set("UISource", owner);
            connection->set("UIDestination", sw.controller);
            std::vector<GraphRef> tops = {owner, first, storyboard, sw.controller};
            auto root = nib_root(bc.gb, tops, {connection}, tops);
            writer.write_file(bc.gb.flatten({root}, options.nib_coder_version),
                              out / (sw.controller_nib_name + ".nib"));
            ++files;
            idmap[sw.controller_nib_name] = sw.controller_nib_name;
            continue;
        }
        bool independently_addressable =
            sw.scene && sw.scene->controller_node && sw.scene->controller_node->attr("storyboardIdentifier");
        if (embedded_children.contains(&sw) && !independently_addressable) continue;
        auto fowner = bc.gb.proxy("IBFilesOwner");
        auto first = bc.gb.proxy("IBFirstResponder");
        auto sbph = bc.gb.proxy("UIStoryboardPlaceholder");
        auto c1 = bc.gb.object("UIRuntimeOutletConnection");
        c1->set("UILabel", bc.gb.string("storyboard"));
        c1->set("UISource", sw.controller);
        c1->set("UIDestination", sbph);
        auto c2 = bc.gb.object("UIRuntimeOutletConnection");
        c2->set("UILabel", bc.gb.string("sceneViewController"));
        c2->set("UISource", fowner);
        c2->set("UIDestination", sw.controller);
        std::vector<GraphRef> cons = {c1, c2};
        cons.insert(cons.end(), sw.scene_connections.begin(), sw.scene_connections.end());
        std::vector<GraphRef> tops = {fowner, first, sbph, sw.controller};
        std::vector<GraphRef> objs = tops;
        objs.insert(objs.end(), sw.scene_extras.begin(), sw.scene_extras.end());
        auto children = embedded_by_parent.find(&sw);
        if (children != embedded_by_parent.end()) {
            for (auto* child : children->second) {
                auto child_storyboard = bc.gb.proxy("UIStoryboardPlaceholder");
                tops.push_back(child_storyboard);
                objs.push_back(child_storyboard);
                objs.insert(objs.end(), child->scene_extras.begin(), child->scene_extras.end());
                for (const auto& extra : child->scene_extras)
                    if (extra->class_name == "UITapGestureRecognizer") tops.push_back(extra);
                if (!child->is_external_storyboard_reference) {
                    auto child_storyboard_connection = bc.gb.object("UIRuntimeOutletConnection");
                    child_storyboard_connection->set("UILabel", bc.gb.string("storyboard"));
                    child_storyboard_connection->set("UISource", child->controller);
                    child_storyboard_connection->set("UIDestination", sbph);
                    cons.push_back(child_storyboard_connection);
                }
                cons.insert(cons.end(), child->scene_connections.begin(), child->scene_connections.end());
            }
        }
        auto root=nib_root(bc.gb,tops,cons,objs,emit_live_nib_version&&sw.controller_base_class=="UIViewController"&&sw.segues.empty()&&sw.scene_extras.size()==1);
        auto parent=sw.controller->get("UIParentViewController");if(parent&&embedded_children.contains(&sw))sw.controller->erase("UIParentViewController");
        GraphRef navigation_item;
        std::optional<GraphValue> navigation_bar;
        if (auto value = sw.controller->get("UINavigationItem"))
            if (auto item = std::get_if<GraphRef>(&*value)) {
                navigation_item = *item;
                if (embedded_children.contains(&sw)) {
                    navigation_bar = navigation_item->get("UINavigationBar");
                    navigation_item->erase("UINavigationBar");
                }
            }
        writer.write_file(bc.gb.flatten({root}, options.nib_coder_version), out / (sw.controller_nib_name + ".nib"));
        if (parent) sw.controller->set("UIParentViewController", *parent);
        if (navigation_item && navigation_bar) navigation_item->set("UINavigationBar", *navigation_bar);
        ++files;
        idmap[sw.controller_nib_name] = sw.controller_nib_name;
    }
    std::string initial;auto it=bc.controller_id_to_nib.find(doc.initial_view_controller);if(it!=bc.controller_id_to_nib.end())initial=it->second;write_plist(out/"Info.plist",idmap,external_refs,initial);++files;return {!diagnostics.has_errors(),files};
}

CompileResult compile_xib(const IBDocument& doc,const std::filesystem::path& out,const CompileOptions& options,Diagnostics& diagnostics){
    const auto* root=doc.xml_document.root.get();const auto* objects=root?root->first_child("objects"):nullptr;if(!objects){diagnostics.error("OPENIB-E2001","XIB has no <objects> element",doc.xml_document.source_path);return {};}
    BuilderContext bc(diagnostics, doc.xml_document.source_path);
    bc.standalone_xib = true;
    try {
        auto tools = std::stod(doc.tools_version);
        bc.legacy_styled_fonts = tools < 16000.0;
        bc.modern_system_colors = tools >= 30000.0;
    } catch (...) {}
    auto sw = std::make_unique<SceneWork>();
    sw->standalone_xib = true;
    std::vector<GraphRef> tops;
    for (const auto& cp : objects->children) {
        auto o = parse_element(bc, *sw, *cp, nullptr, cp->name != "placeholder" && cp->name != "exit");
        if (o) tops.push_back(o);
    }
    for (auto& pr : sw->references) {
        auto it = sw->objects.find(pr.target_id);
        if (it != sw->objects.end()) pr.owner->set(pr.key, it->second);
    }
    for (auto& pc : sw->connections) {
        auto it = sw->objects.find(pc.destination_id);
        if (it != sw->objects.end())
            sw->scene_connections.push_back(connection_object(bc.gb, pc, pc.source, it->second));
    }
    std::vector<GraphRef> traits;
    if(!sw->constraint_variations.empty()){
        auto list=bc.gb.object("_UITraitStorageList"),default_trait=bc.gb.object("UITraitCollection"),key_path=bc.gb.string("encodedConstant"),descendants=bc.gb.object("NSSet");
        std::vector<GraphRef> storages;std::size_t descendant_index=0;
        for(const auto& variation:sw->constraint_variations){
            descendants->set("NS.object."+std::to_string(descendant_index++),variation.constraint);
            for(int copy=0;copy<2;++copy){
                auto storage=bc.gb.object("_UIAttributeTraitStorage");storage->set("UIObject",variation.constraint);storage->set("UIKeyPath",key_path);
                auto matching_trait=bc.gb.object("UITraitCollection");
                auto separator = variation.trait.find('=');
                if (separator != std::string::npos) {
                    auto name = variation.trait.substr(0, separator), value = variation.trait.substr(separator + 1);
                    auto size_class = value == "compact" ? 1 : value == "regular" ? 2 : 0;
                    if (name == "heightClass" || name == "widthClass")
                        matching_trait->set(std::string("UITraitCollectionBuiltinTrait-_UITraitName") +
                                                (name == "heightClass" ? "Vertical" : "Horizontal") + "SizeClass",
                                            std::int64_t(size_class));
                }
                auto make_record = [&](GraphRef trait, double value) {
                    auto number = bc.gb.object("_NSLayoutConstraintConstant");
                    number->set("UISymbolicConstant", std::monostate{});
                    number->set("UINumericConstant", value);
                    auto record = bc.gb.object("_UIAttributeTraitStorageRecord");
                    record->set("UITraitCollection", trait);
                    record->set("UIValue", number);
                    return record;
                };
                storage->set("UIRecords",bc.gb.mutable_array({make_record(matching_trait,variation.value),make_record(default_trait,variation.fallback)}));storages.push_back(storage);
            }
        }
        auto first_view=std::find_if(tops.begin(),tops.end(),[](const GraphRef& item){return item->class_name!="UIProxyObject";});if(first_view!=tops.end())list->set("UITopLevelObject",*first_view);
        list->set("UITraitStorages",bc.gb.array(storages));list->set("UIDescendants",descendants);traits.push_back(list);
    }
    std::vector<GraphRef> objs = tops;
    objs.insert(objs.end(), sw->scene_extras.begin(), sw->scene_extras.end());
    objs.insert(objs.end(), sw->view_extras.begin(), sw->view_extras.end());
    auto r = nib_root(bc.gb, tops, sw->scene_connections, objs, false, {}, traits);
    nib::Writer().write_file(bc.gb.flatten({r}, options.nib_coder_version), out);
    return {!diagnostics.has_errors(), 1};
}

} // namespace

CompileResult Compiler::compile(const std::filesystem::path& input,const std::filesystem::path& output,const CompileOptions& options,Diagnostics& diagnostics) const {
    struct TargetModuleScope{std::string previous;explicit TargetModuleScope(const std::string& module):previous(compiling_target_module){compiling_target_module=module;}~TargetModuleScope(){compiling_target_module=previous;}}scope(options.target_module);
    IBParser p;
    auto doc = p.parse(input, diagnostics);
    auto coverage = analyze_document(doc);
    for (auto& [tag, count] : coverage.unsupported_tag_counts)
        diagnostics.warn("OPENIB-W1000",
                         "Unsupported Interface Builder tag <" + tag + "> appears " + std::to_string(count) +
                             " time(s)",
                         input.string());
    if (options.strict && !coverage.unsupported_tag_counts.empty()) {
        diagnostics.error("OPENIB-E1000", "Strict mode rejects unsupported Interface Builder tags", input.string());
        return {};
    }
    if(doc.is_storyboard) return compile_storyboard(doc,output,options,diagnostics);
    if(doc.is_xib) return compile_xib(doc,output,options,diagnostics);
    diagnostics.error("OPENIB-E0002","Input is neither a CocoaTouch storyboard nor XIB",input.string());
    return {};
}

} // namespace openib
