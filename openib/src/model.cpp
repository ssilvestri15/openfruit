#include "openib/model.hpp"

#include <array>
#include <unordered_set>

namespace openib {

bool IBParser::is_controller_tag(std::string_view tag) {
    static const std::unordered_set<std::string> tags = {
        "viewController", "navigationController", "tableViewController",
        "collectionViewController", "pageViewController", "splitViewController",
        "tabBarController", "viewControllerPlaceholder"
    };
    return tags.contains(std::string(tag));
}

IBDocument IBParser::parse(const std::filesystem::path& path, Diagnostics& diagnostics) const {
    xml::Parser parser;
    IBDocument result;
    result.xml_document = parser.parse_file(path);
    const auto* root = result.xml_document.root.get();
    if (!root || root->name != "document") {
        throw OpenIBError("Interface Builder document root must be <document>");
    }

    result.type = root->attr_or("type");
    result.format_version = root->attr_or("version");
    result.tools_version = root->attr_or("toolsVersion");
    result.target_runtime = root->attr_or("targetRuntime");
    result.initial_view_controller = root->attr_or("initialViewController");
    result.is_storyboard = result.type.find("Storyboard") != std::string::npos;
    result.is_xib = !result.is_storyboard && result.type.find("XIB") != std::string::npos;

    if (result.target_runtime != "iOS.CocoaTouch") {
        diagnostics.warn("OPENIB-W0001", "Document targetRuntime is not iOS.CocoaTouch", path.string(), root->line);
    }

    if (result.is_storyboard) {
        const auto* scenes = root->first_child("scenes");
        if (!scenes) throw OpenIBError("Storyboard has no <scenes> element");
        for (const auto* scene_node : scenes->children_named("scene")) {
            IBScene scene;
            scene.scene_id = scene_node->attr_or("sceneID");
            scene.scene_node = scene_node;
            scene.objects_node = scene_node->first_child("objects");
            if (!scene.objects_node) {
                diagnostics.error("OPENIB-E0101", "Scene has no <objects> element", path.string(), scene_node->line);
                continue;
            }
            for (const auto& child : scene.objects_node->children) {
                if (is_controller_tag(child->name) &&
                    (child->attr_or("sceneMemberID") == "viewController" || !scene.controller_node)) {
                    scene.controller_node = child.get();
                }
            }
            if (!scene.controller_node) {
                diagnostics.error("OPENIB-E0102", "Scene has no supported view controller", path.string(), scene_node->line);
            }
            result.scenes.push_back(scene);
        }
    }

    return result;
}

bool compiler_knows_tag(std::string_view tag) {
    static const std::unordered_set<std::string> known = {
        "document","device","adaptation","dependencies","deployment","plugIn","capability",
        "scenes","scene","objects","resources","image","namedColor",
        "viewController","navigationController","tableViewController","collectionViewController",
        "pageViewController","splitViewController","tabBarController","placeholder","exit",
        "layoutGuides","viewControllerLayoutGuide","view","containerView","stackView","imageView",
        "label","button","switch","searchBar","textView","textField","scrollView","visualEffectView",
        "blurEffect","vibrancyEffect","tableView","tableViewCell","tableViewCellContentView",
        "collectionView","collectionViewCell","collectionReusableView","collectionViewFlowLayout",
        "subviews","rect","point","size","autoresizingMask","constraints","constraint","connections",
        "outlet","action","segue","navigationItem","navigationBar","barButtonItem","toolbarItems","items",
        "state","color","fontDescription","inset","nil","userDefinedRuntimeAttributes",
        "userDefinedRuntimeAttribute","variation","mask","exclude","include","sections","tableViewSection",
        "cells","prototypes","textInputTraits","simulatedNavigationBarMetrics","simulatedTabBarMetrics",
        "simulatedToolbarMetrics","edgeInsets","offsetWrapper","freeformSimulatedSizeMetrics",
        "collectionViewCellContentView","directionalEdgeInsets","imageReference","inferredMetricsTieBreakers",
        "systemColor","toolbar","viewControllerPlaceholder","listContentConfiguration","rightBarButtonItems",
        "segment","segmentedControl","segments","textAttributes","activityIndicatorView","gestureRecognizers",
        "outletCollection","slider","string","tapGestureRecognizer","value","viewLayoutGuide",
        "pageControl","progressView","refreshControl","tabBar","tabBarItem","wkWebView",
        "datePicker","pickerView","stepper","colorWell",
        "accessibility","buttonConfiguration","preferredSymbolConfiguration","wkWebViewConfiguration",
        "wkPreferences","audiovisualMediaTypes","designables","designable","hierarchicalColors","integer","real"
    };
    return known.contains(std::string(tag));
}

static void analyze_node(const xml::Node& node, CoverageReport& report) {
    ++report.tag_counts[node.name];
    if (!compiler_knows_tag(node.name)) ++report.unsupported_tag_counts[node.name];
    if (node.name == "outlet") ++report.outlet_count;
    if (node.name == "action") ++report.action_count;
    if (node.name == "segue") ++report.segue_count;
    if (node.name == "constraint") ++report.constraint_count;
    for (const auto& child : node.children) analyze_node(*child, report);
}

CoverageReport analyze_document(const IBDocument& document) {
    CoverageReport report;
    report.scene_count = document.scenes.size();
    if (document.xml_document.root) analyze_node(*document.xml_document.root, report);
    return report;
}

} // namespace openib
