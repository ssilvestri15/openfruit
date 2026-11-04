#include "genstrings.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace OpenFruit::Genstrings;
namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
} // namespace

int main() {
    try {
        Tables tables;
        std::vector<std::string> warnings;
        Extract(R"SRC(
            // NSLocalizedString("COMMENTED", comment: "")
            let a = NSLocalizedString("PLAY", comment: "Play button")
            let b = NSLocalizedString("PLAY", comment: "Toolbar")
            let c = NSLocalizedString("SIZE", tableName: "Units", value: "%@ of %@", comment: "")
            let d = NSLocalizedString(key, comment: "dynamic")
            let e = "NSLocalizedString(\"IN_STRING\", comment: \"\")"
            let f = NSLocalizedString("ESCAPED \"Q\"\n", comment: "Esc")
        )SRC", Language::Swift, "A.swift", {}, tables, warnings);
        Extract(R"SRC(
            NSString *x = NSLocalizedString(@"OPEN", nil);
            NSString *y = NSLocalizedStringFromTable(@"CLOSE", @"Menu", @"Close menu item");
            NSString *z = NSLocalizedStringWithDefaultValue(@"LONG", nil, [NSBundle mainBundle], @"A " @"joined value", @"Joined");
            /* NSLocalizedString(@"BLOCK", nil) */
        )SRC", Language::ObjectiveC, "B.m", {}, tables, warnings);

        const auto& main = tables.at("Localizable");
        Require(!main.contains("COMMENTED") && !main.contains("IN_STRING") && !tables.contains("") &&
                !main.contains("BLOCK"), "comments or string contents were extracted");
        Require(main.at("PLAY").comments == std::vector<std::string>({"Play button", "Toolbar"}),
                "duplicate key comments were not merged");
        Require(tables.at("Units").at("SIZE").value == "%1$@ of %2$@", "table/value/positional parameters wrong");
        Require(main.at("OPEN").comments.front() == "No comment provided by engineer.", "missing comment default");
        Require(tables.at("Menu").at("CLOSE").comments.front() == "Close menu item", "FromTable mapping wrong");
        Require(main.at("LONG").value == "A joined value", "Objective-C literal concatenation wrong");
        Require(main.contains("ESCAPED \\\"Q\\\"\\n"), "escapes were not preserved as written");
        Require(std::count_if(warnings.begin(), warnings.end(), [](const auto& w) {
                    return w.find("Argument is not a literal string") != std::string::npos; }) == 1,
                "non-literal key was not reported");
        Require(PositionalFormat("%d%%") == "%d%%" && PositionalFormat("%1$@ %2$@") == "%1$@ %2$@" &&
                PositionalFormat("%@ %d") == "%1$@ %2$d", "positional rewrite wrong");
        Require(Render(tables.at("Menu")) == "/* Close menu item */\n\"CLOSE\" = \"CLOSE\";\n\n",
                "rendered layout wrong");
        std::cout << "PASS: genstrings extraction and rendering\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << "\n";
        return 1;
    }
}
