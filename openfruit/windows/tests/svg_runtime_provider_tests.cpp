#include "svg_runtime_provider.hpp"
#include "operation_events.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>
using namespace OpenFruit;
int main() {
    try {
        const auto relative=EnsureNativeSvgProvider("relative-installation");
        if (relative.available || relative.error.empty()) throw std::runtime_error("Relative managed root must fail before acquisition");
        auto context=std::make_shared<OperationContext>(); context->RequestCancellation();
        const auto root=std::filesystem::temp_directory_path()/("s-"+NewOperationId().substr(0,16));
        { OperationBinding binding(context); const auto cancelled=EnsureNativeSvgProvider(root);
          if (cancelled.available || cancelled.error.find("cancelled")==std::string::npos) throw std::runtime_error("Cancelled SVG acquisition must fail before writes"); }
        if (std::filesystem::exists(root)) throw std::runtime_error("Cancellation must not publish provider state");
        std::cout<<"svg_runtime_provider_tests PASS\n"; return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
