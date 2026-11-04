#include "interface_builder_compiler.hpp"

#include "tool_paths.hpp"
#include "win32_process.hpp"
#include "operation_events.hpp"
#include "process_diagnostics.hpp"

#ifdef OPENFRUIT_HAS_OPENIB_INPROCESS
#include <openib/compiler.hpp>
#endif

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

namespace fs = std::filesystem;

namespace OpenFruit {
namespace {
#ifdef OPENFRUIT_HAS_OPENIB_INPROCESS
void PublishDiagnostics(const openib::Diagnostics& diagnostics, const fs::path& input) {
    const auto context = CurrentOperationContext();
    if (!context) return;
    for (const auto& item : diagnostics.items()) {
        const char* severity = item.severity == openib::Severity::Error ? "error" :
            item.severity == openib::Severity::Warning ? "warning" : "info";
        auto data = JsonValue::ObjectValue();
        data.Set("diagnostic_id", JsonValue::String(NewOperationId()));
        data.Set("tool", JsonValue::String("openib"));
        data.Set("code", JsonValue::String(item.code));
        data.Set("severity", JsonValue::String(severity));
        data.Set("message", JsonValue::String(RedactDiagnosticText(item.message)));
        auto source = item.file.empty() ? input : fs::path(Win32Process::ToWide(item.file));
        data.Set("file", JsonValue::String(Win32Process::ToNarrow(source.lexically_normal().wstring())));
        if (item.line) data.Set("line", JsonValue::Number(std::to_string(item.line)));
        // OpenIB supplies no column. Do not invent a source coordinate.
        context->Emit("diagnostic", std::move(data), severity);
    }
}

void PublishCompilerException(const std::string& message, const fs::path& input) {
    const auto context = CurrentOperationContext();
    if (!context) return;
    auto data = JsonValue::ObjectValue();
    data.Set("diagnostic_id", JsonValue::String(NewOperationId()));
    data.Set("tool", JsonValue::String("openib"));
    // This classification belongs to the adapter: OpenIB supplied an exception,
    // not a Diagnostic with its own code or structured source coordinates.
    data.Set("origin", JsonValue::String("openfruit.adapter"));
    data.Set("code", JsonValue::String("OPENFRUIT-IB-EXCEPTION"));
    data.Set("severity", JsonValue::String("error"));
    data.Set("message", JsonValue::String(RedactDiagnosticText(message)));
    data.Set("file", JsonValue::String(Win32Process::ToNarrow(input.lexically_normal().wstring())));
    context->Emit("diagnostic", std::move(data), "error");
}
#endif
class FileProgress {
public:
    explicit FileProgress(std::size_t planned)
        : context_(CurrentOperationContext()), planned_(planned) { Publish("running"); }
    ~FileProgress() { if (!finished_) Publish("failed"); }
    void Completed() { ++completed_; Publish("running"); }
    void Finish() { finished_ = true; Publish("succeeded"); }
private:
    void Publish(const char* state) noexcept {
        if (!context_) return;
        try {
            auto data = JsonValue::ObjectValue();
            data.Set("basis", JsonValue::String("files"));
            data.Set("planned_units", JsonValue::Number(std::to_string(planned_)));
            data.Set("completed_units", JsonValue::Number(std::to_string(completed_)));
            data.Set("percent", JsonValue::Number(std::to_string(planned_ ? completed_ * 100 / planned_ : 100)));
            data.Set("is_time_estimate", JsonValue::Boolean(false));
            data.Set("state", JsonValue::String(state));
            context_->Emit("task.progress", std::move(data));
        } catch (...) {}
    }
    OperationContextPtr context_;
    std::size_t planned_, completed_ = 0;
    bool finished_ = false;
};
}

bool InterfaceBuilderCompiler::CompileUncompiledInBundle(
    const fs::path& bundle_dir,
    std::string& error,
    const std::string& target_module
) {
    std::error_code ec;
    if (!fs::is_directory(bundle_dir, ec)) {
        error = "bundle does not exist: " + bundle_dir.string();
        return false;
    }

    std::vector<fs::path> inputs;
    for (fs::recursive_directory_iterator it(
             bundle_dir, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) {
            error = "unable to scan staged bundle: " + ec.message();
            return false;
        }
        if (!it->is_regular_file(ec)) continue;
        std::string extension = it->path().extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        bool xml_nib = false;
        if (extension == ".nib") {
            std::ifstream probe(it->path(), std::ios::binary);
            char prefix[5]{};
            probe.read(prefix, sizeof(prefix));
            xml_nib = probe.gcount() == sizeof(prefix) &&
                      prefix[0] == '<' && prefix[1] == '?' &&
                      prefix[2] == 'x' && prefix[3] == 'm' && prefix[4] == 'l';
        }
        if (extension == ".storyboard" || extension == ".xib" || xml_nib) {
            inputs.push_back(it->path());
        }
    }
    if (ec) {
        error = "unable to scan staged bundle: " + ec.message();
        return false;
    }
    if (inputs.empty()) return true;

    std::sort(inputs.begin(), inputs.end());
    std::vector<std::wstring> input_paths;
    for (const auto& input : inputs) input_paths.push_back(input.wstring());
    auto metadata = JsonValue::ObjectValue();
    metadata.Set("inputs", StringArray(input_paths));
    metadata.Set("bundle", JsonValue::String(Win32Process::ToNarrow(bundle_dir.wstring())));
    OperationSpan phase("resource.interface_builder", std::move(metadata));
    FileProgress progress(inputs.size());

#ifndef OPENFRUIT_HAS_OPENIB_INPROCESS
    const fs::path compiler = ToolPaths::LocalHome() / "bin" / "openib.exe";
    if (!fs::is_regular_file(compiler, ec)) {
        error = "Interface Builder compiler is missing: " + compiler.string();
        return false;
    }
#endif

    for (const fs::path& input : inputs) {
        std::string extension = input.extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        fs::path output = input;
        output.replace_extension(extension == ".storyboard" ? ".storyboardc" : ".nib");
        const bool in_place = output == input;
        if (in_place) {
            output = input.parent_path() / (input.stem().wstring() + L".OPENFRUIT-compiled.nib");
        }
        auto file_metadata = JsonValue::ObjectValue();
        file_metadata.Set("inputs", StringArray({input.wstring()}));
        file_metadata.Set("output", JsonValue::String(Win32Process::ToNarrow(output.wstring())));
        OperationSpan file_activity("resource.interface_builder.file", std::move(file_metadata));
        std::cout << "OPENFRUIT Interface Builder: " << input.string()
                  << " -> " << output.string() << std::endl;

        bool compiled_ok = false;
        std::string failure_detail;
        // Only the target's own resources, not nested bundles of other targets.
        std::string module = target_module;
        for (const auto& component : input.lexically_relative(bundle_dir).parent_path()) {
            if (component.has_extension()) { module.clear(); break; }
        }

#ifdef OPENFRUIT_HAS_OPENIB_INPROCESS
        openib::Diagnostics ib_diag;
        std::string compiler_exception;
        bool compiler_threw = false;
        try {
            openib::Compiler ib_compiler;
            openib::CompileOptions ib_opts;
            ib_opts.nib_coder_version = 10;
            ib_opts.overwrite = true;
            ib_opts.target_module = module;
            openib::CompileResult res = ib_compiler.compile(input, output, ib_opts, ib_diag);
            if (res.success && fs::exists(output, ec)) {
                compiled_ok = true;
            } else {
                for (const auto& item : ib_diag.items()) {
                    if (item.severity == openib::Severity::Error) {
                        if (!failure_detail.empty()) failure_detail += "; ";
                        failure_detail += item.message;
                    }
                }
            }
        } catch (const std::exception& ex) {
            failure_detail = ex.what();
            compiler_exception = failure_detail;
            compiler_threw = true;
        }
        // Preserve original typed diagnostics on success, failure and exceptions.
        // Publish before fallback/failure while the per-resource span is active.
        PublishDiagnostics(ib_diag, input);
        if (compiler_threw) PublishCompilerException(compiler_exception, input);
#endif

        if (!compiled_ok) {
            const fs::path compiler = ToolPaths::LocalHome() / "bin" / "openib.exe";
            if (fs::is_regular_file(compiler, ec)) {
                std::vector<std::wstring> arguments{compiler.wstring(), L"compile", input.wstring(), L"-o", output.wstring()};
                if (!module.empty()) {
                    arguments.push_back(L"--module");
                    arguments.push_back(Win32Process::ToWide(module));
                }
                const ProcessResult compiled = Win32Process::Run(compiler.wstring(), arguments, bundle_dir.wstring());
                if (compiled.success && fs::exists(output, ec)) {
                    compiled_ok = true;
                } else {
                    failure_detail = "exit " + std::to_string(compiled.exit_code) + ": " + compiled.std_err;
                }
            }
        }

        if (!compiled_ok || !fs::exists(output, ec)) {
            error = "failed to compile " + input.string() + ": " +
                    (failure_detail.empty() ? "Interface Builder compilation failed" : failure_detail);
            return false;
        }
        if (in_place) {
            fs::copy_file(output, input, fs::copy_options::overwrite_existing, ec);
            if (ec) {
                error = "unable to stage compiled NIB: " + input.string() +
                        ": " + ec.message();
                return false;
            }
            fs::remove(output, ec);
            if (ec) {
                error = "unable to remove temporary compiled NIB: " + output.string() +
                        ": " + ec.message();
                return false;
            }
        } else {
            fs::remove(input, ec);
            if (ec) {
                error = "unable to remove compiled XML from staged bundle: " + input.string() +
                        ": " + ec.message();
                return false;
            }
        }
        file_activity.Succeed();
        progress.Completed();
    }
    progress.Finish();
    phase.Succeed();
    return true;
}

} // namespace OpenFruit
