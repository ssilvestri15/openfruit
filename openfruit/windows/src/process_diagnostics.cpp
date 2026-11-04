#include "process_diagnostics.hpp"
#include "win32_process.hpp"
#include "text_util.hpp"

#include <algorithm>
#include <cctype>
#include <regex>
#include <set>

namespace OpenFruit {
namespace {
}

std::string RedactDiagnosticText(std::string text) {
    if (text.find("http") != std::string::npos) {
        static const std::regex userinfo(R"((https?://)[^/\s]+@)");
        static const std::regex query(R"((https?://[^?\s]+)\?[^\s]+)");
        text = std::regex_replace(text, userinfo, "$1[redacted]@");
        text = std::regex_replace(text, query, "$1?[redacted]");
    }
    const std::string lower = ToLowerAscii(text);
    if (lower.find("password") != std::string::npos || lower.find("token") != std::string::npos ||
        lower.find("cookie") != std::string::npos || lower.find("authorization") != std::string::npos ||
        lower.find("secret") != std::string::npos) {
        static const std::regex credential(
            R"(((?:password|token|cookie|authorization|secret)\s*[:=]\s*)[^\r\n]+)", std::regex::icase);
        text = std::regex_replace(text, credential, "$1[redacted]");
    }
    return text;
}

void RedactEventData(JsonValue& value) {
    if (value.IsString()) value = JsonValue::String(RedactDiagnosticText(value.StringValue()));
    else if (value.IsArray()) for (auto& child : value.ArrayItems()) RedactEventData(child);
    else if (value.IsObject()) for (auto& [key, child] : value.ObjectItems()) RedactEventData(child);
}

JsonValue DescribeCommand(const std::wstring& executable,
                          const std::vector<std::wstring>& arguments,
                          const std::wstring& working_directory) {
    auto data = JsonValue::ObjectValue();
    data.Set("executable", JsonValue::String(Win32Process::ToNarrow(executable)));
    data.Set("working_directory", JsonValue::String(Win32Process::ToNarrow(working_directory)));
    auto args = JsonValue::ArrayValue();
    const auto tool = ToLowerAscii(std::filesystem::path(executable).filename().string());
    const bool shell = tool == "cmd.exe" || tool == "powershell.exe" || tool == "pwsh.exe" ||
                       tool == "bash.exe" || tool == "wsl.exe" || tool == "sh.exe";
    static const std::set<std::string> value_options = {
        "-sdk", "-target", "-I", "-F", "-L", "-Fsystem", "-Isystem", "-isysroot",
        "-module-name", "-o", "-MF", "-MT", "-resource-dir", "-module-cache-path",
        "-output-dir", "-emit-module-path", "-emit-objc-header-path", "-filelist"
    };
    static const std::set<std::string> source_extensions = {".swift", ".c", ".m", ".mm", ".cpp", ".cc", ".cxx"};
    static const std::set<std::string> switches = {
        "-c", "-v", "-frontend", "-emit-object", "-emit-module", "-emit-library",
        "-parse-as-library", "-whole-module-optimization", "-enable-objc-interop",
        "-g", "-Onone", "-O", "-Osize", "-Xfrontend", "-Xcc", "-Xllvm",
        "-fmodules", "-fimplicit-modules", "-fimplicit-module-maps"
    };
    bool allowed_value = false;
    bool suppress_value = false;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const std::string raw = Win32Process::ToNarrow(arguments[index]);
        std::string visible = "[redacted]";
        if (index == 0 && arguments[index] == executable) visible = raw;
        else if (!shell && !suppress_value) {
            if (allowed_value) visible = raw;
            else if (raw.rfind("-D", 0) == 0) visible = "-D[redacted]";
            else if (switches.contains(raw) || value_options.contains(raw)) visible = raw;
            else if (!raw.empty() && raw[0] == '@') visible = "@[response-file]";
            else if (source_extensions.contains(ToLowerAscii(std::filesystem::path(raw).extension().string()))) visible = raw;
        }
        args.ArrayItems().push_back(JsonValue::String(RedactDiagnosticText(visible)));
        allowed_value = !shell && value_options.contains(raw);
        const auto option = ToLowerAscii(raw);
        suppress_value = option == "-p" || option == "-h" || option == "--password" ||
            option == "--p12-password" || option == "--token" || option == "--cookie" || option == "--secret";
    }
    data.Set("arguments", std::move(args));
    return data;
}


std::vector<std::string> SensitiveCommandValues(const std::vector<std::wstring>& arguments) {
    std::vector<std::string> values;
    bool next_is_sensitive = false;
    for (const auto& argument : arguments) {
        const std::string raw = Win32Process::ToNarrow(argument);
        const std::string option = ToLowerAscii(raw);
        if (next_is_sensitive && !raw.empty()) values.push_back(raw);
        next_is_sensitive = option == "-p" || option == "-h" || option == "--password" ||
            option == "--p12-password" || option == "--token" || option == "--cookie" || option == "--secret";
        const auto equals = option.find('=');
        if (equals != std::string::npos && (option.find("password") < equals ||
            option.find("token") < equals || option.find("secret") < equals || option.find("cookie") < equals)) {
            if (equals + 1 < raw.size()) values.push_back(raw.substr(equals + 1));
        }
    }
    return values;
}

ProcessDiagnostics::ProcessDiagnostics(OperationContextPtr context, const std::wstring& working_directory,
                                       std::vector<std::string> sensitive_values)
    : context_(std::move(context)), working_directory_(working_directory), sensitive_values_(std::move(sensitive_values)) {}

void ProcessDiagnostics::Feed(const std::string& chunk) {
    if (!context_) return;
    for (char byte : chunk) {
        if (byte == '\n') {
            if (!discarding_line_) Line(std::move(pending_));
            pending_.clear();
            discarding_line_ = false;
        } else if (!discarding_line_) {
            pending_.push_back(byte);
            if (pending_.size() >= 16 * 1024) {
                pending_.clear();
                discarding_line_ = true;
                auto info = JsonValue::ObjectValue();
                info.Set("reason", JsonValue::String("tool output line exceeded diagnostic limit"));
                context_->Emit("diagnostic.truncated", std::move(info), "warning");
            }
        }
    }
}

void ProcessDiagnostics::Finish() {
    if (!pending_.empty() && !discarding_line_) Line(std::move(pending_));
    pending_.clear();
    FinishStack();
}

void ProcessDiagnostics::FinishStack() {
    if (stack_trace_id_.empty()) return;
    auto data = JsonValue::ObjectValue();
    data.Set("stack_trace_id", JsonValue::String(stack_trace_id_));
    data.Set("frame_count", JsonValue::Number(std::to_string(trace_frame_count_)));
    data.Set("truncated", JsonValue::Boolean(trace_truncated_));
    context_->Emit("diagnostic.stack_completed", std::move(data), "error");
    stack_trace_id_.clear();
}

void ProcessDiagnostics::Line(std::string line) {
    if (!context_) return;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    for (const auto& secret : sensitive_values_) {
        std::size_t offset = 0;
        while (!secret.empty() && (offset = line.find(secret, offset)) != std::string::npos) {
            line.replace(offset, secret.size(), "[redacted]");
            offset += 10;
        }
    }
    static const std::regex stack_header(R"(^\s*Stack dump:\s*$)");
    if (std::regex_match(line, stack_header)) {
        FinishStack();
        stack_trace_id_ = NewOperationId();
        trace_frame_count_ = 0;
        trace_truncated_ = false;
        auto data = JsonValue::ObjectValue();
        data.Set("stack_trace_id", JsonValue::String(stack_trace_id_));
        data.Set("availability", JsonValue::String("tool_output"));
        context_->Emit("diagnostic.stack_trace", std::move(data), "error");
        return;
    }
    if (!stack_trace_id_.empty()) {
        // LLVM preamble entries can contain the complete unfiltered command.
        static const std::regex preamble(R"(^\s*[0-9]+\.\s.*$)");
        if (std::regex_match(line, preamble)) return;
        static const std::regex frame(R"(^\s*#?([0-9]+)\s+(0x[0-9a-fA-F]+)\s+(.+)$)");
        static const std::regex module(R"(^(?:(.*?)\s+)?\((.+)\+(0x[0-9a-fA-F]+)\)$)");
        static const std::regex exception(R"(^\s*Exception Code:\s*(0x[0-9a-fA-F]+)\s*$)");
        std::smatch match;
        if (std::regex_match(line, match, exception)) {
            auto data = JsonValue::ObjectValue();
            data.Set("stack_trace_id", JsonValue::String(stack_trace_id_));
            data.Set("exception_code", JsonValue::String(match[1].str()));
            context_->Emit("diagnostic.stack_exception", std::move(data), "error");
            return;
        }
        if (std::regex_match(line, match, frame)) {
            if (trace_frame_count_ >= 256) {
                if (!trace_truncated_) {
                    auto data = JsonValue::ObjectValue();
                    data.Set("stack_trace_id", JsonValue::String(stack_trace_id_));
                    data.Set("frame_limit", JsonValue::Number("256"));
                    context_->Emit("diagnostic.stack_truncated", std::move(data), "warning");
                    trace_truncated_ = true;
                }
                return;
            }
            auto data = JsonValue::ObjectValue();
            data.Set("stack_trace_id", JsonValue::String(stack_trace_id_));
            data.Set("index", JsonValue::Number(std::to_string(trace_frame_count_)));
            data.Set("reported_index", JsonValue::String(match[1].str()));
            data.Set("address", JsonValue::String(match[2].str()));
            const auto detail = RedactDiagnosticText(match[3].str());
            std::smatch location;
            std::string symbolication = "unsymbolicated";
            if (std::regex_match(detail, location, module)) {
                data.Set("module", JsonValue::String(location[2].str()));
                data.Set("module_offset", JsonValue::String(location[3].str()));
                if (location[1].matched && !location[1].str().empty()) {
                    data.Set("symbol", JsonValue::String(location[1].str()));
                    symbolication = "tool_reported_symbol";
                }
            } else data.Set("detail", JsonValue::String(detail));
            data.Set("origin", JsonValue::String("tool_output"));
            data.Set("symbolication", JsonValue::String(symbolication));
            context_->Emit("diagnostic.stack_frame", std::move(data), "error");
            ++trace_frame_count_;
            ++stack_frame_count_;
            return;
        }
    }
    if (line.find("error:") == std::string::npos && line.find("warning:") == std::string::npos &&
        line.find("note:") == std::string::npos) return;
    static const std::regex located(R"(^(.+):([0-9]+):([0-9]+):\s*(fatal error|error|warning|note):\s*(.*)$)");
    static const std::regex global(R"(^(?:(.*?):\s*)?(fatal error|error|warning|note):\s*(.*)$)");
    std::smatch match;
    auto data = JsonValue::ObjectValue();
    std::string severity, message;
    if (std::regex_match(line, match, located)) {
        auto source = std::filesystem::path(Win32Process::ToWide(match[1].str()));
        if (source.is_relative() && !working_directory_.empty()) source = working_directory_ / source;
        data.Set("file", JsonValue::String(Win32Process::ToNarrow(source.lexically_normal().wstring())));
        data.Set("line", JsonValue::Number(match[2].str()));
        data.Set("column", JsonValue::Number(match[3].str()));
        severity = match[4].str();
        message = match[5].str();
    } else if (std::regex_match(line, match, global)) {
        if (match[1].matched) data.Set("tool", JsonValue::String(RedactDiagnosticText(match[1].str())));
        severity = match[2].str();
        message = match[3].str();
    } else return;
    if (severity == "fatal error") severity = "error";
    if (severity == "note" && !previous_diagnostic_.empty()) {
        data.Set("related_diagnostic_id", JsonValue::String(previous_diagnostic_));
    }
    const auto id = NewOperationId();
    if (severity != "note") previous_diagnostic_ = id;
    data.Set("diagnostic_id", JsonValue::String(id));
    data.Set("message", JsonValue::String(RedactDiagnosticText(std::move(message))));
    data.Set("severity", JsonValue::String(severity));
    context_->Emit("diagnostic", std::move(data), severity == "note" ? "info" : severity);
}

} // namespace OpenFruit
