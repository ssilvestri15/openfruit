#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace openib {

enum class Severity { Info, Warning, Error };

struct Diagnostic {
    Severity severity{Severity::Info};
    std::string code;
    std::string message;
    std::string file;
    std::size_t line{0};
};

class Diagnostics {
public:
    void add(Severity severity, std::string code, std::string message,
             std::string file = {}, std::size_t line = 0) {
        items_.push_back({severity, std::move(code), std::move(message), std::move(file), line});
    }

    void info(std::string code, std::string message, std::string file = {}, std::size_t line = 0) {
        add(Severity::Info, std::move(code), std::move(message), std::move(file), line);
    }

    void warn(std::string code, std::string message, std::string file = {}, std::size_t line = 0) {
        add(Severity::Warning, std::move(code), std::move(message), std::move(file), line);
    }

    void error(std::string code, std::string message, std::string file = {}, std::size_t line = 0) {
        add(Severity::Error, std::move(code), std::move(message), std::move(file), line);
    }

    [[nodiscard]] bool has_errors() const {
        for (const auto& item : items_) {
            if (item.severity == Severity::Error) return true;
        }
        return false;
    }

    [[nodiscard]] const std::vector<Diagnostic>& items() const { return items_; }

private:
    std::vector<Diagnostic> items_;
};

class OpenIBError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

} // namespace openib
