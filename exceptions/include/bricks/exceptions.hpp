#pragma once

#include <esp_err.h>
#include <esp_log.h>
#include <esp_system.h>

#include <exception>
#include <stdexcept>
#include <string>
#include <source_location>
#include <concepts>
#include <utility>

namespace bricks::exceptions {

class TracedException {
private:
    std::source_location _location;

public:
    TracedException(std::source_location location = std::source_location::current())
        : _location(location) {}

    virtual ~TracedException() noexcept = default;

    std::source_location location() const noexcept {
        return _location;
    }
};

template<std::derived_from<std::exception> TBase = std::exception>
class Exception : public TBase, public TracedException {
    using Base = TBase;

    mutable std::string _what_cache;
    mutable const char* _what_ptr = nullptr;

public:
    explicit Exception(Base&& base, std::source_location loc = std::source_location::current())
        : Base(std::move(base))
        , TracedException(loc) {}

    explicit Exception(const Base& base, std::source_location loc = std::source_location::current())
        : Base(base)
        , TracedException(loc) {}

    const char* what() const noexcept override {
        if (_what_ptr) return _what_ptr;
        try {
            _what_cache.clear();
            _what_cache += Base::what();
            auto loc = location();
            _what_cache += " at ";
            _what_cache += loc.file_name();
            _what_cache += ':';
            _what_cache += std::to_string(loc.line());
            _what_cache += ':';
            _what_cache += std::to_string(loc.column());
            _what_ptr = _what_cache.c_str();
            return _what_ptr;
        } catch (...) {
            return Base::what();
        }
    }
};

template <class E>
    requires std::derived_from<std::remove_cvref_t<E>, std::exception>
Exception(
    E&&,
    std::source_location = std::source_location::current()
) -> Exception<std::remove_cvref_t<E>>;

namespace detail {
    static constexpr const char* g_tag = "exception";
} // namespace detail

class IDF : public std::exception {
protected:
    esp_err_t   _err;
    const char* _expr;

    mutable std::string _what_cache;
    mutable const char* _what_ptr = nullptr;

public:
    explicit IDF(esp_err_t code, const char* expr = nullptr)
        :  _err(code)
        , _expr(expr ? expr : "") {}

    esp_err_t code()        const noexcept { return _err; }
    const char* expression() const noexcept { return _expr; }

    const char* what() const noexcept override {
        if (_what_ptr) return _what_ptr;
        try {
            _what_cache.clear();
            _what_cache += esp_err_to_name(_err);
            _what_cache += " (";
            _what_cache += std::to_string(static_cast<int>(_err));
            _what_cache += ")";
            if (_expr && *_expr) {
                _what_cache += " in ";
                _what_cache += _expr;
            }
            _what_ptr = _what_cache.c_str();
            return _what_ptr;
        } catch (...) {
            _what_ptr = esp_err_to_name(_err);
            return _what_ptr;
        }
    }
};

class InvalidState : public std::logic_error {
public:
    explicit InvalidState(const std::string& what)
        : std::logic_error(what) {}
};

inline void terminate_handler() {
    try {
        std::exception_ptr eptr{std::current_exception()};

        if (eptr)
            std::rethrow_exception(eptr);

        else
            ESP_LOGI(detail::g_tag, "Exiting without exception");

    } catch (const std::exception& e) {
        std::string out = LOG_ANSI_COLOR(LOG_ANSI_COLOR_RED) "Caught exception:\n" LOG_ANSI_COLOR(LOG_ANSI_COLOR_RED);
        out += e.what();
        out += LOG_ANSI_COLOR_RESET;
        esp_system_abort(out.c_str());

    } catch (...) {
        esp_system_abort(LOG_ANSI_COLOR(LOG_ANSI_COLOR_RED) "Caught an unknown exception" LOG_ANSI_COLOR_RESET);
    }

    std::exit(EXIT_FAILURE);
}

inline void setup_handler() {
    using namespace detail;
    std::set_terminate(terminate_handler);

    static constexpr const char* tag = "exception";

    ESP_LOGI(tag, "Initialized custom terminate handler for better exception print-outs.");
}

} // namespace bricks::exceptions

#define CHECK_IDF_ERROR(x)                   \
    do {                                     \
        using namespace bricks::exceptions;  \
        esp_err_t __err = (x);               \
        if (unlikely(__err != ESP_OK)) {     \
            throw Exception(IDF(__err, #x)); \
        }                                    \
    } while (0)
