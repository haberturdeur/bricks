#pragma once

#include <esp_err.h>
#include <esp_log.h>

#include <stdexcept>
#include <string>
#include <source_location>

namespace bricks::exceptions {

class Exception : public std::runtime_error {
private:
    const char* _expr;
    std::source_location _location;

public:

    explicit Exception(const char* what_arg, const char* expr = nullptr, std::source_location location = std::source_location::current())
        : std::runtime_error(what_arg)
        , _expr(expr)
        , _location(location) {}

    explicit Exception(const std::string& what_arg, const char* expr = nullptr, std::source_location location = std::source_location::current())
        : std::runtime_error(what_arg)
        , _expr(expr)
        , _location(location) {}

    virtual ~Exception() noexcept {}

    const char* expression() const noexcept {
        return _expr;
    }

    virtual std::source_location location() const noexcept {
        return _location;
    }
};

namespace detail {
    static constexpr const char* g_tag = "exception";
};

class IDF : public Exception {
protected:
    esp_err_t m_err;

public:
    explicit IDF(esp_err_t code, const char* expr = nullptr, std::source_location location = std::source_location::current())
        : Exception(std::string(esp_err_to_name(code)) + " (" + std::to_string(code) + ")", expr, location)
        , m_err(code) {}

    virtual esp_err_t code() const noexcept { return m_err; }
};

void setup_handler() {
    using namespace detail;
    std::set_terminate([]() {
        try {
            std::exception_ptr eptr{std::current_exception()};

            if (eptr)
                std::rethrow_exception(eptr);

            else
                ESP_LOGI(g_tag, "Exiting without exception");

        } catch (const Exception& e) { 
            ESP_LOGE(g_tag, "%s%s%s @ %s:%u:%u",
                 (e).what(),
                 (e).expression() ? " in " : "",
                 (e).expression() ? (e).expression() : "",
                 (e).location().file_name(),
                 static_cast<unsigned>((e).location().line()),
                 static_cast<unsigned>((e).location().column()));

        } catch (const std::exception& e) {
            ESP_LOGE(g_tag, "Caught exception: %s", e.what());

        } catch (...) {
            ESP_LOGE(g_tag, "Caught an unknown exception");

        }

        std::exit(EXIT_FAILURE);
    });

    static constexpr const char* tag = "exception";

    ESP_LOGI(tag, "Initialized custom terminate handler for better exception print-outs.");
}

} // namespace bricks::exceptions

#define CHECK_IDF_ERROR(x) \
    do {                                   \
        esp_err_t __err = (x);             \
        if (unlikely(__err != ESP_OK)) {   \
            throw exceptions::IDF(__err, #x); \
        }                                  \
    } while (0)

