#pragma once

#include "esp_event_base.h"
#include "exceptions.hpp"

#include <esp_event.h>

#include <functional>
#include <cstdint>
#include <mutex>
#include <type_traits>
#include <memory>
#include <utility>
#include <list>
#include <any>

namespace bricks::events {

template<typename T, typename... Ts>
struct index_of;

template<typename T, typename... Ts>
struct index_of<T, T, Ts...> : std::integral_constant<std::size_t, 0> {};

template<typename T, typename U, typename... Ts>
struct index_of<T, U, Ts...>
    : std::integral_constant<std::size_t, 1 + index_of<T, Ts...>::value> {};

template<typename T, typename... Ts>
constexpr std::size_t index_of_v = index_of<T, Ts...>::value;

template<typename T, typename E = int>
concept BaseConcept = requires {
    { T::template contains<E>() } -> std::convertible_to<bool>;
};

template<typename E, typename Base>
concept EventOfBase = BaseConcept<Base, E> && Base::template contains<E>();

template<const esp_event_base_t& BaseSymbol, typename... Events>
struct Base {
    static inline const esp_event_base_t base_value = BaseSymbol;

    template<typename E>
    static consteval bool contains() {
        return (std::same_as<E, Events> || ...);
    }

    template<EventOfBase<Base> E>
    static consteval int32_t id() {
        static_assert(contains<E>(),
                      "Event type E is not part of this Base");
        return static_cast<int32_t>(index_of_v<E, Events...>);
    }
};

namespace detail {

struct EventLoopImpl {
    EventLoopImpl() = default;

    virtual void post(esp_event_base_t event_base,
                      std::int32_t event_id,
                      const void *event_data,
                      std::size_t event_data_size,
                      TickType_t ticks_to_wait) = 0;

    virtual void post_isr(esp_event_base_t event_base,
                          std::int32_t event_id,
                          const void *event_data,
                          std::size_t event_data_size,
                          BaseType_t *task_unblocked) = 0;

    virtual esp_event_handler_instance_t register_handler(esp_event_base_t event_base,
                                                          std::int32_t event_id,
                                                          esp_event_handler_t event_handler,
                                                          void *event_handler_arg) = 0;

    virtual void unregister_handler(esp_event_base_t base, std::int32_t event_id, esp_event_handler_instance_t handler) = 0;

    virtual ~EventLoopImpl() = default;
};

class DefaultEventLoopImpl : public EventLoopImpl {
private:
    static inline bool _initialized = false;

public:

    static void create() {
        if (_initialized)
            throw std::runtime_error("DefaultEventLoopImpl already created");

        CHECK_IDF_ERROR(esp_event_loop_create_default());
        _initialized = true;
    }

    static void destroy() {
        if (!_initialized)
            return;

        CHECK_IDF_ERROR(esp_event_loop_delete_default());
        _initialized = false;
    }

    DefaultEventLoopImpl() = default;

    void post(esp_event_base_t base,
              std::int32_t id,
              const void *data,
              std::size_t data_size,
              TickType_t ticks_to_wait) override {
        CHECK_IDF_ERROR(esp_event_post(base, id, data, data_size, ticks_to_wait));
    }

    void post_isr(esp_event_base_t base,
                  std::int32_t id,
                  const void *data,
                  std::size_t data_size,
                  BaseType_t *task_unblocked) override {
        CHECK_IDF_ERROR(esp_event_isr_post(base, id, data, data_size, task_unblocked));
    }

    esp_event_handler_instance_t register_handler(esp_event_base_t base,
                                                  std::int32_t id,
                                                  esp_event_handler_t handler,
                                                  void *arg) override {
        esp_event_handler_instance_t instance;
        CHECK_IDF_ERROR(esp_event_handler_instance_register(base, id, handler, arg, &instance));
        return instance;
    }

    void unregister_handler(esp_event_base_t base,
                            std::int32_t id,
                            esp_event_handler_instance_t handler) override {
        CHECK_IDF_ERROR(esp_event_handler_instance_unregister(base, id, handler));
    }
};

class BasicEventLoopImpl : public EventLoopImpl {
public:
    explicit BasicEventLoopImpl(esp_event_loop_args_t args) {
        CHECK_IDF_ERROR(esp_event_loop_create(&args, &_event_loop));
    }

    void run(TickType_t ticks_to_run) {
        CHECK_IDF_ERROR(esp_event_loop_run(_event_loop, ticks_to_run));
    }

    void post(esp_event_base_t base,
              std::int32_t id,
              const void *data,
              std::size_t data_size,
              TickType_t ticks_to_wait) override {
        CHECK_IDF_ERROR(esp_event_post_to(_event_loop, base, id, data, data_size, ticks_to_wait));
    }

    void post_isr(esp_event_base_t base,
                  std::int32_t id,
                  const void *data,
                  std::size_t data_size,
                  BaseType_t *task_unblocked) override {
        CHECK_IDF_ERROR(esp_event_isr_post_to(_event_loop, base, id, data, data_size, task_unblocked));
    }

    esp_event_handler_instance_t register_handler(esp_event_base_t base,
                                                  std::int32_t id,
                                                  esp_event_handler_t handler,
                                                  void *arg) override {
        esp_event_handler_instance_t instance;
        CHECK_IDF_ERROR(esp_event_handler_instance_register_with(_event_loop, base, id, handler, arg, &instance));
        return instance;
    }

    void unregister_handler(esp_event_base_t base,
                            std::int32_t id,
                            esp_event_handler_instance_t handler) override {
        CHECK_IDF_ERROR(esp_event_handler_instance_unregister_with(_event_loop, base, id, handler));
    }

    ~BasicEventLoopImpl() override {
        ESP_ERROR_CHECK(esp_event_loop_delete(_event_loop));
    }

private:
    esp_event_loop_handle_t _event_loop{};
};

template <typename>
struct _FuncFromPtr;

template <typename R, typename... Args>
struct _FuncFromPtr<R(*)(Args...)> {
    using type = std::function<R(Args...)>;
};

template <typename T>
using FuncFromPtr = typename _FuncFromPtr<T>::type;

} // namespace detail


template<BaseConcept... Bases>
class EventLoop {
public:
    using Handle = std::tuple<esp_event_base_t, int32_t, esp_event_handler_instance_t>;

    template<typename E>
        requires((Bases::template contains<E>() || ...))
    using Handler = void(*)(const E&);

private:
    template<typename E, typename First, typename... Rest>
    struct base_for_impl {
        using type = std::conditional_t<
            First::template contains<E>(),
            First,
            typename base_for_impl<E, Rest...>::type>;
    };

    template<typename E, typename Last>
    struct base_for_impl<E, Last> {
        static_assert(Last::template contains<E>(),
                      "Event type not registered in any supplied Base");
        using type = Last;
    };

    template<typename E>
    using base_for_t = typename base_for_impl<E, Bases...>::type;

    std::unique_ptr<detail::EventLoopImpl> _impl;

    explicit EventLoop(detail::EventLoopImpl* impl)
        : _impl(impl) {}

    template<typename E>
    static void adapter(void* arg, esp_event_base_t, int32_t, void* data) {
        auto* fn = (Handler<E>)(arg); // Technically UB, but should work on POSIX per specs
        (*fn)(*static_cast<const E*>(data));
    }

public:
    static EventLoop create_default() {
        detail::DefaultEventLoopImpl::create();
        return EventLoop(new detail::DefaultEventLoopImpl{});
    }

    static EventLoop create_basic(esp_event_loop_args_t args) {
        return EventLoop(new detail::BasicEventLoopImpl(args));
    }

    template<typename E>
        requires((Bases::template contains<E>() || ...))
    Handle on(esp_event_handler_t handler, void* data) {
        using Selected = base_for_t<E>;

        esp_event_handler_instance_t hinst =
            _impl->register_handler(Selected::base_value,
                                    Selected::template id<E>(),
                                    handler,
                                    data);

        return { Selected::base_value,
                 Selected::template id<E>(),
                 hinst };
    }

    template<typename E>
        requires((Bases::template contains<E>() || ...))
    Handle on(Handler<E> handler) {
        using Selected = base_for_t<E>;

        esp_event_handler_instance_t hinst =
            _impl->register_handler(Selected::base_value,
                                    Selected::template id<E>(),
                                    &adapter<E>,
                                    (void*)(handler)); // Technically UB, but should work on POSIX per specs

        return { Selected::base_value,
                 Selected::template id<E>(),
                 hinst };
    }

    void off(const Handle& handle) {
        auto [base, id, instance] = handle;
        _impl->unregister_handler(base, id, instance);
    }

    template<typename E>
        requires((Bases::template contains<E>() || ...))
    void post(const E& ev,
              TickType_t ticks = portMAX_DELAY) {
        using Selected = base_for_t<E>;
        _impl->post(Selected::base_value,
                    Selected::template id<E>(),
                    &ev, sizeof(E), ticks);
    }

    template<typename E>
        requires((Bases::template contains<E>() || ...))
    void post_isr(const E& ev, BaseType_t* task_unblocked) {
        using Selected = base_for_t<E>;
        _impl->post_isr(Selected::base_value,
                        Selected::template id<E>(),
                        &ev, sizeof(E), task_unblocked);
    }

    template<typename E>
        requires((Bases::template contains<E>() || ...))
    static consteval int32_t id() {
        using Selected = base_for_t<E>;
        return Selected::template id<E>();
    }
};

template<BaseConcept... Bases>
class EventLoopManaged {
private:
    struct Node {
        esp_event_base_t base;
        std::int32_t id;
        esp_event_handler_instance_t instance;

        std::any fn;
    };

    using Storage = std::list<Node>;

public:
    using Handle = Storage::const_iterator;

private:
    template<typename E>
    using FnStore = std::function<void(const E&)>;

    template<typename E, typename First, typename... Rest>
    struct base_for_impl {
        using type = std::conditional_t<
            First::template contains<E>(),
            First,
            typename base_for_impl<E, Rest...>::type>;
    };

    template<typename E, typename Last>
    struct base_for_impl<E, Last> {
        static_assert(Last::template contains<E>(),
                      "Event type not registered in any supplied Base");
        using type = Last;
    };

    template<typename E>
    using base_for_t = typename base_for_impl<E, Bases...>::type;

    template<typename E>
    static void adapter(void* arg, esp_event_base_t, int32_t, void* data) {
        Node* node = static_cast<Node*>(arg);
        auto fn = std::any_cast<FnStore<E>>(node->fn);
        fn(*static_cast<const E*>(data));
    }

    std::unique_ptr<detail::EventLoopImpl> _impl;
    std::list<Node> _store;

    std::mutex _mutex;

    explicit EventLoopManaged(detail::EventLoopImpl* impl)
        : _impl(impl) {}

public:
    static EventLoopManaged create_default() {
        detail::DefaultEventLoopImpl::create();
        return EventLoopManaged(new detail::DefaultEventLoopImpl{});
    }

    static EventLoopManaged create_basic(esp_event_loop_args_t args) {
        return EventLoopManaged(new detail::BasicEventLoopImpl(args));
    }

    template<typename E, typename Fn>
        requires((Bases::template contains<E>() || ...))
    Handle on(Fn&& user_cb) {
        std::scoped_lock l(_mutex);

        using Selected = base_for_t<E>;
        using FunT     = FnStore<E>;
        std::any fn    = FunT(std::forward<Fn>(user_cb));

        auto it = _store.insert(_store.end(), {
            Selected::base_value,
            Selected::template id<E>(),
            {},
            fn
        });

        esp_event_handler_instance_t inst =
            _impl->register_handler(Selected::base_value,
                                    Selected::template id<E>(),
                                    &adapter<E>,
                                    &*it);
        it->instance = inst;

        return it;

    }

    void off(const Handle& handle) {
        std::scoped_lock l(_mutex);

        auto [base, id, instance, _] = *handle;
        _impl->unregister_handler(base, id, instance);
        _store.erase(handle);
    }

    template<typename E>
        requires((Bases::template contains<E>() || ...))
    void post(const E& ev, TickType_t ticks = portMAX_DELAY) {
        using Selected = base_for_t<E>;
        _impl->post(Selected::base_value,
                    Selected::template id<E>(),
                    &ev, sizeof(E), ticks);
    }

    template<typename E>
        requires((Bases::template contains<E>() || ...))
    void post_isr(const E& ev, BaseType_t* task_unblocked) {
        using Selected = base_for_t<E>;
        _impl->post_isr(Selected::base_value,
                        Selected::template id<E>(),
                        &ev, sizeof(E), task_unblocked);
    }

    template<typename E>
        requires((Bases::template contains<E>() || ...))
    static consteval int32_t id() {
        using Selected = base_for_t<E>;
        return Selected::template id<E>();
    }
};

namespace utils {

template<typename T, std::int32_t Event>
struct Unique : T {};

} // namespace utils

} // namespace bricks::events


