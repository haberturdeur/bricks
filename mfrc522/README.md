# mfrc522

MFRC522 ESP-IDF component with software-SPI transport and typed 32-bit record sessions.

## State API

Each record type must be exactly 32 bits (`sizeof(T) == 4`) and trivially copyable.

```cpp
using State = bricks::StateBuilder<RecordA, bricks::vector<RecordC>>;

bricks::mfrc522::Reader reader(pinout, 48); // total card pages
reader.init();

if (reader.new_card_present()) {
    bricks::mfrc522::TypedSession<State> state = reader.start_session<State>();

    std::optional<RecordA> a = state.read<RecordA>();
    std::optional<RecordC> c0 = state.read<RecordC>(0);

    // Bounds helper for vector-tail region
    std::size_t max_n = state.max_vector_records();

    RecordC next{/* ... */};
    bool ok = state.write<RecordC>(7, next); // false if out of range, else write + verify readback
}
```

`bricks::eager<T>` marks the record page of `T` as eager-loaded at session start.
(1 record = 1 page = 32 bits)
