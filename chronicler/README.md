# Chronicler

Chronicler is a esp-idf component designed to create a persistent log of static-sized events, with optional synchronization.

## Design

The Chronicler lives on a single unenecrypted esp_partition.
This partition is on a SPI flash and thus has 2 features:
1. All overlapping writes are "and-ed" together.
2. There is a sector, i.e. a minimum unit that can be erased. Erasing sets all bits to 1, which write cannot.

The schema is as follows:

For each event 4 bits of metadata are kept:

```c
struct record_meta_t {
    uint8_t persisting_started : 1;
    uint8_t persisting_finished : 1;
    uint8_t should_sync : 1;
    uint8_t synced : 1;
};
```

These flags are inverted (do to how flash-behaves)

These metadata are stored at the beginning of each sector.

Thus `sector_size / (event_size + 0.5)` bytes can be stored in each sector.

Additionally first 2 sectors are special, as they contain information about the whole scheme.

These two contain bitmap of used blocks as well as aditional information about the partition:

For each sector, two bits are stored in the bitmap:

```c
typedef enum {
    CHRON_SEC_STARTED = 1U << 0,
    CHRON_SEC_SYNCED  = 1U << 1,
} chron_sector_flags_t;
```

```c
struct sector_meta_t {
    uint32_t magic;
    uint32_t version;
    uint32_t entry_size;
    uint32_t all_zeros; // Watermark for "initialized", has to be written separately from header
    uint8_t  bitmap[];
};
```

Two copies of `sector_meta_t` exist at the head of the partition.
The data copy currently in use is inferred from the pattern of its bitmap rather than a dedicated “active” flag (details below).

### Operations

Only aligned 32-bit writes are assumed atomic. (Techically there no guarantees at all, but this is as close as we can get...)
Every state transition must therefore be a 1 ➜ 0 write, with sector erases used whenever a field needs to return to 1.

#### Formatting

1. Erase meta A, meta B, and the first data sector.
2. Program meta A header fields (`entry_size`, block count, etc.) using 32-bit stores; leave its bitmap erased (all 1s).
3. Issue a separate 32-bit write that clears the `all_zeros`/“initialized” word. This write must happen only after every preceding header word is programmed so the flag can be used to detect torn updates.
4. Leave meta B erased. With both bitmaps blank, either can be selected on boot.
5. All data sectors stay erased; formatting is complete.

#### Loading

1. Check if at least one meta slot is initialized, if not -> fail
2. Pick active slot:
    - if only one slot is initialized -> choose this one
    - if both are initialized, use the following algorithm:
        1. One bitmap all 1s, other partial (some 0s) -> partial slot is active.
        2. One bitmap all 0s, other partial -> partial copy is live; the all-0 copy indicates we have wrapped at least once.
        3. Both bitmaps all 1s -> freshly formatted; pick first, erase first data block
        4. Both bitmaps all 0s -> pick one
3. Find head in active slot

#### Push

1. if not enough space in current block:
    1. if no free sectors available:
        1. erase & initialize inactive meta slot (see formatting 2. and 3.)
    2. erase next free slot
    3. mark the sector as used in bitmap
2. Clear `persisting_started` (and optionally `should_sync`) in the record metadata word.
3. Write payload bytes.
4. Clear `persisting_finished`.
5. (Optionally) After external sync completes, clear `synced`.

