# Chronicler

Chronicler is an ESP-IDF component that maintains a persistent, append-only log of fixed-size events, with optional synchronization state.

## Storage Model

Chronicler uses a single unencrypted `esp_partition` on SPI flash.

Flash characteristics assumed:

1. Program is bitwise AND: overlapping writes are effectively `old_bit & new_bit`.
2. Erase granularity is a sector: erasing sets all bits to `1`. Programming can only change `1 ➜ 0` (never `0 ➜ 1`).

## On-Flash Schema

Each record stores its payload plus 4 bits of per-record metadata:

```c
typedef struct {
    uint8_t persisting_started  : 1;
    uint8_t persisting_finished : 1;
    uint8_t should_sync         : 1;
    uint8_t synced              : 1;
} record_meta_t;
```

Because NOR flash erases to `1` and programs to `0`, these flags are stored inverted:

* “Clearing/setting a flag” in software corresponds to programming a 0 on flash.
* Returning a flag to 1 requires erasing the containing sector.

Per-record metadata bits are stored in a metadata area at the start of each sector, followed by the packed record payloads. The metadata area is padded to a 32-bit boundary to guarantee aligned flash operations.

### Capacity per Sector

Let:

* `S` = sector size (bytes)
* `E` = record (entry) payload size (bytes)
* `M` = metadata bits per record (= 4)

If a sector holds `N` records, it must satisfy:

```
N * E
+ ceil( (N * M) / 8 )
≤ S
```

A practical upper bound:

```
N = floor( (8*S) / (8*E + M) )
```

### Global Metadata (“meta slots”)

The first two sectors of the partition are reserved for global metadata. Each sector contains a `sector_meta_t`. Two copies exist (“meta A” and “meta B”) to allow atomic-ish updates via copy-and-swap.

```c
typedef enum {
    CHRON_SEC_STARTED = 1U << 0,  // sector allocated/entered
    CHRON_SEC_SYNCED  = 1U << 1,  // sector’s contents externally synced
} chron_sector_flags_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t entry_size;   // == E
    uint32_t initialized;  // initialization watermark; written AFTER header words
    uint32_t old;          // old watermark; use the second slot
    uint8_t  bitmap[];     // 2 bits per data sector (CHRON_SEC_*), stored inverted
} sector_meta_t;
```

Two copies of `sector_meta_t` live at the head of the partition. There is no explicit “active” flag; the active copy is inferred from the pattern of its bitmap (details under Loading).

## Atomicity and State Transitions

Only aligned 32-bit writes are treated as “atomic enough” for control words. Every state transition is performed by programming 1 ➜ 0; returning to 1 requires a sector erase.

## Operations

### Formatting (fresh partition or reinitialize)

1. Erase meta A, meta B, and the first data sector.
2. Program meta A header fields (`magic`, `version`, `entry_size`, block/sector count, etc.) using aligned 32-bit stores; leave its bitmap erased (all 1s).
3. Arm the initialization watermark: issue a separate aligned 32-bit write that programs `all_zeros` (i.e., writes a 0). This must occur only after all header words are programmed so torn updates can be detected.
4. Leave meta B erased. With both bitmaps blank (all 1s), either slot can be selected on first boot.
5. All data sectors remain erased. Formatting is complete.

### Loading (boot or mount)

1. Validate meta slots: check whether meta A and/or meta B have the watermark (i.e., are “initialized”). If neither is initialized, fail.
2. Select active meta:
   * Only one initialized → pick that one.
   * Both initialized → use bitmap patterns:
     1. One bitmap all 1s, the other partial (some 0s) → partial is active (has seen use).
     2. One bitmap all 0s, the other partial → partial is active; all-0s indicates the log has wrapped at least once.
     3. Both all 1s → freshly formatted; pick the first and erase the first data sector to begin.
     4. Both all 0s → ambiguous but consistent; pick one deterministically (for example, A).
3. Find the head (append position) in the active layout by scanning the current sector’s per-record metadata:
   * A record with `persisting_started=0` and `persisting_finished=1` (inverted logic) is complete.
   * The first record where `persisting_started` is 1 (i.e., still erased) is the next append slot.
   * Handle torn records by the flags (see Push).

### Push (append one record)

1. Ensure space in the current data sector:
   * If the current sector is full:
     * If no free data sectors remain:
       * Mark active slot as old
       * Switch meta slots: erase and initialize the inactive meta (see Formatting steps 2–3). This begins a new cycle.
     * Erase the next free data sector.
     * Mark the sector used in the active meta bitmap (program `CHRON_SEC_STARTED` bit to 0).
2. Begin record: program to 0 the per-record bit for `persisting_started`. If the record should be synced later, also program `should_sync` to 0 here.
3. Write payload bytes (record body).
4. Finish record: program `persisting_finished` to 0.
5. Optional sync handling: if the entry is marked `should_sync` and a sync callback is registered via `Chronicler::set_sync_callback`, the callback runs immediately with the entry bytes. After external sync completes, program `synced` to 0. When an entire sector’s records have `synced=0` where required, you may decide to program the sector’s `CHRON_SEC_SYNCED` bit in the meta bitmap to 0; `Chronicler::sweep_synced_sector` implements this lazily (one sector per call) so you can treat it like a lightweight GC.

## Notes and Invariants

* Flags are inverted on flash: “flag set” in logical terms means the corresponding bit on flash is 0.
* Bitmap bits are also inverted (erased = 1 = unknown or unused; programmed = 0 = asserted).
* Only 32-bit aligned control writes are used for headers and flag transitions to minimize torn-write windows.
* Erases are the only way to return bits to 1; plan sector lifetimes accordingly.
* The active meta is always the one whose bitmap most plausibly reflects the latest allocation state (per Loading rules).

## ESP-IDF Apps

* `example/` – minimal usage demo that appends, reads back, and syncs entries. Run with `idf.py -C example flash monitor`.
* `test_apps/` – Unity-based integration tests for the component. Run with `idf.py -C test_apps flash monitor`.
