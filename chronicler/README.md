# Chronicler

Chronicler is an ESP-IDF component that maintains a persistent, append-only log of variable-size events, with optional synchronization state.

## Storage Model

Chronicler uses a single unencrypted `esp_partition` on SPI flash.

Flash characteristics assumed:

1. Program is bitwise AND: overlapping writes are effectively `old_bit & new_bit`.
2. Erase granularity is a sector: erasing sets all bits to `1`. Programming can only change `1 ➜ 0` (never `0 ➜ 1`).

## On-Flash Schema

Each record is self-delimiting and stores its payload plus a 2-byte header and a 1-byte trailer:

```c
typedef struct {
    uint16_t length_flags; // low 12 bits = payload length, high 4 bits = flags
} record_header_t;
```

The CRC8 byte is the write-finished marker: erased flash has `crc8 == 0xFF`, and a record is considered complete only once the CRC8 byte is programmed and validates. This allows torn writes to be detected without a separate "started/finished" flag.

`length_flags` layout (bit 0 is LSB):
* bits 0..11: `length` (0..4095)
* bits 12..15: `flags` (stored inverted; 1 = cleared, 0 = set)

Flag assignment:
* bit 12: `should_sync`
* bit 13: `synced`
* bit 14: `crc_escaped`
* bit 15: `entry_disposable`

ASCII layouts (on-disk):

Record layout (byte offsets relative to record start):

+--------+------+----------------------+------------------------------+
| Offset | Size | Field                | Notes                        |
+--------+------+----------------------+------------------------------+
| 0      | 1    | length_flags[7:0]    | length_flags LSB             |
| 1      | 1    | length_flags[15:8]   | length_flags MSB             |
| 2      | N    | payload              | N = length (0..4095)         |
| 2 + N  | 1    | crc8                 | CRC8 over payload+length     |
+--------+------+----------------------+------------------------------+

length_flags bit layout (bit 0 is LSB):

+------------------+-------------+--------+-------------+---------+
| 15               | 14          | 13     | 12          | 11 .. 0 |
| entry_disposable | crc_escaped | synced | should_sync | length  |
+------------------+-------------+--------+-------------+---------+

Because NOR flash erases to `1` and programs to `0`, flag bits are stored inverted (i.e., programming a 0 asserts the flag). The CRC8 byte is written as a normal byte and must be distinguishable from the erased value. If the computed CRC8 is `0xFF`, store `0xFE` and set `crc_escaped`; on read, treat `0xFE` with `crc_escaped` set as `0xFF`.

CRC is computed over the payload and the 12-bit length field only (flags masked out). This allows `synced` to be updated later without invalidating CRC.

### Per-sector header (data sectors)

Each data sector begins with two bytes of per-sector metadata:

```
uint8_t session_id;
uint8_t sector_flags;
```

The session ID is an 8-bit value for grouping or session tracking. The 8-bit flags are application-defined.

Layout order within a data sector is:
1. Per-sector header (2 bytes)
2. Variable-length record stream

Data sector layout (byte offsets relative to sector start):

### Capacity per Sector

Capacity is variable because entry sizes vary. A sector is filled by appending records sequentially until the next record header+payload would exceed the sector boundary.

### Global Metadata (“meta slots”)

The first two sectors of the partition are reserved for global metadata. Each sector contains a `sector_meta_t`. Two copies exist (“meta A” and “meta B”) to allow atomic-ish updates via copy-and-swap.

```c
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint8_t  initialized;  // initialization watermark; written AFTER header bytes
    uint8_t  old;          // old watermark; use the second slot
    uint8_t  bitmap[];     // 4 bits per data sector (USED, FULL_AND_SYNCED, DISPOSABLE, RESERVED), stored inverted
} sector_meta_t;
```

Bitmap bits per data sector:
* `USED` – sector is allocated/entered.
* `FULL_AND_SYNCED` – all required entries in the sector are synced (optional).
* `DISPOSABLE` – sector is safe to delete/erase early.
* `RESERVED` – unused (for alignment/future use).

Metadata sector layout (byte offsets relative to sector start):

+--------+------+------------------+------------------------------+
| Offset | Size | Field            | Notes                        |
+--------+------+------------------+------------------------------+
| 0      | 4    | magic            | uint32                       |
| 4      | 4    | version          | uint32 (currently 1)         |
| 8      | 1    | initialized      | 0x00 means initialized       |
| 9      | 1    | old              | 0x00 means old slot          |
| 10     | ...  | bitmap           | 4 bits per data sector       |
+--------+------+------------------+------------------------------+

Bitmap packing (nibbles, stored inverted):

+---------------+---------------+
| Byte (i) high | Byte (i) low  |
+---------------+---------------+
| sector (2i+1) | sector (2i)   |
+---------------+---------------+

Nibble bit layout (bit 0 is LSB):

+------------+--------------+----------------+----------+
| bit 3      | bit 2        | bit 1          | bit 0    |
| reserved   | disposable   | full_and_synced| used     |
+------------+--------------+----------------+----------+

Two copies of `sector_meta_t` live at the head of the partition. There is no explicit “active” flag; the active copy is inferred from the pattern of its bitmap (details under Loading).

## Atomicity and State Transitions

All control bytes are updated with 8-bit reads/writes. Every state transition is performed by programming 1 ➜ 0; returning to 1 requires a sector erase.

## Operations

### Formatting (fresh partition or reinitialize)

1. Erase meta A, meta B, and the first data sector.
2. Program meta A header fields (`magic`, `version`, etc.) using 8-bit stores; leave its bitmap erased (all 1s).
3. Arm the initialization watermark: issue a separate byte write that programs `0x00`. This must occur only after all header bytes are programmed so torn updates can be detected.
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
3. Find the head (append position) in the active layout by scanning the current sector’s records starting at the record-stream offset (after the per-sector header):
   * Parse `length_flags`, extract `length`, then validate bounds.
   * If `length == 0` or the record would exceed the remaining sector space, stop.
   * Read the CRC8 byte at the end of the record; if it is `0xFF` (erased), stop.
   * If `crc_escaped` is set, treat stored `0xFE` as CRC `0xFF`.
   * CRC mismatch terminates the log for that sector.

Session filtering: all public APIs operate only on sectors whose `session_id` matches the session passed to `load(...)` / `create(...)`.
When `dispose_other_sessions` is enabled, any used sector with a different `session_id` is marked `DISPOSABLE` on startup.

### Push (append one record)

1. Ensure space in the current data sector:
   * If the current sector is full:
     * If no free data sectors remain:
       * Mark active slot as old
       * Switch meta slots: erase and initialize the inactive meta (see Formatting steps 2–3). This begins a new cycle.
     * Erase the next free data sector.
     * Mark the sector used in the active meta bitmap (program `USED` bit to 0).
2. Begin record: write `length_flags` (with `should_sync` cleared if required), then write payload bytes.
3. Finish record: compute CRC8, set `crc_escaped` if needed, then program the CRC8 byte (this is the write-finished flag). If CRC8 is `0xFF`, store `0xFE`.
4. Optional sync handling: if the entry is marked `should_sync` and a sync callback is registered via `Chronicler::set_sync_callback`, the callback runs immediately with the entry bytes. After external sync completes, program `synced` to 0. When an entire sector’s records have `synced=0` where required, you may decide to program the sector’s `FULL_AND_SYNCED` bit in the meta bitmap to 0; `Chronicler::sweep_synced_sector` implements this lazily (one sector per call) so you can treat it like a lightweight GC.

### Disposal / GC

When an entry is safe to delete early, program its `entry_disposable` flag bit to 0. Once all entries in a sector are marked `entry_disposable`, the sector is automatically marked `DISPOSABLE` in the meta bitmap. You can also explicitly mark a sector as disposable via the public API; GC only erases sectors with the `DISPOSABLE` bit programmed.

## Notes and Invariants

* Flags are inverted on flash: “flag set” in logical terms means the corresponding bit on flash is 0.
* Bitmap bits are also inverted (erased = 1 = unknown or unused; programmed = 0 = asserted).
* Control writes are byte-sized; no 32-bit alignment is required.
* CRC8 bytes must be distinguishable from the erased value (`0xFF`) to act as a write-finished marker.
* Metadata version is currently `1`.
* Zero-length entries are invalid; pushes must reject them.
* Erases are the only way to return bits to 1; plan sector lifetimes accordingly.
* The active meta is always the one whose bitmap most plausibly reflects the latest allocation state (per Loading rules).
* Public `Chronicler` methods are serialized with a single mutex; the sync callback runs after releasing that mutex.

## ESP-IDF Apps

* `example/` – minimal usage demo that appends, reads back, and syncs entries. Run with `idf.py -C example flash monitor`.
* `test_apps/` – Unity-based integration tests for the component. Run with `idf.py -C test_apps flash monitor`.
