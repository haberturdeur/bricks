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

```c
struct sector_meta_t {
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

#### Append (block already allocated)

1. Clear `persisting_started` (and optionally `should_sync`) in the record metadata word.
2. Write payload bytes.
3. Clear `persisting_finished`.
4. After external sync completes, clear `synced`.

#### Allocate a new block

1. Sector-erase the block to return metadata + payload area to 1s.
2. Clear the block’s bitmap bit.
3. Append records using the sequence above.

#### Wrap / reclaim

1. Treat blocks as a ring; when the head reaches the end, wrap to block 0.
2. Skip blocks whose bitmap bit is 0.
   If the head cannot find a 1, erase the oldest sector whose entries are already `synced`.
3. After the erase, that sector’s blocks read as 1 again and become eligible for reuse.

#### Metadata generations

Boot chooses the live metadata copy solely from the bitmaps:

1. One bitmap all 1s, other partial (some 0s) → partial copy is live.
2. One bitmap all 0s, other partial → partial copy is live; the all-0 copy indicates we have wrapped at least once.
3. Both bitmaps all 1s → freshly formatted; pick either.
4. Both bitmaps all 0s → pick one, erase + reinitialize it, treat the other as stale.

Publishing a new generation:

1. Select the metadata sector whose bitmap is all 1s (unused) or all 0s (retired). If it is all 0s, erase it now.
2. Write header fields with 32-bit stores, stopping before the `all_zeros` flag.
3. Copy the in-RAM bitmap into the sector by clearing bits for allocated blocks.
4. Commit the header by issuing a dedicated 32-bit write that clears `all_zeros`. Since this word is written last, a partially updated header is detected because the flag will remain 0xFFFF'FFFF.
5. Switch the writer to the new generation. The previously live bitmap can be lazily driven toward all 0s (or left alone if already 0); on the next rotation it becomes the “retired” candidate in step 1.
