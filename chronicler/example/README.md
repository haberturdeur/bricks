# Chronicler Example (C)

Small ESP-IDF app that drives the `bricks_chronicler` C API end-to-end
against the first `ESP_PARTITION_TYPE_DATA` partition discovered on the target.
All verification happens on-device via logging; no host interaction required.

## Test flow

1. **Partition lookup** – resolves the data partition and aborts early if not found.
2. **Fresh chronicler** – formats the partition via `bricks_chronicler_create`
   for an entry size (first 4 bytes, then 200 bytes) and registers a sync-request
   callback.
3. **Push & wrap** – appends `capacity + 32` sequential payloads (every third
   entry marked `should_sync`). Confirms reported size equals the expected number
   of retained entries after wrap, plus spot-checks oldest/newest/middle records.
4. **Iterator check** – walks every stored entry with `bricks_chronicler_iter_*`
   to ensure the iterator returns entries in order and matches the predicted values.
5. **Sync bookkeeping** – reads all unsynced entries via
   `bricks_chronicler_get_unsynced`, marks them synced, and verifies the count
   drops to zero.
6. **Dump & reload** – copies the entire log into RAM, destroys the handle,
   re-opens it with `bricks_chronicler_load_or_create`, and byte-compares the
   reloaded entries against the dump. Logs how many times the sync callback fired.

## Building & running

```bash
idf.py -C example set-target esp32   # or other target
idf.py -C example flash monitor
```

Ensure your partition table exposes a writable data partition large enough
for the chronicler metadata plus several data sectors.
