# Chronicler Usage Example

Small ESP-IDF app that demonstrates how to use the `bricks_chronicler` C++ API
in a normal firmware. It finds a writable data partition (preferring the
`storage` label), appends a few structured entries, logs them back out, and then
marks sync-required entries as synced.

The project uses `partitions.csv` to expose a `storage` data partition for the
log.

## Building & running

```bash
idf.py -C example set-target esp32   # or other target
idf.py -C example flash monitor
```

Watch the monitor output to see entries being appended, replayed, and marked
synced.
