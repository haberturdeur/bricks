# mfrc522 test_apps

IDF build smoke test for the `mfrc522` component.

## Run

```bash
idf.py -C test_apps set-target esp32s3
idf.py -C test_apps build
```

This validates that the component and its dependencies compile with `idf.py`.
