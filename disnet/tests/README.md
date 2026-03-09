# disnet host tests

Run without ESP hardware:

```bash
cmake -S disnet/tests -B disnet/tests/build
cmake --build disnet/tests/build
ctest --test-dir disnet/tests/build --output-on-failure
```

The test harness compiles `disnet` with lightweight host shims for ESP-IDF/FreeRTOS APIs.
