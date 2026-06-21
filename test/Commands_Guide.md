# Automated tests

The project registers automated correctness and negative tests through CTest.
The test cases execute the same compiled CLI binaries that are delivered to the
user, so they also validate command routing, dependency linkage, exit codes and
fail-closed behaviour.

## Configure and build

```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --config Release
```

## Run every test

```bash
ctest --test-dir build --output-on-failure
```

For a multi-configuration generator on Windows:

```powershell
ctest --test-dir build -C Release --output-on-failure
```

## Run one laboratory only

```bash
ctest --test-dir build -L Lab1 --output-on-failure
ctest --test-dir build -L Lab3 --output-on-failure
ctest --test-dir build -L Lab4 --output-on-failure
ctest --test-dir build -L Lab5 --output-on-failure
ctest --test-dir build -L Lab6 --output-on-failure
```

## Registered positive suites

- `Lab1_KAT`: NIST AES known-answer tests.
- `Lab1_SelfTest`: GCM tamper/wrong-key/wrong-AAD rejection and CTR round trip.
- `Lab3_OAEP_SelfTest`: OAEP round trips, wrong-label rejection and tamper rejection.
- `Lab4_Hash_KAT`: SHA-2, SHA-3 and SHAKE known-answer tests.
- `Lab5_Signature_SelfTest`: ECDSA correctness, modified message, modified signature and wrong-key rejection.
- `Lab6_PQC_SelfTest`: ML-DSA and ML-KEM correctness and negative tests.

Each lab also has a `Rejects_Unknown_Command` test. These tests pass only when
the executable returns a non-zero status for malformed command input.
