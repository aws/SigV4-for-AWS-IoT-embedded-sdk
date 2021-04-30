# AWS IoT SigV4 Client library

## Building the SigV4 Library

## Building Unit Tests

### Platform Prerequisites

- For running unit tests:
    - **C90 compiler** like gcc.
    - **CMake 3.13.0 or later**.
    - **Ruby 2.0.0 or later** is additionally required for the CMock test framework (that we use).
- For running the coverage target, **gcov** and **lcov** are additionally required.

### Steps to build **Unit Tests**

1. `cd` in this repo.

1. Run the *cmake* command: `cmake -S test -B build -DBUILD_CLONE_SUBMODULES=ON`.

1. Run this command to build the library and unit tests: `make -C build all`.

1. The generated test executables will be present in `build/bin/tests` folder.

1. Run `cd build && ctest` to execute all tests and view the test run summary.

## Reference examples

The AWS IoT Embedded C-SDK repository contains [demos](https://github.com/aws/aws-iot-device-sdk-embedded-C/tree/main/demos/http) showing the use of the AWS IoT SigV4 Client Library on a POSIX platform.

## Generating documentation

The Doxygen references found in this repository were created using Doxygen
version 1.8.20. To generate these Doxygen pages, please run the following
command from the root of this repository:

```shell
doxygen docs/doxygen/config.doxyfile
```
## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on contributing.
