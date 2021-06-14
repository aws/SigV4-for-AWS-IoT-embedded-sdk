# AWS IoT SigV4 Utility Library

**Note** This library is currently under development.

The AWS IoT SigV4 Library is a standalone utility for generating a signature and authorization header according to the specifications of the [Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html) signing process. This utility is an optional addition to applications sending direct HTTP requests to AWS services requiring SigV4 authentication.

## Building the SigV4 Library

The [source](https://github.com/aws/SigV4-for-AWS-IoT-embedded-sdk/tree/main/source) directory contains all of the source files required to build the SigV4 Library. The [source/include](https://github.com/aws/SigV4-for-AWS-IoT-embedded-sdk/tree/main/source/include) folder should be added to the compiler's include path.

To use CMake, please refer to the [sigV4FilePaths.cmake](https://github.com/aws/SigV4-for-AWS-IoT-embedded-sdk/blob/main/sigv4FilePaths.cmake) file, which contains the relevant information regarding source files and header include paths required to build this library.

## Building Unit Tests

### Platform Prerequisites

- For running unit tests:
    - **C90 compiler** like gcc.
    - **CMake 3.13.0 or later**.
    - **Ruby 2.0.0 or later** is additionally required for the CMock test framework (that we use).
- For running the coverage target, **gcov** and **lcov** are additionally required.

### Steps to build **Unit Tests**

1. Go to the root directory of this repository.

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
