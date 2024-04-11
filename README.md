This is a wrapper for Open SSL keys.

For now this wrapper only supports ECDSA keys.

---
## Dependencies
- [OpenSSL](https://www.openssl.org/)
- [CMake](https://cmake.org/)

## Installation
```bash
# This will build and create an install folder that can be used in other projects.
./build.sh
```

## Usage
```cmake
list(APPEND CMAKE_PREFIX_PATH "/path/to/OsslEcKey/install")
find_package(OsslEcKey REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE ossl::OsslKey)
```

```cpp
#include <OsslKey/OsslEcKey.h>
#include <OsslKey/OsslResult.h>

OsslKey::OsslEcKey key;
// To generate a fresh key pair.
OsslKey::OsslResult result = key.GenerateKeyPair();
if (result != OsslKey::OsslResult::Success) {
    // Handle error.
}
```
