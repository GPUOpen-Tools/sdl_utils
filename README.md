# Secure Development Lifecycle Utilities (SDL Utils)

Utilities to be used as part of the Secure Development Lifecycle.

## Components

This library provides two platform-specific security utilities:

### Safe CRT (Linux)

Linux implementations of Windows secure C runtime library functions that provide bounds-checking and error handling to prevent buffer overflows and other security issues. These implementations follow the semantics of the `_s`-suffixed functions from the Windows CRT, enabling cross-platform code that uses the safer Windows API to compile and run correctly on Linux. Note that `sscanf_s` intentionally rejects `%s` and `%[` format specifiers (see table below), so this library is not a complete drop-in replacement for all Windows CRT `_s` functions.

**Functions provided:**

| Function | Description |
|---|---|
| `memcpy_s` | Safe memory copy — fails if `count > dest_size` or if source and destination regions overlap |
| `memmove_s` | Safe memory move — same validation as `memcpy_s`, handles overlapping regions |
| `strcpy_s` | Safe string copy — always null-terminates, fails on overflow |
| `strncpy_s` | Safe bounded string copy — supports `_TRUNCATE` sentinel, does not null-pad |
| `strcat_s` | Safe string append — resets dest to empty string on overflow |
| `sprintf_s` | Safe formatted string output |
| `vsnprintf_s` | Safe variadic formatted output — supports `_TRUNCATE` sentinel |
| `fprintf_s` | Safe formatted file output |
| `sscanf_s` | Safe formatted string input — `%s` and `%[` are not supported |
| `fopen_s` | Safe file open |
| `fread_s` | Safe file read |

**`_TRUNCATE` sentinel:** Several string functions accept `_TRUNCATE` as the `count` argument to truncate output on overflow rather than returning `ERANGE`. This matches Windows CRT semantics. Note that functions using `_TRUNCATE` may still return `-1` to indicate that truncation occurred (e.g., `vsnprintf_s` returns `-1` when the output is truncated), so callers that need to detect truncation should check the return value.

**Header:** `include/linux/safe_crt.h`

---

### Binary Security Check (Windows)

Header-only runtime security validation to detect proxy attacks and suspicious binary replacements by verifying digital signatures of binaries in the application installation directory and its subdirectories.

**Detection methods:**
- Invalid or tampered digital signatures on `.exe` and `.dll` files
- Reparse points (junctions/symlinks) in the application directory, which are flagged as suspicious

**Behavior:**
- Call `BinarySecurity::IsInstallationValid()` at application startup.
- First checks whether the main application EXE has a valid digital signature. If the EXE is unsigned (e.g., a development build), the scan is skipped entirely to avoid false positives.
- If the EXE signature is valid, recursively scans the application directory up to 16 levels deep.
- Signature verification of collected files is performed in parallel (up to 16 threads), with a sequential fallback if parallel verification fails.
- On a security violation, displays a `MessageBox` dialog listing suspicious files and advises the user to reinstall.
- Directory enumeration failures and maximum scan depth are also treated as security failures.

**Header:** `include/binary_security_check.h`

## Building

### Standalone build

Standard CMake build:

```bash
cmake -B build
cmake --build build
```

With an optional build number for version stamping:

```bash
cmake -B build -DSDL_UTILS_BUILD_NUMBER=<build_number>
cmake --build build
```

## Using in Your Project

### CMake Integration

Add this repository as a subdirectory in your CMakeLists.txt:

```cmake
add_subdirectory(path/to/sdl_utils)
```

Then link against the appropriate component:

**For Safe CRT (Linux):**
```cmake
target_link_libraries(your_target PRIVATE AMD::sdl_utils::safe_crt)
```

**For Binary Security (Windows):**
```cmake
target_link_libraries(your_target PRIVATE AMD::sdl_utils::binary_security)
```

The Binary Security target automatically links `wintrust`, `crypt32`, and `user32`.

### Code Usage

**Safe CRT example (Linux):**
```cpp
#include <linux/safe_crt.h>

char dest[10];
errno_t err = strcpy_s(dest, sizeof(dest), "hello");
if (err != 0) {
    // Handle error
}

// Truncate rather than fail on overflow
char buf[8];
strncpy_s(buf, sizeof(buf), "a very long string", _TRUNCATE);
```

**Binary Security example (Windows):**
```cpp
#include <binary_security_check.h>

int main() {
    if (!BinarySecurity::IsInstallationValid()) {
        // Security validation failed - dialog already shown to user
        return 1;
    }
    // Proceed with application
}
```

## Requirements

- CMake 3.25 or higher
- C++20 compiler
- Linux: GCC or Clang
- Windows: MSVC 2022 or later
