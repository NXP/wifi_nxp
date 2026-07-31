# AGENTS Guidelines for This Repository

This repository contains the NXP Wi-Fi driver for FreeRTOS-based MCU SDK platforms. Portability across RTOS platforms, maintainability, and code quality are top priorities. When working on the project interactively with an agent, please follow the guidelines below.
 
## General Guidelines

- This project is fully self-contained; do not create or modify files outside of this repository
- **Stay within the project directory**: do not generate output files outside of this repository
- **Avoid large edits**: make smaller, incremental changes
- **If output is truncated**: always continue from where it was truncated; do not restart from the beginning
- **Multi-chip support**: the driver supports multiple chip variants — always consider impact on all supported chips
- **Platform support**: supports SDIO, UART, and IMU bus interfaces
 
## Code Style

- **Indentation**: 4 spaces — never tabs
- **Line length**: maximum 120 characters
- **Brace style**: Allman — opening `{` always on its own line for all constructs
- **Variables**: declared at the top of the function block, before any statements
- **Pointer * binds to the variable name**: `int *ptr`, not `int* ptr`
- static on all file-local functions and variables
- `(void)` cast on intentionally ignored return values
- Consecutive `#define` values should be vertically aligned
- No floating point in driver code
 
## Language Standard

- C99/C03 compatible
- **Fixed-width types preferred**: `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `t_u8`, `t_u16`, `t_u32`
 
## Naming Conventions

- **Functions/variables**: lowercase_with_underscores (snake_case)
- **Macros/constants**: UPPER_CASE
- **Static functions**: Mark functions that are only used within a file as static
- **Public API prefixes**: `wlan_` for connection manager, `wifi_` for driver level
- **Types**: snake_case_t suffix for typedefs
 
## Code Quality

- **Always use OSA APIS**: The OSA (Operating System Abstraction) layer is the mechanism that allows the same codebase to run on FreeRTOS and Zephyr. Never call FreeRTOS primitives directly
- LwIP APIs and structs are confined to `port/net` and `incl/port/net` only
- **No printf in driver code** - use module logging macros: `wifi_e()`, `wifi_w()`, `wifi_d()`, `wlcm_e()`, `wlcm_d()`, `wifi_io_e()`, `wifi_io_d()` PRINTF() is only acceptable in example/application code.
- Check all return values from OSA calls, memory allocations, and any API that can fail
- **No magic numbers**: define named constants with `#define` or `enum`
- `goto fail` / `goto done` for cleanup on error paths in functions that allocate multiple resources
- **FreeRTOS / Zephyr Cross-Applicability**: This repository serves both FreeRTOS (wifi_nxp_gh, release/*) and Zephyr (develop/zephyr_upstream_gh). Changes must be evaluated for applicability to both platforms.
- Always remember to add license header for new files.
- Always run code coverity check: All changes should be free of high impact risk. Run code-quality-ai skill for automated MISRA C-2012 / CERT-C / CWE analysis. 
- C++ Compatibility for Public Headers: All public header files (files under `incl/`) must be wrapped with extern "C" guards to ensure they can be included from C++ translation units
  ```c
  #ifdef __cplusplus
  extern "C" {
  #endif
  ```
 
## 64-bit Compatibility

The driver must compile and run correctly on both 32-bit and 64-bit (AArch64) platforms.
- Never cast a pointer to a fixed-width 32-bit integer; use `uintptr_t`
- Integer ↔ `void*` conversions must go through `uintptr_t`
- Use `%zu` for `sizeof()` and `size_t` in format strings
- Use `%p` for pointer values in format strings
- Do not use `uint32_t`/`t_u32` variables to hold pointer addresses
- Function parameters that carry pointer-sized data must use `uintptr_t`
- Alignment mask operations on pointers must use `uintptr_t`
- Do NOT flag these — they are correct:
  - `(int)(uintptr_t)x` — correct double-cast to extract integer from `void*`
  - `(void *)(uintptr_t)x` — correct double-cast to store integer in `void*`
  - `(uint32_t)some_enum` — integer-to-integer cast, not a pointer cast
 
## Comment Format - `wlan.h`

- All public APIs, structs, enums, and macros in `incl/wlcmgr/wlan.h` must use Doxygen /** ... */ comments with backslash tags only (`\param`, `\return`, `\note`, `\ref`, `\a` — never @-style).
- Struct field / enum member / macro: single-line `/** Brief description. */` immediately above the declaration.
- `\param` direction: `\param[in]`, `\param[out]`, `\param[in,out]`; always a colon after the parameter name
- One `\return` line per possible return value
- Use `\ref` TypeName to cross-reference types; `\a param_name` to italicize a parameter name inline
 
## Error Handling

- Return `MLAN_STATUS_SUCCESS`/`MLAN_STATUS_FAILURE` for driver-internal functions
- Check return values and handle all error cases
- Validate input parameters at function entry
 
## Functions

- Keep functions focused and reasonably sized
- Break complex functions into smaller helper functions
- Mark functions static when they're not used outside the file
- Use inline sparingly and only for very small, performance-critical functions
- Mark unused parameters with `(void)param`;
 
## Memory Management

- No large local variables on the stack: stack space is severely limited on MCU targets. Avoid large local arrays or structs
- Use OSA API for memory allocation/free: `OSA_MemoryAllocate()`/`OSA_MemoryFree()`
- Always check allocation results for NULL
- Free resources in reverse order of allocation
- Initialize allocated memory when needed
- Avoid memory leaks - ensure all allocated memory is freed on error paths
 
## Project Structure

- `wifidriver/`          # Core Wi-Fi driver: firmware download, command/event, data path
   - `mlan_*.c`          # MLAN (MAC layer) — chip-agnostic 802.11 logic
   - `wifi.c`            # Main driver entry, task management
   - `wifi-sdio.c`       # SDIO bus interface
   - `wifi-imu.c`        # IMU bus interface
   - `wpa_supp_if/`      # wpa_supplicant integration
   - `incl/`             # Internal MLAN headers
- `wlcmgr/`              # WLAN connection manager
- `incl/`                # Public headers
- `port/`                # Platform port layer
   - `osa/`              # OSA implementation (FreeRTOS and Zephyr backends)
   - `net/`              # Network stack integration
- `cli/`                 # CLI framework
- `dhcpd/`               # DHCP server for uAP mode
- `nw_utils/`            # Network utility functions
- `firmware_dnld/`       # Firmware download abstraction
- `fwdnld_intf_abs/`     # Firmware download interface abstraction
- `wmcrypto/`            # Crypto utilities
- `example/`             # Example applications
 
## Version Control

- Write clear, descriptive commit messages. Commit message format:
  ```c
  <one-line title>
  [Description]
  [Root Cause]
  [Fix]
  [Testing]
  Change-Id: <id>
  ```
- Wrap commit messages at 75 characters
- Use bullet points to summarize changes when appropriate
- Write commit messages in imperative mood
- **Do not include internal JIRA IDs in commit titles or bodies** — this repo is mirrored to GitHub
- **Do not use internal SoC nicknames in commit messages** — use official product names only
 
## Static Analysis

- Fix all warnings before committing
- Be aware of common issues:
  - Endianness problems (use `cpu_to_le32()`, `le32_to_cpu()`, etc.)
  - NULL pointer dereferences
  - Memory leaks
  - Lock ordering issues
  - Race conditions
 
## Documentation

- **User Manual Update**: If a PR modifies any APIs in wlan.h or test command, the corresponding user manuals must be updated.
 
## Common Pitfalls to Avoid

- Don't call FreeRTOS APIs directly — use OSA wrappers
- Don't declare large arrays or structs as local variables
- Make sure changes are 64-bit compatibility
- Don't call lwIP APIs outside `port/net` and `incl/port/net`
- Don't ignore return values from functions that can fail
- Don't add new public APIs to wlan.h without Doxygen comments and user manual updates
- Don't add new public headers without `extern "C"` guards
