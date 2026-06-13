/* Translation unit for the CKseal C-interop target.
 *
 * The actual declarations come from the cbindgen-generated kseal.h (copied in
 * by scripts/build-rust-host.sh / the xcframework build). This file exists only
 * so SwiftPM has a compilable source for the target; the kseal_* symbols are
 * provided by libkseal_ffi (linked via the package's linker settings). */
#include "kseal.h"
