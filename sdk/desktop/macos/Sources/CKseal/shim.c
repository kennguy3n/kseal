/* Translation unit for the CKseal C-interop target.
 *
 * The declarations come from the cbindgen-generated kseal.h (staged by
 * scripts/build-rust-host.sh / the xcframework build). This file exists only so
 * SwiftPM has a compilable source for the target; the kseal_* symbols are
 * provided by the kseal-ffi shared library (linked via the package's linker
 * settings). */
#include "kseal.h"
