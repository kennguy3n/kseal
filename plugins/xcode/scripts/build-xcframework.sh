#!/usr/bin/env bash
#
# build-xcframework.sh — package the kseal iOS SDK as a hardened, distributable
# XCFramework and emit a build-proof.
#
# Pipeline (all public toolchain, App Store-safe — see ../../docs/ios-app-review.md):
#   1. Build the Rust trust-core XCFramework (KsealFFI) via the SDK's own script.
#   2. Archive KsealSDK for iOS device + simulator with library evolution on.
#   3. Combine slices into KsealSDK.xcframework (xcodebuild -create-xcframework).
#   4. Harden each slice: strip local/debug symbols + metadata (strip/otool).
#   5. Emit the build-proof manifest with kseal-harden (build hash, seed digest,
#      tool versions, SDK version, transforms).
#   6. Optionally register the proof with RegistryService.CreateBuild
#      (when KSEAL_REGISTRY_URL/KSEAL_API_KEY/… are set), else offline artifact.
#
# Requires macOS + Xcode for steps 1–3. On a non-Apple host the Apple-only steps
# are skipped cleanly (exit 0) so a Linux CI lane does not fail; the build-proof
# logic (steps 5–6) is still exercised by the unit/integration tests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XCODE_PLUGIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$XCODE_PLUGIN_DIR/../.." && pwd)"
SDK_IOS_DIR="$REPO_ROOT/sdk/ios"
OUT_DIR="$XCODE_PLUGIN_DIR/build"
DIST_DIR="$OUT_DIR/dist"
PROOF_DIR="$OUT_DIR/proof"

VERSION_NAME="${KSEAL_VERSION_NAME:-0.1.0}"
VERSION_CODE="${KSEAL_VERSION_CODE:-0}"
SDK_VERSION="${KSEAL_SDK_VERSION:-0.1.0}"

mkdir -p "$DIST_DIR" "$PROOF_DIR"

# --- Build the kseal-harden tool (needed for the build proof on any host). ----
echo "[xcframework] building kseal-harden"
( cd "$XCODE_PLUGIN_DIR" && swift build -c release --product kseal-harden )
HARDEN_TOOL="$XCODE_PLUGIN_DIR/.build/release/kseal-harden"

if ! command -v xcodebuild >/dev/null 2>&1; then
    echo "[xcframework] xcodebuild not found — skipping Apple-only packaging steps."
    echo "[xcframework] (run on macOS with Xcode to produce KsealSDK.xcframework)"
    exit 0
fi

# --- 1. Rust trust-core XCFramework (delegates to the SDK's build script). -----
echo "[xcframework] building KsealFFI.xcframework"
"$SDK_IOS_DIR/scripts/build-xcframework.sh"

# --- 2/3. Archive KsealSDK for device + simulator, then create the xcframework.
ARCHIVE_DIR="$OUT_DIR/archives"
rm -rf "$ARCHIVE_DIR"
mkdir -p "$ARCHIVE_DIR"

archive_slice() {
    local destination="$1" name="$2"
    echo "[xcframework] archiving KsealSDK ($name)"
    # sdk/ios is a SwiftPM package (no .xcworkspace). Run xcodebuild from inside
    # the package directory so it picks up Package.swift and the auto-generated
    # KsealSDK scheme; do NOT pass -workspace (that expects a .xcworkspace file).
    ( cd "$SDK_IOS_DIR" && xcodebuild archive \
        -scheme KsealSDK \
        -destination "$destination" \
        -archivePath "$ARCHIVE_DIR/$name.xcarchive" \
        -derivedDataPath "$OUT_DIR/DerivedData" \
        SKIP_INSTALL=NO \
        BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
        ONLY_ACTIVE_ARCH=NO )
}

archive_slice "generic/platform=iOS" "ios"
archive_slice "generic/platform=iOS Simulator" "ios-sim"

FRAMEWORK_REL="Products/Library/Frameworks/KsealSDK.framework"
rm -rf "$DIST_DIR/KsealSDK.xcframework"
xcodebuild -create-xcframework \
    -framework "$ARCHIVE_DIR/ios.xcarchive/$FRAMEWORK_REL" \
    -framework "$ARCHIVE_DIR/ios-sim.xcarchive/$FRAMEWORK_REL" \
    -output "$DIST_DIR/KsealSDK.xcframework"

# --- 4. Harden every Mach-O slice in the produced xcframeworks. ----------------
echo "[xcframework] hardening slices (strip/otool)"
while IFS= read -r -d '' macho; do
    "$SCRIPT_DIR/harden-binary.sh" "$macho" || true
done < <(find "$DIST_DIR/KsealSDK.xcframework" "$SDK_IOS_DIR/build/KsealFFI.xcframework" \
            -type f \( -name "KsealSDK" -o -name "*.a" \) -print0 2>/dev/null)

# --- 5. Emit the build proof for the packaged SDK. -----------------------------
echo "[xcframework] emitting build proof"
"$HARDEN_TOOL" generate \
    --target KsealSDK \
    --sdk-version "$SDK_VERSION" \
    --version-name "$VERSION_NAME" \
    --version-code "$VERSION_CODE" \
    --platform ios \
    --host xcframework-pipeline \
    --tool-version "xcodebuild=$(xcodebuild -version | head -n1)" \
    --tool-version "swift=$(swift --version 2>/dev/null | head -n1)" \
    --out-strings "$PROOF_DIR/KsealSecureStrings.generated.swift" \
    --out-manifest "$PROOF_DIR/kseal-build-proof.json"

# --- 6. Register the proof (offline fallback when unconfigured/unreachable). ---
echo "[xcframework] registering build proof"
"$HARDEN_TOOL" register \
    --manifest "$PROOF_DIR/kseal-build-proof.json" \
    --offline-artifact "$PROOF_DIR/kseal-build-proof.offline.json"

echo "[xcframework] done: $DIST_DIR/KsealSDK.xcframework"
echo "[xcframework] build proof: $PROOF_DIR/kseal-build-proof.json"
