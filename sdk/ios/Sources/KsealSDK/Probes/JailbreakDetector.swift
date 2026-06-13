import Foundation

/// Detects jailbreak: known package-manager/app artifacts, relinked system
/// directories, a broken sandbox (write outside the container), and injected
/// dynamic libraries.
struct JailbreakDetector: Probe {
    let id = "jailbreak"
    private let env: DeviceEnvironment

    init(_ env: DeviceEnvironment) { self.env = env }

    func evaluate() -> Set<RiskSignal> {
        var signals = Set<RiskSignal>()

        if hasJailbreakArtifact() || hasSuspiciousSymlink() || env.canWriteOutsideSandbox() {
            signals.insert(.jailbreak)
        }
        if env.environmentVariable("DYLD_INSERT_LIBRARIES") != nil {
            // Library injection is both an environment risk and a hook vector.
            signals.insert(.environment)
        }
        return signals
    }

    private func hasJailbreakArtifact() -> Bool {
        Self.artifactPaths.contains { env.fileExists($0) }
    }

    private func hasSuspiciousSymlink() -> Bool {
        Self.relinkedPaths.contains { env.isSymlink($0) }
    }

    static let artifactPaths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/var/jb",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/bin/bash",
        "/bin/sh",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/stash",
        "/usr/libexec/cydia",
        "/usr/libexec/sftp-server",
        "/Library/MobileSubstrate/CydiaSubstrate.dylib",
    ]

    static let relinkedPaths = [
        "/Applications",
        "/Library/Ringtones",
        "/Library/Wallpaper",
        "/usr/include",
        "/usr/libexec",
        "/usr/share",
    ]
}
