import Foundation

/// The toolchain binaries available for binary hardening, resolved once.
///
/// `strip`/`nm` ship with every Clang/LLVM toolchain (Linux included), while
/// `otool`/`lipo` are Apple-only. Callers use `isAppleToolchain` to decide
/// whether Mach-O-specific steps run or skip cleanly.
public struct ToolEnvironment {
    public let strip: String?
    public let nm: String?
    public let otool: String?
    public let lipo: String?

    public init(strip: String?, nm: String?, otool: String?, lipo: String?) {
        self.strip = strip
        self.nm = nm
        self.otool = otool
        self.lipo = lipo
    }

    /// True when the Apple Mach-O tooling (`otool` + `lipo`) is present.
    public var isAppleToolchain: Bool { otool != nil && lipo != nil }

    public static func detect(using runner: ProcessRunning = SystemProcessRunner()) -> ToolEnvironment {
        ToolEnvironment(
            strip: runner.which("strip"),
            nm: runner.which("nm"),
            otool: runner.which("otool"),
            lipo: runner.which("lipo")
        )
    }
}

/// Outcome of stripping a binary.
public struct SymbolStripResult: Equatable {
    public let symbolsBefore: Int
    public let symbolsAfter: Int
    public let stripTool: String
    public let flags: [String]

    public var removedSymbols: Int { max(symbolsBefore - symbolsAfter, 0) }

    public init(symbolsBefore: Int, symbolsAfter: Int, stripTool: String, flags: [String]) {
        self.symbolsBefore = symbolsBefore
        self.symbolsAfter = symbolsAfter
        self.stripTool = stripTool
        self.flags = flags
    }
}

public enum SymbolHardenerError: Error, CustomStringConvertible {
    case stripUnavailable
    case binaryMissing(String)
    case stripFailed(String)

    public var description: String {
        switch self {
        case .stripUnavailable:
            return "no `strip` tool found on PATH"
        case .binaryMissing(let path):
            return "binary not found: \(path)"
        case .stripFailed(let detail):
            return "strip failed: \(detail)"
        }
    }
}

/// Performs symbol + metadata stripping on a compiled binary using only the
/// public toolchain. App Store-safe: `strip -x` removes local/debug symbols
/// (standard release hygiene) and the linker dead-strip flags drop unreachable
/// code — both are documented, accepted release optimizations, not private-API
/// tricks.
public struct SymbolHardener {
    private let runner: ProcessRunning

    public init(runner: ProcessRunning = SystemProcessRunner()) {
        self.runner = runner
    }

    /// Flags passed to `strip`. `-x` removes non-global (local) symbols, which
    /// strips the bulk of internal names a reverse-engineer would key off while
    /// preserving the global symbols dynamic linking needs.
    public func stripFlags() -> [String] { ["-x"] }

    /// Standard linker flags an integrator adds to "Other Linker Flags" so the
    /// linker dead-strips unreachable code and removes local symbols at link
    /// time. These are public, documented `ld`/`clang` flags.
    public func recommendedLinkerFlags() -> [String] {
        ["-Xlinker", "-dead_strip", "-Xlinker", "-x"]
    }

    /// Counts symbols in `binary` via `nm`. Returns 0 when `nm` is unavailable
    /// or the binary has no symbol table (already stripped).
    public func symbolCount(of binary: URL, env: ToolEnvironment) -> Int {
        guard let nm = env.nm else { return 0 }
        guard let result = try? runner.run(nm, arguments: [binary.path]) else { return 0 }
        guard result.succeeded else { return 0 }
        return result.standardOutput
            .split(separator: "\n")
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .count
    }

    /// Strips `binary` in place. Throws when `strip` is unavailable or fails;
    /// callers on a non-Apple host should gate on `ToolEnvironment` first.
    @discardableResult
    public func strip(binary: URL, env: ToolEnvironment) throws -> SymbolStripResult {
        guard let strip = env.strip else { throw SymbolHardenerError.stripUnavailable }
        guard FileManager.default.fileExists(atPath: binary.path) else {
            throw SymbolHardenerError.binaryMissing(binary.path)
        }
        let before = symbolCount(of: binary, env: env)
        let flags = stripFlags()
        let result = try runner.run(strip, arguments: flags + [binary.path])
        guard result.succeeded else {
            throw SymbolHardenerError.stripFailed(result.standardError.isEmpty ? result.standardOutput : result.standardError)
        }
        let after = symbolCount(of: binary, env: env)
        return SymbolStripResult(symbolsBefore: before, symbolsAfter: after, stripTool: strip, flags: flags)
    }

    /// Reads the tool version line (best effort) for the build-proof manifest.
    public func toolVersion(_ executable: String) -> String? {
        guard let result = try? runner.run(executable, arguments: ["--version"]), result.succeeded else {
            return nil
        }
        return result.standardOutput.split(separator: "\n").first.map(String.init)?
            .trimmingCharacters(in: .whitespaces)
    }
}
