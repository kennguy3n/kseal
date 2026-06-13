import Foundation

/// Result of running an external tool.
public struct ProcessResult {
    public let exitCode: Int32
    public let standardOutput: String
    public let standardError: String

    public var succeeded: Bool { exitCode == 0 }

    public init(exitCode: Int32, standardOutput: String, standardError: String) {
        self.exitCode = exitCode
        self.standardOutput = standardOutput
        self.standardError = standardError
    }
}

/// Abstraction over launching toolchain binaries so the hardening logic can be
/// exercised with a mock in tests and with the real toolchain in production.
public protocol ProcessRunning {
    func run(_ executable: String, arguments: [String]) throws -> ProcessResult
    /// Resolves an executable on `PATH`, returning its absolute path if present.
    func which(_ name: String) -> String?
}

/// Default runner backed by Foundation's `Process`.
public struct SystemProcessRunner: ProcessRunning {
    public init() {}

    public func run(_ executable: String, arguments: [String]) throws -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        try process.run()
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return ProcessResult(
            exitCode: process.terminationStatus,
            standardOutput: String(decoding: outData, as: UTF8.self),
            standardError: String(decoding: errData, as: UTF8.self)
        )
    }

    public func which(_ name: String) -> String? {
        // Absolute path passed straight through.
        if name.hasPrefix("/") {
            return FileManager.default.isExecutableFile(atPath: name) ? name : nil
        }
        let path = ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin:/usr/local/bin"
        for dir in path.split(separator: ":") {
            let candidate = String(dir) + "/" + name
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return candidate
            }
        }
        return nil
    }
}
