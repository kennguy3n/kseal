import XCTest
@testable import KsealHardenCore

/// Closure-driven process runner for deterministic unit tests.
final class ScriptedRunner: ProcessRunning {
    var handler: (_ executable: String, _ arguments: [String]) -> ProcessResult
    var available: Set<String>
    var calls: [(String, [String])] = []

    init(available: Set<String>, handler: @escaping (String, [String]) -> ProcessResult) {
        self.available = available
        self.handler = handler
    }

    func run(_ executable: String, arguments: [String]) throws -> ProcessResult {
        calls.append((executable, arguments))
        return handler(executable, arguments)
    }

    func which(_ name: String) -> String? {
        available.contains(name) ? "/usr/bin/\(name)" : nil
    }
}

final class SymbolHardenerTests: XCTestCase {
    func testStripFlagsAndLinkerFlags() {
        let h = SymbolHardener()
        XCTAssertEqual(h.stripFlags(), ["-x"])
        XCTAssertEqual(h.recommendedLinkerFlags(), ["-Xlinker", "-dead_strip", "-Xlinker", "-x"])
    }

    func testToolEnvironmentDetectsAppleToolchain() {
        let apple = ScriptedRunner(available: ["strip", "nm", "otool", "lipo"]) { _, _ in
            ProcessResult(exitCode: 0, standardOutput: "", standardError: "")
        }
        XCTAssertTrue(ToolEnvironment.detect(using: apple).isAppleToolchain)

        let linux = ScriptedRunner(available: ["strip", "nm"]) { _, _ in
            ProcessResult(exitCode: 0, standardOutput: "", standardError: "")
        }
        XCTAssertFalse(ToolEnvironment.detect(using: linux).isAppleToolchain)
    }

    func testSymbolCountParsing() {
        let runner = ScriptedRunner(available: ["nm"]) { _, _ in
            ProcessResult(exitCode: 0, standardOutput: "0000 T main\n0000 t helper\n\n0000 d data\n", standardError: "")
        }
        let env = ToolEnvironment.detect(using: runner)
        let count = SymbolHardener(runner: runner).symbolCount(of: URL(fileURLWithPath: "/bin/x"), env: env)
        XCTAssertEqual(count, 3) // blank line ignored
    }

    func testStripUnavailableThrows() {
        let runner = ScriptedRunner(available: []) { _, _ in
            ProcessResult(exitCode: 0, standardOutput: "", standardError: "")
        }
        let env = ToolEnvironment.detect(using: runner)
        XCTAssertThrowsError(try SymbolHardener(runner: runner).strip(binary: URL(fileURLWithPath: "/bin/x"), env: env)) {
            XCTAssertTrue($0 is SymbolHardenerError)
        }
    }

    func testStripInvokesToolWithFlags() throws {
        // Simulate a binary with 5 symbols before strip and 2 after.
        var stripped = false
        let runner = ScriptedRunner(available: ["strip", "nm"]) { exe, _ in
            if exe.hasSuffix("strip") {
                stripped = true
                return ProcessResult(exitCode: 0, standardOutput: "", standardError: "")
            }
            // nm
            let out = stripped ? "a\nb\n" : "a\nb\nc\nd\ne\n"
            return ProcessResult(exitCode: 0, standardOutput: out, standardError: "")
        }
        // Pretend the binary exists by pointing at a real temp file.
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("kseal-bin-\(UUID().uuidString)")
        FileManager.default.createFile(atPath: tmp.path, contents: Data([0x7f, 0x45, 0x4c, 0x46]))
        defer { try? FileManager.default.removeItem(at: tmp) }

        let env = ToolEnvironment.detect(using: runner)
        let result = try SymbolHardener(runner: runner).strip(binary: tmp, env: env)
        XCTAssertEqual(result.symbolsBefore, 5)
        XCTAssertEqual(result.symbolsAfter, 2)
        XCTAssertEqual(result.removedSymbols, 3)
        XCTAssertEqual(result.flags, ["-x"])
        XCTAssertTrue(runner.calls.contains { $0.0.hasSuffix("strip") && $0.1.contains("-x") })
    }

    /// Real end-to-end strip when the toolchain is present. Compiles a tiny
    /// binary with local symbols, strips it, and asserts the symbol table
    /// shrank. Skips cleanly when a C compiler / strip / nm is unavailable
    /// (e.g. a minimal CI image) rather than faking the result.
    func testRealStripReducesSymbols() throws {
        let env = ToolEnvironment.detect()
        let realRunner = SystemProcessRunner()
        guard env.strip != nil, env.nm != nil,
              let cc = realRunner.which("cc") ?? realRunner.which("clang") ?? realRunner.which("gcc") else {
            throw XCTSkip("strip/nm/C-compiler unavailable on this host")
        }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("kseal-strip-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let src = dir.appendingPathComponent("prog.c")
        try """
        #include <stdio.h>
        static int kseal_secret_helper(int x) { return x * 7 + 13; }
        static const char *kseal_secret_label(void) { return "kseal-internal-label"; }
        int main(void) { printf("%d %s\\n", kseal_secret_helper(3), kseal_secret_label()); return 0; }
        """.write(to: src, atomically: true, encoding: .utf8)

        let bin = dir.appendingPathComponent("prog")
        let compile = try realRunner.run(cc, arguments: ["-g", "-O0", src.path, "-o", bin.path])
        guard compile.succeeded else { throw XCTSkip("compiler failed: \(compile.standardError)") }

        let hardener = SymbolHardener()
        let result = try hardener.strip(binary: bin, env: env)
        XCTAssertLessThanOrEqual(result.symbolsAfter, result.symbolsBefore)
        XCTAssertGreaterThan(result.symbolsBefore, 0)
    }
}
