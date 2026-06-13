import Foundation
#if canImport(FoundationXML)
import FoundationXML
#endif

/// A dotted numeric version (`CFBundleVersion` / `sparkle:version`-style) with a
/// total order that compares component-by-component numerically, so `1.10.0`
/// correctly outranks `1.9.0`. Non-numeric components compare as 0; a missing
/// trailing component is treated as 0 so `1.2` == `1.2.0`.
public struct SemanticVersion: Comparable, Equatable, CustomStringConvertible, Sendable {
    public let raw: String
    private let components: [Int]

    public init(_ raw: String) {
        self.raw = raw
        self.components = raw
            .split(separator: ".", omittingEmptySubsequences: false)
            .map { Int($0.prefix(while: { $0.isNumber })) ?? 0 }
    }

    public var description: String { raw }

    public static func < (lhs: SemanticVersion, rhs: SemanticVersion) -> Bool {
        let count = max(lhs.components.count, rhs.components.count)
        for i in 0..<count {
            let l = i < lhs.components.count ? lhs.components[i] : 0
            let r = i < rhs.components.count ? rhs.components[i] : 0
            if l != r { return l < r }
        }
        return false
    }

    public static func == (lhs: SemanticVersion, rhs: SemanticVersion) -> Bool {
        !(lhs < rhs) && !(rhs < lhs)
    }
}

/// One Sparkle appcast entry: the version, the download enclosure's declared
/// length, the EdDSA (Ed25519) signature over the archive bytes, and an optional
/// minimum-OS gate.
public struct AppcastItem: Equatable, Sendable {
    public let version: SemanticVersion
    public let shortVersionString: String?
    public let url: String
    public let contentLength: Int
    /// Raw Ed25519 signature bytes (decoded from the appcast's base64
    /// `sparkle:edSignature`) over the **archive** bytes.
    public let edSignature: Data
    public let minimumSystemVersion: SemanticVersion?

    public init(
        version: SemanticVersion,
        shortVersionString: String? = nil,
        url: String,
        contentLength: Int,
        edSignature: Data,
        minimumSystemVersion: SemanticVersion? = nil
    ) {
        self.version = version
        self.shortVersionString = shortVersionString
        self.url = url
        self.contentLength = contentLength
        self.edSignature = edSignature
        self.minimumSystemVersion = minimumSystemVersion
    }
}

/// A parsed appcast (newest-first ordering is established by the channel, not the
/// feed, so a malformed/disordered feed cannot trick version selection).
public struct Appcast: Equatable, Sendable {
    public let items: [AppcastItem]
    public init(items: [AppcastItem]) { self.items = items }
}

/// Why a secure-update check could not produce an applicable, verified update.
/// Every case is **fail-closed**: the channel never returns an update it could
/// not fully verify.
public enum SecureUpdateError: Error, Equatable {
    /// The appcast could not be parsed.
    case malformedFeed
    /// The downloaded archive's size did not match the appcast enclosure length.
    case lengthMismatch(expected: Int, actual: Int)
    /// The EdDSA signature over the archive did not verify against the channel key.
    case signatureInvalid
    /// Notarization was required by policy but the archive was not notarized.
    case notarizationFailed
    /// The channel public key is not a valid Ed25519 key (32 bytes).
    case invalidChannelKey
}

/// Result of a secure-update check.
public enum SecureUpdateResult: Equatable {
    /// No applicable newer version is offered.
    case upToDate
    /// A newer version was offered and **fully verified**; safe to hand to the
    /// installer.
    case updateAvailable(VerifiedUpdate)
}

/// An appcast item whose archive bytes have passed every verification gate.
public struct VerifiedUpdate: Equatable, Sendable {
    public let item: AppcastItem
    public let archive: Data
}

// MARK: - External boundaries (mocked)

/// The external secure-update feed — the third-party boundary the engineering
/// rules say to mock. Production fronts an HTTPS appcast + CDN download; tests
/// inject a deterministic in-memory feed. **No network is performed by the SDK
/// itself**; the feed is the seam where the host's transport plugs in.
public protocol AppcastFeed {
    func fetchAppcast() throws -> Appcast
    func fetchArchive(for item: AppcastItem) throws -> Data
}

/// Confirms an update archive's macOS notarization — a thin seam over the
/// Gatekeeper assessment so the (Darwin-only) `SecAssessment` call is mockable.
/// Only consulted when the channel policy requires notarization.
public protocol UpdateNotaryVerifier {
    func isNotarized(archive: Data, item: AppcastItem) -> Bool
}

/// Notary that approves everything; the default when notarization is not
/// required by policy.
public struct PermissiveNotaryVerifier: UpdateNotaryVerifier {
    public init() {}
    public func isNotarized(archive: Data, item: AppcastItem) -> Bool { true }
}

/// Verifies an Ed25519 signature over `message` with `publicKey`. Defaults to
/// the real Rust-core verifier over the C ABI; injectable for isolation.
public typealias UpdateSignatureVerifier = (_ message: Data, _ signature: Data, _ publicKey: Data) -> Bool

/// The default secure-update signature verifier: Ed25519 over `message`,
/// delegated to the real Rust trust core over the C ABI (the same primitive that
/// verifies signed configs).
public func ksealEd25519Verify(_ message: Data, _ signature: Data, _ publicKey: Data) -> Bool {
    verifyConfigSignature(config: message, signature: signature, publicKey: publicKey)
}

// MARK: - Channel policy

/// Configuration for a secure-update channel.
public struct UpdateChannelPolicy {
    /// Ed25519 public key (32 bytes) the appcast EdDSA signatures must verify
    /// against — the Sparkle "EdDSA" channel key.
    public let publicKey: Data
    /// The currently running app version; only strictly-newer offers apply.
    public let currentVersion: SemanticVersion
    /// The running OS version, used to honor an item's minimum-OS gate.
    public let currentSystemVersion: SemanticVersion?
    /// When true, an offered update must additionally pass notarization (fail
    /// closed). Default false.
    public let requireNotarization: Bool

    public init(
        publicKey: Data,
        currentVersion: SemanticVersion,
        currentSystemVersion: SemanticVersion? = nil,
        requireNotarization: Bool = false
    ) {
        self.publicKey = publicKey
        self.currentVersion = currentVersion
        self.currentSystemVersion = currentSystemVersion
        self.requireNotarization = requireNotarization
    }
}

/// Verifies the integrity/signature of a Sparkle-style update channel **before**
/// anything is applied. The verification logic is real (Ed25519 EdDSA over the
/// downloaded archive, exactly Sparkle's scheme, plus length and optional
/// notarization checks); only the feed/notary are mocked. Fails closed on any
/// signature/length/notarization failure.
public final class SecureUpdateChannel {
    private let policy: UpdateChannelPolicy
    private let feed: AppcastFeed
    private let notary: UpdateNotaryVerifier
    private let verifySignature: UpdateSignatureVerifier

    public init(
        policy: UpdateChannelPolicy,
        feed: AppcastFeed,
        notary: UpdateNotaryVerifier = PermissiveNotaryVerifier(),
        verifySignature: @escaping UpdateSignatureVerifier = ksealEd25519Verify
    ) {
        self.policy = policy
        self.feed = feed
        self.notary = notary
        self.verifySignature = verifySignature
    }

    /// Selects the newest applicable item and fully verifies it. Returns
    /// `.upToDate` when nothing newer (or nothing the current OS can run) is
    /// offered; throws `SecureUpdateError` when an offered update fails any gate.
    public func checkForUpdate() throws -> SecureUpdateResult {
        guard policy.publicKey.count == 32 else { throw SecureUpdateError.invalidChannelKey }

        let appcast = try feed.fetchAppcast()
        // Newest applicable: strictly newer than current and runnable on this OS.
        let applicable = appcast.items
            .filter { $0.version > policy.currentVersion }
            .filter { canRun($0) }
            .max(by: { $0.version < $1.version })

        guard let item = applicable else { return .upToDate }

        let archive = try feed.fetchArchive(for: item)

        guard archive.count == item.contentLength else {
            throw SecureUpdateError.lengthMismatch(expected: item.contentLength, actual: archive.count)
        }
        guard verifySignature(archive, item.edSignature, policy.publicKey) else {
            throw SecureUpdateError.signatureInvalid
        }
        if policy.requireNotarization, !notary.isNotarized(archive: archive, item: item) {
            throw SecureUpdateError.notarizationFailed
        }
        return .updateAvailable(VerifiedUpdate(item: item, archive: archive))
    }

    private func canRun(_ item: AppcastItem) -> Bool {
        guard let minimum = item.minimumSystemVersion else { return true }
        guard let current = policy.currentSystemVersion else { return true }
        return current >= minimum
    }
}

// MARK: - Appcast parsing + in-memory feed

/// Parses a Sparkle appcast (RSS XML) into `AppcastItem`s. Pure, allocation-light,
/// and host-independent so it is fully unit-testable. A document that is not
/// well-formed XML throws `SecureUpdateError.malformedFeed`.
public enum AppcastParser {
    public static func parse(_ data: Data) throws -> Appcast {
        let delegate = AppcastParserDelegate()
        let parser = XMLParser(data: data)
        parser.delegate = delegate
        guard parser.parse(), !delegate.failed else { throw SecureUpdateError.malformedFeed }
        return Appcast(items: delegate.items)
    }
}

private final class AppcastParserDelegate: NSObject, XMLParserDelegate {
    var items: [AppcastItem] = []
    var failed = false

    private var inItem = false
    private var currentElement = ""
    private var text = ""
    private var version: String?
    private var shortVersion: String?
    private var minimumSystemVersion: String?
    private var url: String?
    private var length: Int?
    private var edSignature: Data?

    func parser(_ parser: XMLParser, didStartElement elementName: String,
                namespaceURI: String?, qualifiedName qName: String?,
                attributes attributeDict: [String: String]) {
        let name = localName(qName ?? elementName)
        currentElement = name
        text = ""
        if name == "item" {
            inItem = true
            version = nil; shortVersion = nil; minimumSystemVersion = nil
            url = nil; length = nil; edSignature = nil
        } else if inItem && name == "enclosure" {
            // Sparkle carries the download + signature on the enclosure element.
            url = attributeDict["url"]
            if let len = attributeDict["length"] { length = Int(len) }
            if let sig = attributeForKeySuffix(attributeDict, "edSignature") {
                edSignature = Data(base64Encoded: sig)
            }
            if version == nil, let v = attributeForKeySuffix(attributeDict, "version") {
                version = v
            }
            if shortVersion == nil, let sv = attributeForKeySuffix(attributeDict, "shortVersionString") {
                shortVersion = sv
            }
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        text += string
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String,
                namespaceURI: String?, qualifiedName qName: String?) {
        let name = localName(qName ?? elementName)
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if inItem {
            switch name {
            case "version": if !trimmed.isEmpty { version = trimmed }
            case "shortVersionString": if !trimmed.isEmpty { shortVersion = trimmed }
            case "minimumSystemVersion": if !trimmed.isEmpty { minimumSystemVersion = trimmed }
            case "item":
                inItem = false
                appendItem()
            default: break
            }
        }
        text = ""
    }

    func parser(_ parser: XMLParser, parseErrorOccurred parseError: Error) {
        failed = true
    }

    private func appendItem() {
        // An item missing the fields required to verify it is skipped rather than
        // silently trusted: only fully-formed, verifiable offers are surfaced.
        guard let version, let url, let length, let edSignature, !edSignature.isEmpty else { return }
        items.append(AppcastItem(
            version: SemanticVersion(version),
            shortVersionString: shortVersion,
            url: url,
            contentLength: length,
            edSignature: edSignature,
            minimumSystemVersion: minimumSystemVersion.map(SemanticVersion.init)
        ))
    }

    /// Strips an `ns:` prefix so the parser is namespace-agnostic.
    private func localName(_ qualified: String) -> String {
        if let colon = qualified.lastIndex(of: ":") {
            return String(qualified[qualified.index(after: colon)...])
        }
        return qualified
    }

    /// Finds an attribute whose (possibly namespace-prefixed) key ends in
    /// `suffix`, e.g. `sparkle:edSignature` for `edSignature`.
    private func attributeForKeySuffix(_ dict: [String: String], _ suffix: String) -> String? {
        for (key, value) in dict where localName(key) == suffix { return value }
        return nil
    }
}

/// An `AppcastFeed` backed by bytes already in memory — the production default
/// for hosts that fetch the appcast/archive with their own transport and hand
/// the bytes to the channel, and the deterministic feed used by tests. Parsing
/// the appcast XML and looking up the archive are real; no network is performed.
public struct InMemoryAppcastFeed: AppcastFeed {
    private let appcast: Appcast
    private let archives: [String: Data]

    /// - Parameters:
    ///   - appcastXML: the raw Sparkle appcast document.
    ///   - archives: archive bytes keyed by enclosure `url`.
    public init(appcastXML: Data, archives: [String: Data]) throws {
        self.appcast = try AppcastParser.parse(appcastXML)
        self.archives = archives
    }

    public init(appcast: Appcast, archives: [String: Data]) {
        self.appcast = appcast
        self.archives = archives
    }

    public func fetchAppcast() throws -> Appcast { appcast }

    public func fetchArchive(for item: AppcastItem) throws -> Data {
        // A missing archive is treated as a zero-length body so the channel's
        // length check fails closed rather than the feed inventing bytes.
        archives[item.url] ?? Data()
    }
}
