import Foundation

// MARK: - PathKind

/// Identifiers for the well-known directories FabricNerve consults.
///
/// Resolvers map these to concrete absolute URLs. The default resolver writes
/// under `~/Library/Application Support/Stallari/Beacon/`. Harness-side
/// integrations inject `StallariPathResolver` so paths land in DD-252's
/// well-known list (`~/Library/Application Support/Stallari/...`).
///
/// **DD-270 Phase A.** New protocol-based path injection seam — replaces the
/// hard-coded `~/.config/stallari/beacon/` derivation in FabricNerve 0.x.
public enum PathKind: Sendable, Hashable {
    /// Root directory for SDK persistence — pending reports, sent reports,
    /// `config.json`, `install_id`.
    case beaconRoot

    /// Staging directory for POSIX-crash marker files (written from signal
    /// handlers via async-signal-safe POSIX calls).
    case beaconCrashStaging

    /// Encrypted outbox directory — consumed by StallariKit's
    /// ``EncryptedReportStore`` for the daemon-side SQLCipher store.
    /// The default resolver still computes a sensible path here so external
    /// SDK consumers can wrap their own implementation if needed.
    case beaconOutbox
}

// MARK: - PathResolving

/// Resolves a ``PathKind`` to an absolute directory URL.
///
/// FabricNerve ships ``DefaultPathResolver`` writing under
/// `~/Library/Application Support/Stallari/Beacon/`. Harness-side integrations
/// inject a richer resolver bridging to `StallariPaths` for DD-252 well-known
/// path compliance.
///
/// Path computation MUST NOT throw — the protocol is pure. Directory creation
/// is the caller's concern (and is where I/O errors arise).
public protocol PathResolving: Sendable {
    func directory(for kind: PathKind) -> URL
}

// MARK: - DefaultPathResolver

/// Default ``PathResolving`` implementation. Writes under
/// `~/Library/Application Support/Stallari/Beacon/`.
///
/// External SDK consumers that need a different base directory should
/// implement their own ``PathResolving`` and pass it to
/// ``BeaconPaths/configure(resolver:)`` at process start.
public struct DefaultPathResolver: PathResolving {

    public init() {}

    public func directory(for kind: PathKind) -> URL {
        let appSupport: URL
        if let url = try? FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: false
        ) {
            appSupport = url
        } else {
            // Synthetic fallback — should never happen in practice on macOS/iOS.
            appSupport = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support", isDirectory: true)
        }

        let beaconRoot = appSupport
            .appendingPathComponent("Stallari", isDirectory: true)
            .appendingPathComponent("Beacon", isDirectory: true)

        switch kind {
        case .beaconRoot:
            return beaconRoot
        case .beaconCrashStaging:
            return beaconRoot.appendingPathComponent("crash-staging", isDirectory: true)
        case .beaconOutbox:
            return beaconRoot.appendingPathComponent("outbox", isDirectory: true)
        }
    }
}
