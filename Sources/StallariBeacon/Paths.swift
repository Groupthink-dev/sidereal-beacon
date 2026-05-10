import Foundation

// MARK: - BeaconPaths

/// FabricNerve's path-resolution façade.
///
/// Consults a singleton ``PathResolving`` instance (default
/// ``DefaultPathResolver``). The harness installs `StallariPathResolver` at
/// process start via ``BeaconPaths/configure(resolver:)`` so paths land in
/// DD-252's well-known list.
///
/// **Concurrency.** The resolver pointer is protected by an `NSLock` — reads
/// from any thread are safe; configuration is intended as a one-shot at
/// process start (last writer wins on the rare re-configuration case).
///
/// **DD-270 Phase A.** Replaces the hard-coded
/// `~/.config/stallari/beacon/` derivation in FabricNerve 0.x. All four
/// SDK FS sites (``ReportStore`` defaults, ``BeaconConfig``,
/// ``InstallID``, ``CrashCollector`` staging) now route through this façade.
public enum BeaconPaths {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var _resolver: PathResolving = DefaultPathResolver()

    /// Install a custom resolver. Intended to be called once at process start.
    ///
    /// The call is idempotent — subsequent calls replace the resolver (last
    /// writer wins). Concurrent reads via ``directory(for:)`` are safe at all
    /// times.
    public static func configure(resolver: PathResolving) {
        lock.lock()
        defer { lock.unlock() }
        _resolver = resolver
    }

    /// The current resolver. Thread-safe.
    public static var resolver: PathResolving {
        lock.lock()
        defer { lock.unlock() }
        return _resolver
    }

    /// Resolve a path kind to a directory URL.
    ///
    /// Path computation is pure — never throws. Directory *creation* is the
    /// caller's concern (and is where I/O errors arise).
    public static func directory(for kind: PathKind) -> URL {
        resolver.directory(for: kind)
    }
}
