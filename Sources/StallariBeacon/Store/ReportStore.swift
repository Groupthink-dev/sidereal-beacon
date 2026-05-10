import Foundation

// MARK: - Errors

/// Errors thrown by ``ReportStore`` operations.
public enum ReportStoreError: Error, Sendable {
    case directoryCreationFailed(path: String, underlying: Error)
    case writeFailed(reportId: String, underlying: Error)
    case readFailed(path: String, underlying: Error)
    case reportNotFound(reportId: String)
    case deleteFailed(reportId: String, underlying: Error)
    case cryptoUnavailable
}

// MARK: - ReportStore protocol

/// Persists ``BeaconReport`` instances pending user-gated outbound flush.
///
/// Conforming types implement durable storage of beacon reports. FabricNerve
/// ships ``FileReportStore`` as the default (JSON files on disk). Daemon
/// integrations in ``stallari-harness`` provide an encrypted-at-rest
/// implementation (``EncryptedReportStore`` in StallariKit, SQLCipher-backed
/// via DD-247). External SDK consumers MAY conform their own backend.
///
/// All methods are `async throws` so conforming types may be actors *or*
/// classes with internal synchronisation around a shared connection.
///
/// **DD-270 substrate.** This protocol replaces the original concrete
/// `actor ReportStore` from FabricNerve 0.x. The dependency inversion lets
/// FabricNerve preserve its zero-external-deps invariant while StallariKit
/// supplies the daemon's encrypted persistence layer.
///
/// **External SDK consumers.** If you don't provide a `reportStore` to
/// ``Beacon/configure(appVersion:component:customScrubPatterns:outboundGate:reportStore:pathResolver:)``,
/// a file-backed ``FileReportStore`` is used. Encrypted persistence (SQLCipher)
/// lives in `stallari-harness/StallariKit` and is not available to external
/// SDK consumers — bring your own ``ReportStore`` if you need durable
/// encrypted storage.
public protocol ReportStore: Sendable {
    /// Writes a report to the pending queue.
    func save(_ report: BeaconReport) async throws

    /// Returns all pending reports, newest first.
    func listPending() async throws -> [BeaconReport]

    /// Returns all sent reports.
    func listSent() async throws -> [BeaconReport]

    /// Finds a report by ID in either pending or sent.
    /// Returns `nil` if no report with the given ID exists.
    func get(_ reportId: String) async throws -> BeaconReport?

    /// Deletes a report by ID.
    func delete(_ reportId: String) async throws

    /// Moves a report from pending to sent.
    func markSent(_ reportId: String) async throws

    /// Deletes sent reports older than `days` days. Returns count deleted.
    @discardableResult
    func pruneSent(olderThan days: Int) async throws -> Int

    /// Removes all reports.
    func deleteAll() async throws

    /// Returns the number of reports awaiting send.
    func pendingCount() async throws -> Int
}

public extension ReportStore {
    /// Convenience overload — prunes sent reports older than 30 days.
    @discardableResult
    func pruneSent() async throws -> Int {
        try await pruneSent(olderThan: 30)
    }
}
