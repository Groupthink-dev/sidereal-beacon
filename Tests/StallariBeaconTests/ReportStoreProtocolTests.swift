// DD-270 — Phase A — protocolisation of ReportStore + PathResolving seam.

import Foundation
import Testing
@testable import StallariBeacon

@Suite("ReportStore protocol (DD-270 Phase A)")
struct ReportStoreProtocolTests {

    // MARK: - 1. FileReportStore conforms

    @Test("FileReportStore conforms to ReportStore protocol")
    func inMemoryStoreConformsToProtocol() async throws {
        // Use a temp dir so the default-resolved path isn't touched.
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("dd270-protocol-conformance-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let store: any ReportStore = FileReportStore(baseDirectory: tempDir)
        // Trivial sanity: protocol method dispatch reaches the concrete actor.
        let count = try await store.pendingCount()
        #expect(count == 0)
    }

    // MARK: - 2. Protocol round-trip

    @Test("Protocol-typed store round-trips enqueue → dequeue")
    func protocolRoundTrips_enqueueDequeue() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("dd270-roundtrip-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let store: any ReportStore = FileReportStore(baseDirectory: tempDir)
        let report = BeaconReport(
            type: .feedback,
            app: AppInfo(version: "0.87.2.0", component: "test"),
            system: SystemInfo.current(),
            payload: .feedback(FeedbackReport(message: "round-trip"))
        )

        try await store.save(report)
        #expect(try await store.pendingCount() == 1)

        let fetched = try await store.get(report.reportId)
        #expect(fetched?.reportId == report.reportId)
    }

    // MARK: - 3. Injected resolver overrides default

    @Test("BeaconPaths.configure(resolver:) overrides default resolution")
    func injectedResolverOverridesDefault() {
        // Snapshot the existing resolver so other tests aren't affected by
        // this test's mutation — BeaconPaths is process-singleton state.
        let original = BeaconPaths.resolver
        defer { BeaconPaths.configure(resolver: original) }

        let probe = ProbeResolver(base: FileManager.default.temporaryDirectory
            .appendingPathComponent("dd270-resolver-probe-\(UUID().uuidString)"))
        BeaconPaths.configure(resolver: probe)

        let resolved = BeaconPaths.directory(for: .beaconRoot)
        #expect(resolved.path.hasPrefix(probe.base.path))
    }

    // MARK: - 4. PathKind coverage

    @Test("DefaultPathResolver answers every PathKind under one root")
    func pathKindCoverage() {
        let resolver = DefaultPathResolver()
        let root = resolver.directory(for: .beaconRoot)
        let staging = resolver.directory(for: .beaconCrashStaging)
        let outbox = resolver.directory(for: .beaconOutbox)

        // Staging + outbox both live under root.
        #expect(staging.path.hasPrefix(root.path))
        #expect(outbox.path.hasPrefix(root.path))

        // Distinct subdirectories.
        #expect(staging.lastPathComponent == "crash-staging")
        #expect(outbox.lastPathComponent == "outbox")

        // Root sits under "Stallari/Beacon" per the DD-270 memo layering.
        #expect(root.pathComponents.contains("Stallari"))
        #expect(root.pathComponents.contains("Beacon"))
    }
}

// MARK: - Test helpers

/// Test resolver — every PathKind resolves under a single test-supplied base.
private struct ProbeResolver: PathResolving {
    let base: URL

    func directory(for kind: PathKind) -> URL {
        switch kind {
        case .beaconRoot: return base
        case .beaconCrashStaging: return base.appendingPathComponent("crash-staging", isDirectory: true)
        case .beaconOutbox: return base.appendingPathComponent("outbox", isDirectory: true)
        }
    }
}
