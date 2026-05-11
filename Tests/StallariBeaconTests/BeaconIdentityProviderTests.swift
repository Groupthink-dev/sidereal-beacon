// DD-270 Phase B (Layer A) — BeaconIdentityProvider protocol contract.

import Foundation
import Testing
@testable import StallariBeacon

// `.serialized` — these tests mutate the BeaconPaths process-singleton.
// Without serialisation, parallel tests race on `BeaconPaths.configure(resolver:)`
// and the file-backed InstallID's persist/read pair sees a different
// resolver than it just wrote against. The Phase A protocol tests don't
// hit this because they never call multiple I/O methods that depend on
// the same singleton state surviving across calls.
@Suite("BeaconIdentityProvider (DD-270 Phase B)", .serialized)
struct BeaconIdentityProviderTests {

    // MARK: - 1. FileInstallIDProvider conforms

    @Test("FileInstallIDProvider satisfies BeaconIdentityProvider")
    func fileProviderConforms() {
        // Snapshot the existing resolver so this test's mutation doesn't
        // leak. Without this, parallel suites racing on BeaconPaths.resolver
        // can break each other.
        let originalResolver = BeaconPaths.resolver
        defer { BeaconPaths.configure(resolver: originalResolver) }

        // Route paths into a per-test tempdir so the InstallID file lands
        // somewhere disposable.
        let tempBase = FileManager.default.temporaryDirectory
            .appendingPathComponent("dd270-identity-conformance-\(UUID().uuidString)")
        BeaconPaths.configure(resolver: TempResolver(base: tempBase))
        defer { try? FileManager.default.removeItem(at: tempBase) }

        let provider: any BeaconIdentityProvider = FileInstallIDProvider()
        let id = provider.installID()
        #expect(id.hasPrefix("ins_"))
        #expect(id.count == 20)
    }

    // MARK: - 2. installID is stable within a process

    @Test("FileInstallIDProvider returns the same ID across calls")
    func stableIDAcrossCalls() {
        let originalResolver = BeaconPaths.resolver
        defer { BeaconPaths.configure(resolver: originalResolver) }
        let tempBase = FileManager.default.temporaryDirectory
            .appendingPathComponent("dd270-identity-stable-\(UUID().uuidString)")
        BeaconPaths.configure(resolver: TempResolver(base: tempBase))
        defer { try? FileManager.default.removeItem(at: tempBase) }

        let provider = FileInstallIDProvider()
        let first = provider.installID()
        let second = provider.installID()
        #expect(first == second)
    }

    // MARK: - 3. reset() clears identity

    @Test("FileInstallIDProvider.reset() generates a fresh ID on next call")
    func resetGeneratesFreshID() {
        let originalResolver = BeaconPaths.resolver
        defer { BeaconPaths.configure(resolver: originalResolver) }
        let tempBase = FileManager.default.temporaryDirectory
            .appendingPathComponent("dd270-identity-reset-\(UUID().uuidString)")
        BeaconPaths.configure(resolver: TempResolver(base: tempBase))
        defer { try? FileManager.default.removeItem(at: tempBase) }

        let provider = FileInstallIDProvider()
        let original = provider.installID()
        provider.reset()
        let fresh = provider.installID()
        #expect(original != fresh)
        #expect(fresh.hasPrefix("ins_"))
    }

    // MARK: - 4. Beacon.installID() routes through injected provider

    @Test("Beacon.installID() returns the injected provider's ID")
    func beaconRoutesThroughInjectedProvider() async {
        let stub = StubIdentityProvider(stubID: "ins_stub_test_id_xx")
        let beacon = await Beacon.configure(
            appVersion: "0.87.5.0",
            component: "test",
            identityProvider: stub
        )
        let id = await beacon.installID()
        #expect(id == "ins_stub_test_id_xx")
    }

    // MARK: - 5. Default identity provider is FileInstallIDProvider

    @Test("Beacon defaults to FileInstallIDProvider when none injected")
    func beaconDefaultsToFileProvider() async {
        let originalResolver = BeaconPaths.resolver
        defer { BeaconPaths.configure(resolver: originalResolver) }
        let tempBase = FileManager.default.temporaryDirectory
            .appendingPathComponent("dd270-identity-default-\(UUID().uuidString)")
        BeaconPaths.configure(resolver: TempResolver(base: tempBase))
        defer { try? FileManager.default.removeItem(at: tempBase) }

        let beacon = await Beacon.configure(
            appVersion: "0.87.5.0",
            component: "test"
        )
        let id = await beacon.installID()
        #expect(id.hasPrefix("ins_"))
        #expect(id.count == 20)
    }
}

// MARK: - Test helpers

private struct TempResolver: PathResolving {
    let base: URL
    func directory(for kind: PathKind) -> URL {
        switch kind {
        case .beaconRoot: return base
        case .beaconCrashStaging: return base.appendingPathComponent("crash-staging", isDirectory: true)
        case .beaconOutbox: return base.appendingPathComponent("outbox", isDirectory: true)
        }
    }
}

private struct StubIdentityProvider: BeaconIdentityProvider {
    let stubID: String
    func installID() -> String { stubID }
    func reset() { /* no-op */ }
}
