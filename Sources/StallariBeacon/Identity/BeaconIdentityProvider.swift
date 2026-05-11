// DD-270 Phase B (Layer A) — BeaconIdentityProvider protocol + file-backed
// default impl.
//
// Mirrors the Phase A `ReportStore`/`FileReportStore` shape: FabricNerve
// owns the protocol and the file-backed default; daemon-side StallariKit
// supplies a `CredentialStoreIdentityProvider` (DD-186 Keychain-backed)
// that the harness injects via `Beacon.configure(identityProvider:)`.

import Foundation

// MARK: - BeaconIdentityProvider

/// Provides the per-install identifier transmitted in beacon reports.
///
/// FabricNerve ships ``FileInstallIDProvider`` as the default — it reads
/// from / writes to the legacy `install_id` file inside the beacon root
/// (resolved through `BeaconPaths.directory(for: .beaconRoot)`). The
/// harness's `CredentialStoreIdentityProvider` (in StallariKit) supersedes
/// this for the daemon, persisting identity in the system Keychain via
/// DD-186's CredentialStore.
///
/// **DD-270 Phase B substrate.** Replaces the historical static-only
/// `InstallID.loadOrCreate()` call shape with a protocol seam so
/// daemon-side identity can move to Keychain without breaking SDK
/// consumers.
///
/// ## Concurrency
///
/// Conformers MUST be safe to call from any thread. Both methods are
/// synchronous because identity reads sit on the hot path of every report
/// dispatch — the file-backed default reads from disk once and caches
/// in-process, the CredentialStore-backed variant uses the Keychain's own
/// concurrency primitives.
public protocol BeaconIdentityProvider: Sendable {
    /// Returns the current install ID, generating one if absent.
    /// Format: `ins_` + 16 hex chars (20 chars total). See ``InstallID/isValid(_:)``.
    func installID() -> String

    /// Wipes the persisted install ID. Subsequent ``installID()`` calls
    /// generate a fresh one. Used for the "Delete all data" user action.
    func reset()
}

// MARK: - FileInstallIDProvider (default)

/// File-backed ``BeaconIdentityProvider`` implementation. Wraps the
/// existing static ``InstallID`` API.
///
/// This is the SDK default. Daemon integrations in `stallari-harness` use
/// `CredentialStoreIdentityProvider` (Keychain-backed via DD-186) instead
/// — the dependency inversion is what lets FabricNerve preserve its
/// zero-external-deps invariant.
public struct FileInstallIDProvider: BeaconIdentityProvider {

    public init() {}

    public func installID() -> String {
        InstallID.loadOrCreate()
    }

    public func reset() {
        InstallID.reset()
    }
}
