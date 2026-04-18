import Foundation

// MARK: - SecurityEventType

/// Classification of security events reported via Beacon.
public enum SecurityEventType: String, Codable, Sendable {
    /// Guardrail overlay file hash doesn't match registry manifest.
    case guardrailHashMismatch = "guardrail_hash_mismatch"

    /// Sealed guardrail payload could not be decrypted.
    case guardrailDecryptionFailure = "guardrail_decryption_failure"

    /// Guardrail overlay expected but not found on disk.
    case guardrailOverlayMissing = "guardrail_overlay_missing"

    /// Seal key not found in Keychain for the pack.
    case sealKeyMissing = "seal_key_missing"

    /// User granted or revoked consent for a community agent.
    case consentOverride = "consent_override"
}

// MARK: - SecurityReport

/// Security event report for guardrail integrity and agent consent events.
///
/// Triggered by: guardrail hash mismatches, decryption failures, missing overlays,
/// seal key issues, and user consent grants/revocations. These events are always
/// reported (not gated by consent) since they indicate potential security issues.
public struct SecurityReport: Codable, Sendable, Equatable {
    /// Classification of the security event.
    public let eventType: SecurityEventType

    /// Human-readable detail about the event.
    public let detail: String

    /// Version of the guardrail overlay involved (nil if no overlay).
    public let overlayVersion: String?

    /// Version of the bundled baseline guardrails.
    public let baselineVersion: String

    /// When the event occurred.
    public let timestamp: Date

    public init(
        eventType: SecurityEventType,
        detail: String,
        overlayVersion: String? = nil,
        baselineVersion: String,
        timestamp: Date = Date()
    ) {
        self.eventType = eventType
        self.detail = detail
        self.overlayVersion = overlayVersion
        self.baselineVersion = baselineVersion
        self.timestamp = timestamp
    }

    private enum CodingKeys: String, CodingKey {
        case eventType = "event_type"
        case detail
        case overlayVersion = "overlay_version"
        case baselineVersion = "baseline_version"
        case timestamp
    }
}
