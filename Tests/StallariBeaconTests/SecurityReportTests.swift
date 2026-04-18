import Foundation
import Testing

@testable import StallariBeacon

// MARK: - Security Report Tests

@Suite("SecurityReport")
struct SecurityReportTests {

    // MARK: - Codable round-trip

    @Test("SecurityReport Codable round-trip with overlay version")
    func securityReportRoundTrip() throws {
        let report = SecurityReport(
            eventType: .guardrailHashMismatch,
            detail: "Expected abc123, got def456",
            overlayVersion: "2.4.0",
            baselineVersion: "2.0.0"
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(report)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(SecurityReport.self, from: data)

        #expect(decoded.eventType == .guardrailHashMismatch)
        #expect(decoded.detail == "Expected abc123, got def456")
        #expect(decoded.overlayVersion == "2.4.0")
        #expect(decoded.baselineVersion == "2.0.0")
    }

    @Test("SecurityReport round-trip with nil overlay version")
    func securityReportNilOverlay() throws {
        let report = SecurityReport(
            eventType: .guardrailDecryptionFailure,
            detail: "AES-GCM decryption failed",
            baselineVersion: "2.0.0"
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(report)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(SecurityReport.self, from: data)

        #expect(decoded.eventType == .guardrailDecryptionFailure)
        #expect(decoded.overlayVersion == nil)
    }

    // MARK: - BeaconReport integration

    @Test("BeaconReport with security payload round-trip")
    func beaconReportSecurityPayload() throws {
        let securityReport = SecurityReport(
            eventType: .guardrailDecryptionFailure,
            detail: "AES-GCM decryption failed",
            baselineVersion: "2.0.0"
        )

        let original = BeaconReport(
            reportId: "brpt_sec00001",
            type: .security,
            timestamp: Date(timeIntervalSinceReferenceDate: 800_000_000),
            app: AppInfo(version: "0.66.0.0", component: "daemon"),
            system: SystemInfo(osVersion: "15.4", arch: "arm64", memoryGb: 36, memoryPressure: .nominal),
            payload: .security(securityReport)
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(original)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(BeaconReport.self, from: data)

        #expect(decoded.type == .security)
        #expect(decoded.reportId == "brpt_sec00001")
        if case .security(let payload) = decoded.payload {
            #expect(payload.eventType == .guardrailDecryptionFailure)
            #expect(payload.overlayVersion == nil)
        } else {
            Issue.record("Expected security payload")
        }
    }

    // MARK: - SecurityEventType exhaustive

    @Test("All SecurityEventType cases round-trip")
    func allSecurityEventTypes() throws {
        let allTypes: [SecurityEventType] = [
            .guardrailHashMismatch,
            .guardrailDecryptionFailure,
            .guardrailOverlayMissing,
            .sealKeyMissing,
            .consentOverride,
        ]

        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        for eventType in allTypes {
            let report = SecurityReport(
                eventType: eventType,
                detail: "Test \(eventType.rawValue)",
                baselineVersion: "1.0.0"
            )
            let data = try encoder.encode(report)
            let decoded = try decoder.decode(SecurityReport.self, from: data)
            #expect(decoded.eventType == eventType)
        }
    }

    // MARK: - SecurityEventType raw values

    @Test("SecurityEventType raw values match wire format")
    func securityEventTypeRawValues() {
        #expect(SecurityEventType.guardrailHashMismatch.rawValue == "guardrail_hash_mismatch")
        #expect(SecurityEventType.guardrailDecryptionFailure.rawValue == "guardrail_decryption_failure")
        #expect(SecurityEventType.guardrailOverlayMissing.rawValue == "guardrail_overlay_missing")
        #expect(SecurityEventType.sealKeyMissing.rawValue == "seal_key_missing")
        #expect(SecurityEventType.consentOverride.rawValue == "consent_override")
    }

    // MARK: - JSON key format

    @Test("Security report JSON uses snake_case keys")
    func jsonSnakeCaseKeys() throws {
        let report = SecurityReport(
            eventType: .sealKeyMissing,
            detail: "Key not found",
            overlayVersion: "1.0.0",
            baselineVersion: "1.0.0"
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(report)
        let json = String(data: data, encoding: .utf8)!

        #expect(json.contains("event_type"))
        #expect(json.contains("overlay_version"))
        #expect(json.contains("baseline_version"))
    }

    // MARK: - Consent gate

    @Test("Security reports bypass consent gate")
    func securityBypassesConsentGate() throws {
        let config = BeaconConfig() // defaults: everything off
        let gate = ConsentGate(config: config)
        #expect(gate.canSendSecurityReports() == true)
    }

    @Test("check() does not throw for security report")
    func checkAllowsSecurity() throws {
        let config = BeaconConfig() // defaults: everything off
        let gate = ConsentGate(config: config)

        let report = BeaconReport(
            type: .security,
            app: AppInfo(version: "1.0.0", component: "test"),
            system: SystemInfo(osVersion: "15.4", arch: "arm64", memoryGb: 36, memoryPressure: .nominal),
            payload: .security(SecurityReport(
                eventType: .guardrailOverlayMissing,
                detail: "Overlay file not found",
                baselineVersion: "1.0.0"
            ))
        )

        // Should not throw — security reports are always allowed.
        try gate.check(report)
    }
}
