import Foundation

// MARK: - OutboxHealth

/// Beacon outbox health row surfaced on ``HealthSnapshot/outbox``.
/// Introduced in Beacon schema 1.3.0 (DD-270 Phase C) as the consumer
/// surface for the SQLCipher-backed outbox shipped in DD-270 Phase A.
/// Mirror of `stallari-fabric/FabricNerve` canonical.
public struct OutboxHealth: Codable, Sendable, Equatable, Hashable {
    public let pending: Int
    public let lastSendOk: Date?
    public let lastSendError: String?

    public init(
        pending: Int = 0,
        lastSendOk: Date? = nil,
        lastSendError: String? = nil
    ) {
        self.pending = pending
        self.lastSendOk = lastSendOk
        self.lastSendError = lastSendError
    }

    private enum CodingKeys: String, CodingKey {
        case pending
        case lastSendOk = "last_send_ok"
        case lastSendError = "last_send_error"
    }
}
