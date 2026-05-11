import Foundation

// MARK: - BladeIndexHealth

/// Per-blade local-corpus index health row surfaced on
/// ``HealthSnapshot/indexHealth``. Introduced in Beacon schema 1.3.0
/// (DD-270 Phase C) as the consumer surface for the local-corpus index
/// substrate (DD-256). Mirror of `stallari-fabric/FabricNerve` canonical.
public struct BladeIndexHealth: Codable, Sendable, Equatable, Hashable {
    public let bladeName: String
    public let lagSeconds: Int?
    public let lastIndexedAt: Date?
    public let corruptionCount: Int

    public init(
        bladeName: String,
        lagSeconds: Int? = nil,
        lastIndexedAt: Date? = nil,
        corruptionCount: Int = 0
    ) {
        self.bladeName = bladeName
        self.lagSeconds = lagSeconds
        self.lastIndexedAt = lastIndexedAt
        self.corruptionCount = corruptionCount
    }

    private enum CodingKeys: String, CodingKey {
        case bladeName = "blade_name"
        case lagSeconds = "lag_seconds"
        case lastIndexedAt = "last_indexed_at"
        case corruptionCount = "corruption_count"
    }
}
