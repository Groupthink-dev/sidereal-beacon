import Foundation

// MARK: - TracksHealth

/// Tracks substrate health row surfaced on ``HealthSnapshot/tracks``.
/// Introduced in Beacon schema 1.3.0 (DD-270 Phase C) as the consumer
/// surface for the Tracks substrate (DD-245). Mirror of
/// `stallari-fabric/FabricNerve` canonical.
public struct TracksHealth: Codable, Sendable, Equatable, Hashable {
    public let emitted24h: Int
    public let chainHeadSha: String?

    public init(emitted24h: Int = 0, chainHeadSha: String? = nil) {
        self.emitted24h = emitted24h
        self.chainHeadSha = chainHeadSha
    }

    private enum CodingKeys: String, CodingKey {
        case emitted24h = "emitted_24h"
        case chainHeadSha = "chain_head_sha"
    }
}
