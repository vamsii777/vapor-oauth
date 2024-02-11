import JWTKit
import Foundation

// Define the protocol
public protocol JWTSignerService: Sendable {
    var keyManagementService: KeyManagementService { get }
    func makeJWTSigner() async throws -> JWTSigners
}
