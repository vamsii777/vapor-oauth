import Vapor
import JWTKit

public protocol RefreshToken: JWTPayload {
    var tokenString: String { get set }
    var clientID: String { get set }
    var userID: String? { get set }
    var scopes: [String]? { get set }
    var expiration: Date { get }
}

// Implementing verify(using:) for the RefreshToken protocol
extension RefreshToken {
    public func verify(using signer: JWTSigner) throws {
        try expiration.verifyNotExpired()
    }
}
