import Vapor
import JWTKit

public protocol AccessToken: JWTPayload {
    var jti: String { get }
    var clientID: String { get }
    var userID: String? { get }
    var scopes: [String]? { get }
    var expiryTime: Date { get }
}

// Providing a default implementation of verify(using:) for AccessToken
extension AccessToken {
    public func verify(using signer: JWTSigner) throws {
        try expiryTime.verifyNotExpired()
    }
}
