import Foundation
import JWTKit

public protocol KeyManagementService: Sendable  {
    func generateKey() throws -> RSAKey
    func storeKey(_ key: RSAKey) throws
    func retrieveKey(identifier: String) throws -> RSAKey
    func publicKeyIdentifier() throws -> String
    func convertToJWK(_ key: RSAKey) throws -> JWK 
    func privateKeyIdentifier() throws -> String
    // Additional methods for key rotation, deletion, etc.

}
