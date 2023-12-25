import Foundation
import JWTKit

public protocol KeyManagementService {
    func generateKey() throws -> RSAKey
    func storeKey(_ key: RSAKey) throws
    func retrieveKey(identifier: String) throws -> RSAKey
    func publicKeyIdentifier() throws -> String
    func convertToJWK(_ key: RSAKey) throws -> JWK 
    // Additional methods for key rotation, deletion, etc.

}
