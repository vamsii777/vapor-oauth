import JWTKit
import VaporOAuth
import Foundation
import Crypto

class FakeKeyManagementService: KeyManagementService {
    
    func privateKeyIdentifier() throws -> String {
        return ""
    }
    
    func generateKey() throws -> RSAKey {
        // Not required for HMAC based implementation
        fatalError("generateKey() should not be called in FakeKeyManagementService")
    }
    
    func storeKey(_ key: RSAKey) throws {
        // Not required for HMAC based implementation
        fatalError("storeKey(_:) should not be called in FakeKeyManagementService")
    }
    
    func retrieveKey(identifier: String) throws -> RSAKey {
        // Not required for HMAC based implementation
        fatalError("retrieveKey(identifier:) should not be called in FakeKeyManagementService")
    }
    
    func publicKeyIdentifier() throws -> String {
        // Not required for HMAC based implementation
        fatalError("publicKeyIdentifier() should not be called in FakeKeyManagementService")
    }
    
    func convertToJWK(_ key: RSAKey) throws -> JWK {
        // Creating a dummy RSA JWK with arbitrary modulus and exponent values
        let dummyModulus = "dummyModulus" // Base64 encoded string
        let dummyExponent = "dummyExponent" // Base64 encoded string
        return JWK.rsa(.rs256, identifier: nil, modulus: dummyModulus, exponent: dummyExponent)
    }
}
