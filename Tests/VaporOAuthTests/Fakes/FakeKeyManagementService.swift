import JWTKit
import VaporOAuth
import Foundation
import Crypto

class FakeKeyManagementService: KeyManagementService {
    
    private var keys = [String: Data]()
    private var currentPublicKeyId: String?
    private var currentPrivateKeyId: String?
    
    func generateKey() async throws -> (privateKeyIdentifier: String, publicKeyIdentifier: String) {
        let privateKeyId = UUID().uuidString
        let publicKeyId = UUID().uuidString
        
        // Fake keys
        keys[privateKeyId] = Data("fake_private_key".utf8)
        keys[publicKeyId] = Data("fake_public_key".utf8)
        
        currentPrivateKeyId = privateKeyId
        currentPublicKeyId = publicKeyId
        
        return (privateKeyIdentifier: privateKeyId, publicKeyIdentifier: publicKeyId)
    }
    
    func storeKey(_ key: String, keyType: KeyType) async throws {
        let keyId = UUID().uuidString
        keys[keyId] = Data(key.utf8)
        if keyType == .private {
            currentPrivateKeyId = keyId
        } else {
            currentPublicKeyId = keyId
        }
    }
    
    func retrieveKey(identifier: String, keyType: KeyType) async throws -> Data {
        guard let key = keys[identifier] else {
            throw NSError(domain: "FakeKeyManagementService", code: 1, userInfo: [NSLocalizedDescriptionKey: "Key not found"])
        }
        return key
    }
    
    func publicKeyIdentifier() async throws -> String {
        guard let publicKeyId = currentPublicKeyId else {
            throw NSError(domain: "FakeKeyManagementService", code: 1, userInfo: [NSLocalizedDescriptionKey: "Public key not set"])
        }
        return publicKeyId
    }
    
    func privateKeyIdentifier() async throws -> String {
        guard let privateKeyId = currentPrivateKeyId else {
            throw NSError(domain: "FakeKeyManagementService", code: 1, userInfo: [NSLocalizedDescriptionKey: "Private key not set"])
        }
        return privateKeyId
    }
    
    func rotateKey(deprecateOld: Bool) async throws {
        // Create a new key pair
        let newKeys = try await generateKey()
        
        if deprecateOld {
            // Deprecate old keys
            if let oldPrivateKeyId = currentPrivateKeyId {
                keys.removeValue(forKey: oldPrivateKeyId)
            }
            if let oldPublicKeyId = currentPublicKeyId {
                keys.removeValue(forKey: oldPublicKeyId)
            }
        }
        
        currentPrivateKeyId = newKeys.privateKeyIdentifier
        currentPublicKeyId = newKeys.publicKeyIdentifier
    }
    
    func deleteKey(identifier: String) async throws {
        keys.removeValue(forKey: identifier)
    }
    
    func listKeys() async throws -> [String] {
        return Array(keys.keys)
    }
    
    func convertToJWK(_ publicKey: Data) throws -> [JWTKit.JWK] {
        // Assuming that publicKey data can be converted to the necessary components
        // for an ECDSA key. You'll need to adjust this to suit your actual key format.
        // This is just an illustrative example.
        
        let keyIdentifier = JWKIdentifier(string: "test") // Generate a unique identifier
        let xCoordinate = "your_x_coordinate" // Replace with actual x coordinate in base64 URL encoded string
        let yCoordinate = "your_y_coordinate" // Replace with actual y coordinate in base64 URL encoded string
        let curve = ECDSAKey.Curve.p256 // Replace with actual curve type if different
        
        let jwk = JWK.ecdsa(.es256, identifier: keyIdentifier, x: xCoordinate, y: yCoordinate, curve: curve)
        
        return [jwk]
    }
}
