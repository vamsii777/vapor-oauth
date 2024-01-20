import Foundation
import JWTKit

public enum KeyType: String, Codable {
    case `public`
    case `private`
}

/// A protocol that defines the interface for a key management service.
public protocol KeyManagementService: Sendable {

    /// Generates a new key pair and returns the identifiers for the private and public keys.
    /// - Returns: A tuple containing the private key identifier and the public key identifier.
    /// - Throws: An error if the key generation fails.
    func generateKey() throws -> (privateKeyIdentifier: String, publicKeyIdentifier: String)

    /// Stores a key in the key management service.
    /// - Parameters:
    ///   - key: The key to be stored.
    ///   - keyType: The type of the key (public or private).
    /// - Throws: An error if the key storage fails.
    func storeKey(_ key: String, keyType: KeyType) throws

    /// Retrieves a key from the key management service.
    /// - Parameters:
    ///   - identifier: The identifier of the key to be retrieved.
    ///   - keyType: The type of the key (public or private).
    /// - Returns: The key data.
    /// - Throws: An error if the key retrieval fails.
    func retrieveKey(identifier: String, keyType: KeyType) throws -> Data

    /// Retrieves the identifier of the public key.
    /// - Returns: The identifier of the public key.
    /// - Throws: An error if the public key identifier retrieval fails.
    func publicKeyIdentifier() throws -> String

    /// Converts a public key to a JSON Web Key (JWK) representation.
    /// - Parameter publicKey: The public key data.
    /// - Returns: The JWK representation of the public key.
    /// - Throws: An error if the conversion fails.
    func convertToJWK(_ publicKey: Data) throws -> [JWK]

    /// Retrieves the identifier of the private key.
    /// - Returns: The identifier of the private key.
    /// - Throws: An error if the private key identifier retrieval fails.
    func privateKeyIdentifier() throws -> String
    
    /// Rotates the key by generating a new key pair and optionally deprecating the old key.
    /// - Parameter deprecateOld: A flag indicating whether to deprecate the old key.
    /// - Throws: An error if the key rotation fails.
    func rotateKey(deprecateOld: Bool) throws

    /// Deletes a key from the key management service.
    /// - Parameter identifier: The identifier of the key to be deleted.
    /// - Throws: An error if the key deletion fails.
    func deleteKey(identifier: String) throws

    /// Lists all the keys stored in the key management service.
    /// - Returns: An array of key identifiers.
    /// - Throws: An error if the key listing fails.
    func listKeys() throws -> [String]
}
