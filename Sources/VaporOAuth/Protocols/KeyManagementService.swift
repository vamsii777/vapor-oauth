import Foundation
import JWTKit

public enum KeyType: String, Codable {
    case `public`
    case `private`
}

/// Protocol for managing RSA keys used in cryptographic operations.
public protocol KeyManagementService: Sendable  {

    /// Generates a new RSA key.
    /// - Returns: A newly generated RSAKey.
    /// - Throws: An error if the key generation fails.
    func generateKey() throws -> RSAKey

    /// Stores a RSA key.
    /// - Parameter key: The RSAKey to be stored.
    /// - Parameter keyType: The type of key (public or private).
    /// - Throws: An error if storing the key fails.
    func storeKey(_ key: RSAKey, keyType: KeyType) throws

    /// Retrieves a RSA key based on its identifier and type.
    /// - Parameters:
    ///   - identifier: The unique identifier of the key.
    ///   - keyType: The type of key (public or private).
    /// - Returns: The requested RSAKey.
    /// - Throws: An error if retrieving the key fails.
    func retrieveKey(identifier: String, keyType: KeyType) throws -> RSAKey

    /// Retrieves the identifier of the public key.
    /// - Returns: The identifier of the public key.
    /// - Throws: An error if the operation fails.
    func publicKeyIdentifier() throws -> String

    /// Converts a RSAKey to a JSON Web Key (JWK) format.
    /// - Parameter key: The RSAKey to convert.
    /// - Returns: The corresponding JWK.
    /// - Throws: An error if the conversion fails.
    func convertToJWK(_ key: RSAKey) throws -> JWK 

    /// Retrieves the identifier of the private key.
    /// - Returns: The identifier of the private key.
    /// - Throws: An error if the operation fails.
    func privateKeyIdentifier() throws -> String

    /// Rotates the keys by generating a new key and optionally deprecating the old one.
    /// - Parameter deprecateOld: A boolean indicating whether to deprecate the old key.
    /// - Throws: An error if the key rotation fails.
    func rotateKey(deprecateOld: Bool) throws

    /// Deletes a RSA key based on its identifier.
    /// - Parameter identifier: The unique identifier of the key to be deleted.
    /// - Throws: An error if the deletion fails.
    func deleteKey(identifier: String) throws

    /// Lists all available RSA keys.
    /// - Returns: An array of identifiers of the available RSA keys.
    /// - Throws: An error if the operation fails.
    func listKeys() throws -> [String]
}