protocol KeyManagementService {
    func generateKey() throws -> RSAKey
    func storeKey(_ key: RSAKey) throws
    func retrieveKey(identifier: String) throws -> RSAKey
    // Additional methods for key rotation, deletion, etc.

}
