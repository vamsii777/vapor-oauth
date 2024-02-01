public protocol UserManager: Sendable {
    func authenticateUser(username: String, password: String) async throws -> String?
    func getUser(userID: String) async throws -> OAuthUser?
    func getUserClient(userID: String, clientID: String) async throws -> OAuthUser?
}
