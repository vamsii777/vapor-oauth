import VaporOAuth

struct StubUserManager: UserManager {
    func authenticateUser(username: String, password: String) -> String? {
        return nil
    }
    
    func getUser(userID: String) -> OAuthUser? {
        return nil
    }
    
    
    func getUserClient(userID: String, clientID: String) -> OAuthUser? {
        return nil
    }
}
