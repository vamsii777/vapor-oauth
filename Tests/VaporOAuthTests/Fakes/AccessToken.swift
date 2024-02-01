import Vapor
@testable import VaporOAuth

struct FakeAccessToken: AccessToken {
    let jti: String
    let clientID: String
    let userID: String?
    let scopes: String?
    let expiryTime: Date

    init(jti: String, clientID: String, userID: String? = nil, scopes: String? = nil, expiryTime: Date) {
        self.jti = jti
        self.clientID = clientID
        self.userID = userID
        self.scopes = scopes
        self.expiryTime = expiryTime
    }
}
