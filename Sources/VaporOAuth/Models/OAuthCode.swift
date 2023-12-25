import Foundation

public final class OAuthCode {
    public let codeID: String
    public let clientID: String
    public let redirectURI: String
    public let userID: String
    public let expiryDate: Date
    public let scopes: [String]?

    // PKCE parameters
    public let codeChallenge: String?
    public let codeChallengeMethod: String?

    // Nonce parameter
    public var nonce: String?

    public var extend: [String: Any] = [:]

    public init(
        codeID: String,
        clientID: String,
        redirectURI: String,
        userID: String,
        expiryDate: Date,
        scopes: [String]?,
        codeChallenge: String?, // Add PKCE parameters
        codeChallengeMethod: String?,
        nonce: String? = nil
    ) {
        self.codeID = codeID
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.userID = userID
        self.expiryDate = expiryDate
        self.scopes = scopes
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.nonce = nonce
    }
}
