public struct TokenAuthenticator {

    public init() {}

    func validateRefreshToken(_ refreshToken: RefreshToken, clientID: String) -> Bool {
        guard refreshToken.clientID  == clientID else {
            return false
        }

        return true
    }

    func validateAccessToken(_ accessToken: AccessToken, requiredScopes: String?) -> Bool {
        guard let requiredScopesString = requiredScopes else {
            return true
        }

        let requiredScopesArray = requiredScopesString.components(separatedBy: " ")

        guard let accessTokenScopesString = accessToken.scopes else {
            return false
        }

        let accessTokenScopesArray = accessTokenScopesString.components(separatedBy: " ")

        for scope in requiredScopesArray {
            if !accessTokenScopesArray.contains(scope) {
                return false
            }
        }

        return true
    }
}
