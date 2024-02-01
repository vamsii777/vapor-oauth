import XCTVapor
import JWTKit
@testable import VaporOAuth

class TokenRefreshTests: XCTestCase {
    
    // MARK: - Properties
    
    var app: Application!
    var fakeClientGetter: FakeClientGetter!
    var fakeTokenManager: FakeTokenManager!
    let testClientID = "ABCDEF"
    let testClientSecret = "01234567890"
    let refreshTokenString = "ABCDEFGJ-REFRESH-TOKEN"
    let scope1 = "email"
    let scope2 = "create"
    let scope3 = "edit"
    let scope4 = "profile"
    var validRefreshToken: RefreshToken!
    
    // MARK: - Overrides
    
    override func setUp() {
        fakeClientGetter = FakeClientGetter()
        fakeTokenManager = FakeTokenManager()
        
        app = try! TestDataBuilder.getOAuth2Application(
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientGetter,
            validScopes: [scope1, scope2, scope3, scope4]
        )
        
        let testClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: nil,
            clientSecret: testClientSecret,
            validScopes: "\(scope1)\(scope2)\(scope4)",
            confidential: true,
            allowedGrantType: .authorization
        )
        fakeClientGetter.validClients[testClientID] = testClient
        validRefreshToken = FakeRefreshToken(
            jti: refreshTokenString,
            clientID: testClientID,
            userID: nil,
            scopes: "\(scope1)\(scope2)", exp: Date().addingTimeInterval(60)
        )
        fakeTokenManager.refreshTokens[refreshTokenString] = validRefreshToken
    }
    
    override func tearDown() async throws {
        app.shutdown()
        try await super.tearDown()
    }
    
    // MARK: - Tests
    func testCorrectErrorWhenGrantTypeNotSupplied() async throws {
        let response = try await getTokenResponse(grantType: nil)
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'grant_type' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet() async throws {
        let grantType = "some_unknown_type"
        let response = try await getTokenResponse(grantType: grantType)
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "unsupported_grant_type")
        XCTAssertEqual(responseJSON.errorDescription, "This server does not support the '\(grantType)' grant type")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testCorrectErrorWhenClientIDNotSupplied() async throws {
        let response = try await getTokenResponse(clientID: nil)
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'client_id' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testCorrectErrorWhenClientIDNotValid() async throws {
        let response = try await getTokenResponse(clientID: "UNKNOWN_CLIENT")
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testCorrectErrorWhenClientDoesNotAuthenticate() async throws {
        let response = try await getTokenResponse(clientSecret: "incorrectPassword")
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testCorrectErrorIfClientSecretNotSent() async throws {
        let response = try await getTokenResponse(clientSecret: nil)
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'client_secret' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testCorrectErrrIfRefreshTokenNotSent() async throws {
        let response = try await getTokenResponse(refreshToken: nil)
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'refresh_token' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testThatNonConfidentialClientsGetErrorWhenRequestingToken() async throws {
        let nonConfidentialClientID = "NONCONF"
        let nonConfidentialClientSecret = "SECRET"
        let nonConfidentialClient = OAuthClient(clientID: nonConfidentialClientID, redirectURIs: nil, clientSecret: nonConfidentialClientSecret, confidential: false, allowedGrantType: .authorization)
        fakeClientGetter.validClients[nonConfidentialClientID] = nonConfidentialClient
        
        let response = try await getTokenResponse(clientID: nonConfidentialClientID, clientSecret: nonConfidentialClientSecret)
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "unauthorized_client")
        XCTAssertEqual(responseJSON.errorDescription, "You are not authorized to use the Client Credentials grant type")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testThatAttemptingRefreshWithNonExistentTokenReturnsError() async throws {
        let expiredRefreshToken = "NONEXISTENTTOKEN"
        
        let response = try await getTokenResponse(refreshToken: expiredRefreshToken)
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_grant")
        XCTAssertEqual(responseJSON.errorDescription, "The refresh token is invalid")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testThatAttemptingRefreshWithRefreshTokenFromDifferentClientReturnsError() async throws {
        let otherClientID = "ABCDEFGHIJKLMON"
        let otherClientSecret = "1234"
        let otherClient = OAuthClient(clientID: otherClientID, redirectURIs: nil, clientSecret: otherClientSecret, confidential: true, allowedGrantType: .authorization)
        fakeClientGetter.validClients[otherClientID] = otherClient
        
        let response = try await getTokenResponse(clientID: otherClientID, clientSecret: otherClientSecret)
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_grant")
        XCTAssertEqual(responseJSON.errorDescription, "The refresh token is invalid")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    
    func testThatProvidingValidRefreshTokenProvidesAccessTokenInResponse() async throws {
        let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.accessTokenToReturn = accessToken
        let response = try await getTokenResponse()
        
        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
        XCTAssertEqual(responseJSON.tokenType, "bearer")
        XCTAssertEqual(responseJSON.expiresIn, 3600)
        XCTAssertEqual(responseJSON.accessToken, accessToken)
        XCTAssertNil(responseJSON.refreshToken)
    }
    
    func testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo() async throws {
        let scope = "email edit"
        
        let response = try await getTokenResponse(scope: scope)
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained an invalid scope")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testCorrectErrorWhenRequestingUnknownScope() async throws {
        let scope = "email unknown"
        
        let response = try await getTokenResponse(scope: scope)
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained an unknown scope")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testErrorIfRequestingScopeGreaterThanOriginallyRequestedEvenIfApplicatioHasAccess() async throws {
        let response = try await getTokenResponse(scope: "\(scope1) \(scope4)")
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained elevated scopes")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testLoweringScopeOnRefreshSetsScopeCorrectlyOnAccessAndRefreshTokens() async throws {
        let scope1 = "email"  // Define the scope1 string as needed

        let response = try await getTokenResponse(scope: scope1)
        
        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)
        
        guard let accessTokenString = responseJSON.accessToken else {
            XCTFail("No access token found in response")
            return
        }
        
        var signers = JWTSigners()
        signers.use(.hs256(key: "dummySecret")) // Use the actual key and algorithm
        
        do {
            // Decode the access token to verify its scopes
            let jwt = try signers.verify(accessTokenString, as: MyAccessToken.self)
            guard let accessTokenScopes = jwt.scopes else {
                XCTFail("Access token does not contain scopes")
                return
            }
            
            // Assuming accessToken.scopes is a space-separated string
            XCTAssertEqual(accessTokenScopes, scope1, "Access token scopes do not match the expected scope")

        } catch {
            XCTFail("Failed to decode JWT: \(error)")
            return
        }

        // Compare accessToken.scopes directly to the string
        XCTAssertEqual(accessToken.scopes, scope1)

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(responseJSON.scope, scope1)
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])

        let refreshTokenString = responseJSON.refreshToken ?? ""

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail("Failed to retrieve refresh token")
            return
        }

        // Compare refreshToken.scopes directly to the string
        XCTAssertEqual(refreshToken.scopes, scope1)
    }
    
    func testNotRequestingScopeOnRefreshDoesNotAlterOriginalScope() async throws {
        let originalScopes = validRefreshToken.scopes // Assuming this is a String representing scopes
        
        let response = try await getTokenResponse() // Simulate token refresh/response
        
        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)
        
        guard let accessTokenString = responseJSON.accessToken else {
            XCTFail("No access token found in response")
            return
        }

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        // Directly compare the string values of scopes
        XCTAssertEqual(accessToken.scopes, originalScopes)
        XCTAssertEqual(refreshToken.scopes, originalScopes)
    }
    
    func testRequestingTheSameScopeWhenRefreshingWorksCorrectlyAndReturnsResult() async throws {
        // Ensure scopesToRequest is correctly initialized from validRefreshToken
        let scopesToRequest = validRefreshToken.scopes

        let response = try await getTokenResponse(scope: scopesToRequest)

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)
        
        // Set up JWTSigners
        var signers = JWTSigners()
        signers.use(.hs256(key: "dummySecret"))
        
        // Extract accessTokenString from response
        guard let accessTokenString = responseJSON.accessToken else {
            XCTFail("No access token found in response")
            return
        }
        
        var scopes: String? = nil // Initialize `scopes` here to ensure it's always initialized before use
        
        do {
            // Decode JWT
            let jwt = try signers.verify(accessTokenString, as: MyAccessToken.self)
            scopes = jwt.scopes // Assign decoded scopes to the `scopes` variable
        } catch {
            XCTFail("Failed to decode JWT: \(error)")
            return // Ensure exit from function upon failure
        }
        
        // Validate that the refreshed token has the requested scopes
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail("Failed to retrieve refresh token")
            return
        }

        // Directly compare the string values of scopes
        XCTAssertEqual(accessToken.scopes, scopesToRequest)
        XCTAssertEqual(refreshToken.scopes, scopesToRequest)
    }
    
    func testErrorWhenRequestingScopeWithNoScopesOriginallyRequestedOnRefreshToken() async throws {
        let newRefreshToken = "NEW_REFRESH_TOKEN"
        let refreshTokenWithoutScope = FakeRefreshToken(jti: newRefreshToken, clientID: testClientID, userID: nil, scopes: nil, exp: Date().addingTimeInterval(60))
        fakeTokenManager.refreshTokens[newRefreshToken] = refreshTokenWithoutScope
        
        let response = try await getTokenResponse(refreshToken: newRefreshToken, scope: scope1)
        
        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained elevated scopes")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }
    
    func testUserIDIsSetOnAccessTokenIfRefreshTokenHasOne() async throws {
        let userID = "abcdefg-123456"
        let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        let userIDRefreshTokenString = "ASHFUIEWHFIHEWIUF"
        let userIDRefreshToken = FakeRefreshToken(jti: userIDRefreshTokenString, clientID: testClientID, userID: userID, scopes: "\(scope1)\(scope2)", exp: Date().addingTimeInterval(60))
        fakeTokenManager.refreshTokens[userIDRefreshTokenString] = userIDRefreshToken
        fakeTokenManager.accessTokenToReturn = accessToken
        _ = try await getTokenResponse(refreshToken: userIDRefreshTokenString)
        
        guard let token = fakeTokenManager.getAccessToken(accessToken) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(token.userID, userID)
    }
    
    func testClientIDSetOnAccessTokenFromRefreshToken() async throws {
        let refreshTokenString = "some-new-refreshToken"
        let clientID = "the-client-id-to-set"
        let refreshToken = FakeRefreshToken(jti: refreshTokenString, clientID: clientID, userID: "some-user", exp: Date().addingTimeInterval(60))
        
        // Set up the mock refresh token in your fake token manager
        fakeTokenManager.refreshTokens[refreshTokenString] = refreshToken
        
        // Configure a mock OAuth client that's considered valid
        fakeClientGetter.validClients[clientID] = OAuthClient(clientID: clientID, redirectURIs: nil, clientSecret: testClientSecret, confidential: true, allowedGrantType: .authorization)
        
        // Attempt to get a new token response using the refresh token
        let response = try await getTokenResponse(clientID: clientID, refreshToken: refreshTokenString)
        
        // Decode the response to obtain the access token string
        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)
        
        guard let accessTokenString = responseJSON.accessToken else {
            XCTFail("No access token found in response")
            return
        }
        
        var signers = JWTSigners()
        signers.use(.hs256(key: "dummySecret"))
        
        do {
            let jwt = try signers.verify(accessTokenString, as: MyAccessToken.self)
            let accessTokenJti = jwt.jti
            
            // Retrieve the access token details using the token string
            guard let accessToken = fakeTokenManager.getAccessToken(accessTokenJti) else {
                XCTFail("Failed to retrieve access token details")
                return
            }
            
            // Assert that the clientID of the retrieved access token matches the expected clientID
            XCTAssertEqual(accessToken.clientID, clientID, "Access token clientID does not match the expected clientID")
            
        } catch {
            XCTFail("Failed to decode JWT: \(error)")
        }
        
    }
    
    func testExpiryTimeSetOnNewAccessToken() async throws {
        
        let currentTime = Date()
        fakeTokenManager.currentTime = currentTime
        
        let response = try await getTokenResponse()
        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)
        
        guard let accessTokenString = responseJSON.accessToken else {
            XCTFail("Access token not found in response")
            return
        }
        
        var signers = JWTSigners()
        signers.use(.hs256(key: "dummySecret"))
        
        do {
            let jwt = try signers.verify(accessTokenString, as: MyAccessToken.self)
            
            // Verify the expiry time directly with the Date object
            let expectedExpiryTime = currentTime.addingTimeInterval(3600)
            let accessTokenExpiryTime = jwt.expiryTime
            
            // Calculate the time difference and assert it's within 5 seconds tolerance
            let timeDifference = accessTokenExpiryTime.timeIntervalSince(expectedExpiryTime)
            XCTAssertTrue(abs(timeDifference) <= 5, "Access token expiry time is not within the expected range")
        } catch {
            XCTFail("Failed to decode JWT: \(error)")
        }
    }
    
    
    // MARK: - Private
    
    func getTokenResponse(
        grantType: String? = "refresh_token",
        clientID: String? = "ABCDEF",
        clientSecret: String? = "01234567890",
        refreshToken: String? = "ABCDEFGJ-REFRESH-TOKEN",
        scope: String? = nil
    ) async throws -> XCTHTTPResponse {
        return try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: grantType,
            clientID: clientID,
            clientSecret: clientSecret,
            scope: scope,
            refreshToken: refreshToken
        )
    }
    
    struct MyAccessToken: AccessToken {
        var jti: String
        var clientID: String
        var userID: String?
        var scopes: String?
        var expiryTime: Date
    }
    
}
