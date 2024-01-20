import Vapor

public struct OAuthDiscoveryDocument: Content {
    
    public var issuer: String?
    public var authorizationEndpoint: String?
    public var tokenEndpoint: String?
    public var userInfoEndpoint: String?
    public var revocationEndpoint: String?
    public var introspectionEndpoint: String?
    public var jwksURI: String?
    public var registrationEndpoint: String?
    public var scopesSupported: [String]?
    public var responseTypesSupported: [String]?
    public var responseModesSupported: [String]?
    public var grantTypesSupported: [String]?
    public var acrValuesSupported: [String]?
    public var idTokenEncryptionAlgValuesSupported: [String]?
    public var idTokenEncryptionEncValuesSupported: [String]?
    public var userinfoSigningAlgValuesSupported: [String]?
    public var userinfoEncryptionAlgValuesSupported: [String]?
    public var userinfoEncryptionEncValuesSupported: [String]?
    public var requestObjectSigningAlgValuesSupported: [String]?
    public var requestObjectEncryptionAlgValuesSupported: [String]?
    public var requestObjectEncryptionEncValuesSupported: [String]?
    public var tokenEndpointAuthMethodsSupported: [String]?
    public var tokenEndpointAuthSigningAlgValuesSupported: [String]?
    public var displayValuesSupported: [String]?
    public var claimTypesSupported: [String]?
    public var claimsSupported: [String]?
    public var serviceDocumentation: String?
    public var claimsLocalesSupported: [String]?
    public var uiLocalesSupported: [String]?
    public var claimsParameterSupported: Bool?
    public var requestParameterSupported: Bool?
    public var requestUriParameterSupported: Bool?
    public var requireRequestUriRegistration: Bool?
    public var opPolicyURI: String?
    public var opTosURI: String?
    public var extend: [String: Any] = [:]
    
   
    
    // Exclude 'extend' property from encoding
    private enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint
        case tokenEndpoint
        case userInfoEndpoint
        case revocationEndpoint
        case introspectionEndpoint
        case jwksURI
        case registrationEndpoint
        case scopesSupported
        case responseTypesSupported
        case responseModesSupported
        case grantTypesSupported
        case acrValuesSupported
        case idTokenEncryptionAlgValuesSupported
        case idTokenEncryptionEncValuesSupported
        case userinfoSigningAlgValuesSupported
        case userinfoEncryptionAlgValuesSupported
        case userinfoEncryptionEncValuesSupported
        case requestObjectSigningAlgValuesSupported
        case requestObjectEncryptionAlgValuesSupported
        case requestObjectEncryptionEncValuesSupported
        case tokenEndpointAuthMethodsSupported
        case tokenEndpointAuthSigningAlgValuesSupported
        case displayValuesSupported
        case claimTypesSupported
        case claimsSupported
        case serviceDocumentation
        case claimsLocalesSupported
        case uiLocalesSupported
        case claimsParameterSupported
        case requestParameterSupported
        case requestUriParameterSupported
        case requireRequestUriRegistration
        case opPolicyURI
        case opTosURI
    }
}
