import Vapor

struct DiscoveryDocumentHandler {
    
    let discoveryDocument: DiscoveryDocument
    
    init(discoveryDocument: DiscoveryDocument) {
        self.discoveryDocument = discoveryDocument
    }
    
    func generateDiscoveryDocument() -> OAuthDiscoveryDocument {
        return OAuthDiscoveryDocument(
            issuer: discoveryDocument.issuer,
            authorizationEndpoint: discoveryDocument.authorizationEndpoint,
            tokenEndpoint: discoveryDocument.tokenEndpoint,
            userInfoEndpoint: discoveryDocument.userInfoEndpoint,
            revocationEndpoint: discoveryDocument.revocationEndpoint,
            introspectionEndpoint: discoveryDocument.introspectionEndpoint,
            jwksURI: discoveryDocument.jwksURI,
            registrationEndpoint: discoveryDocument.registrationEndpoint,
            scopesSupported: discoveryDocument.scopesSupported,
            responseTypesSupported: discoveryDocument.responseTypesSupported,
            responseModesSupported: discoveryDocument.responseModesSupported,
            grantTypesSupported: discoveryDocument.grantTypesSupported,
            acrValuesSupported: discoveryDocument.acrValuesSupported,
            idTokenEncryptionAlgValuesSupported: discoveryDocument.idTokenEncryptionAlgValuesSupported,
            idTokenEncryptionEncValuesSupported: discoveryDocument.idTokenEncryptionEncValuesSupported,
            userinfoSigningAlgValuesSupported: discoveryDocument.userinfoSigningAlgValuesSupported,
            userinfoEncryptionAlgValuesSupported: discoveryDocument.userinfoEncryptionAlgValuesSupported,
            userinfoEncryptionEncValuesSupported: discoveryDocument.userinfoEncryptionEncValuesSupported,
            requestObjectSigningAlgValuesSupported: discoveryDocument.requestObjectSigningAlgValuesSupported,
            requestObjectEncryptionAlgValuesSupported: discoveryDocument.requestObjectEncryptionAlgValuesSupported,
            requestObjectEncryptionEncValuesSupported: discoveryDocument.requestObjectEncryptionEncValuesSupported,
            tokenEndpointAuthMethodsSupported: discoveryDocument.tokenEndpointAuthMethodsSupported,
            tokenEndpointAuthSigningAlgValuesSupported: discoveryDocument.tokenEndpointAuthSigningAlgValuesSupported,
            displayValuesSupported: discoveryDocument.displayValuesSupported,
            claimTypesSupported: discoveryDocument.claimTypesSupported,
            claimsSupported: discoveryDocument.claimsSupported,
            serviceDocumentation: discoveryDocument.serviceDocumentation,
            claimsLocalesSupported: discoveryDocument.claimsLocalesSupported,
            uiLocalesSupported: discoveryDocument.uiLocalesSupported,
            claimsParameterSupported: discoveryDocument.claimsParameterSupported,
            requestParameterSupported: discoveryDocument.requestParameterSupported,
            requestUriParameterSupported: discoveryDocument.requireRequestUriRegistration,
            requireRequestUriRegistration: discoveryDocument.requireRequestUriRegistration,
            opPolicyURI: discoveryDocument.opPolicyURI,
            opTosURI: discoveryDocument.opTosURI
        )
    }
    
    func handleRequest(request: Request) throws -> OAuthDiscoveryDocument {
        return generateDiscoveryDocument()
    }
}
