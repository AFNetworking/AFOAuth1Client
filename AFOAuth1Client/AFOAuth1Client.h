// AFOAuth1Client.m
//
// Copyright (c) 2011-2014 AFNetworking (http://afnetworking.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import <AFNetworking/AFHTTPClient.h>

typedef NS_ENUM(NSUInteger, AFOAuthSignatureMethod) {
    AFPlainTextSignatureMethod = 1,
    AFHMACSHA1SignatureMethod = 2,
};

@class AFOAuth1Token;

/**
 `AFOAuth1Client` encapsulates common patterns to authenticate against a resource server conforming to the behavior outlined in the OAuth 1.0a specification.

 @see RFC 5849 The OAuth 1.0 Protocol: https://tools.ietf.org/html/rfc5849
 */
@interface AFOAuth1Client : AFHTTPClient <NSCoding, NSCopying>

///-----------------------------------
/// @name Managing OAuth Configuration
///-----------------------------------

/**
 The method used to create an OAuth signature. `AFPlainTextSignatureMethod` by default.
 */
@property (nonatomic, assign) AFOAuthSignatureMethod signatureMethod;

/**
 The authentication realm.
 */
@property (nonatomic, copy) NSString *realm;

/**
 The client's access token.
 */
@property (nonatomic, strong) AFOAuth1Token *accessToken;

///---------------------
/// @name Initialization
///---------------------

/**
 Initializes an `AFOAuth1Client` object with the specified base URL, key, and secret.

 @param url The base URL for the HTTP client. This argument must not be `nil`.
 @param key The client key.
 @param secret The client secret.
 */
- (id)initWithBaseURL:(NSURL *)url
                  key:(NSString *)key
               secret:(NSString *)secret;

///---------------------
/// @name Authenticating
///---------------------

/**
 Creates and enqueues `AFHTTPRequestOperation` objects to make the necessary request token and access token requests using the specified parameters. 
 
 @discussion This is a convenience for doing `acquireOAuthRequestTokenWithPath:callbackURL:accessMethod:scope:success:failure` and then `acquireOAuthAccessTokenWithPath:requestToken:accessMethod:success:failure:`.
 
 @param requestTokenPath The request token URL path.
 @param userAuthorizationPath The user authorization URL path.
 @param callbackURL The callback URL.
 @param accessTokenPath The path for requesting an access token.
 @param accessMethod The HTTP method for requesting an access token.
 @param scope The requested authorization scope.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes two arguments: the OAuth credential returned by the server, and the response object sent from the server.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a single argument: the error returned from the server.
 */
- (void)authorizeUsingOAuthWithRequestTokenPath:(NSString *)requestTokenPath
                          userAuthorizationPath:(NSString *)userAuthorizationPath
                                    callbackURL:(NSURL *)callbackURL
                                accessTokenPath:(NSString *)accessTokenPath
                                   accessMethod:(NSString *)accessMethod
                                          scope:(NSString *)scope
                                        success:(void (^)(AFOAuth1Token *accessToken, id responseObject))success
                                        failure:(void (^)(NSError *error))failure;

/**
 Creates and enqueues an `AFHTTPRequestOperation` to acquire an OAuth request token with the specified path, callback URL, access method, and scope.

 @param path The URL path.
 @param callbackURL The URL to be set for `oauth_callback`. If `nil`, "oob" (out-of-band) is specified.
 @param accessMethod The HTTP method.
 @param scope The requested authorization scope.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes two arguments: the OAuth credential returned by the server, and the response object sent from the server.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a single argument: the error returned from the server.
 */
- (void)acquireOAuthRequestTokenWithPath:(NSString *)path
                             callbackURL:(NSURL *)callbackURL
                            accessMethod:(NSString *)accessMethod
                                   scope:(NSString *)scope
                                 success:(void (^)(AFOAuth1Token *requestToken, id responseObject))success
                                 failure:(void (^)(NSError *error))failure;

/**
 Creates and enqueues an `AFHTTPRequestOperation` to acquire an OAuth request token with the specified path, callback URL, access method, and scope.

 @param path The URL method.
 @param requestToken The request token.
 @param accessMethod The HTTP method.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes two arguments: the OAuth credential returned by the server, and the response object sent from the server.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a single argument: the error returned from the server.
 */
- (void)acquireOAuthAccessTokenWithPath:(NSString *)path
                           requestToken:(AFOAuth1Token *)requestToken
                           accessMethod:(NSString *)accessMethod
                                success:(void (^)(AFOAuth1Token *accessToken, id responseObject))success
                                failure:(void (^)(NSError *error))failure;

///----------------------------------------------------
/// @name Configuring Service Provider Request Handling
///----------------------------------------------------

/**
 Sets the service provider request handler and completion handler blocks.

 @param block A block to be executed when the request is made to the service provider. This block has no return value and takes a single argument: the request made to the service provider.
 @param completion A block to be executed when the request is finished. This block has no return value and takes no arguments.
 */
- (void)setServiceProviderRequestHandler:(void (^)(NSURLRequest *request))block
                              completion:(void (^)())completion;

@end

///----------------
/// @name Constants
///----------------

/**

 */
extern NSString * const kAFApplicationLaunchedWithURLNotification;

/**

 */
extern NSString * const kAFApplicationLaunchOptionsURLKey;

#pragma mark -

/**
 `AFOAuth1Token` models the credentials returned from an OAuth server, storing the key, secret, session, verifier, and whether the token is expired and can be renewed.

 OAuth credentials can be stored in the user's keychain, and retrieved on subsequent launches.
 */
@interface AFOAuth1Token : NSObject <NSCoding, NSCopying>

/**
 The OAuth token key.
 */
@property (readonly, nonatomic, copy) NSString *key;

/**
 The OAuth token secret.
 */
@property (readonly, nonatomic, copy) NSString *secret;

/**
 The OAuth token session.
 */
@property (readonly, nonatomic, copy) NSString *session;

/**
 The OAuth token verifier.
 */
@property (nonatomic, copy) NSString *verifier;

/**
 Whether the OAuth token can be renewed.
 */
@property (readonly, nonatomic, assign, getter = canBeRenewed) BOOL renewable;

/**
 Whether the OAuth token is expired.
 */
@property (readonly, nonatomic, assign, getter = isExpired) BOOL expired;

/**
 Any additional information associated with the OAuth token.
 */
@property (nonatomic, strong) NSDictionary *userInfo;

/**
 Initialize an OAuth token from a URL query string.
 
 @param queryString The query of a URL containing the OAuth token credentials.
 */
- (id)initWithQueryString:(NSString *)queryString;

/**
 Initializes an OAuth token with the specified key, secret, session, and expiration date.
 
 @param key The OAuth token key.
 @param secret The OAuth token secret.
 @param session The OAuth token session.
 @param expiration The OAuth token expiration date
 @param renewable Whether the OAuth token can be renewed.
 */
- (id)initWithKey:(NSString *)key
           secret:(NSString *)secret
          session:(NSString *)session
       expiration:(NSDate *)expiration
        renewable:(BOOL)canBeRenewed;

///---------------------
/// @name Authenticating
///---------------------

/**
 Stores the specified OAuth token for a given web service identifier in the Keychain
 with the default Keychain Accessibilty of kSecAttrAccessibleWhenUnlocked.
 
 @param token The OAuth credential to be stored.
 @param identifier The service identifier associated with the specified token.
 
 @return Whether or not the credential was stored in the keychain.
 */
+ (BOOL)storeCredential:(AFOAuth1Token *)credential
         withIdentifier:(NSString *)identifier;

/**
 Stores the specified OAuth token for a given web service identifier in the Keychain.

 @param token The OAuth credential to be stored.
 @param identifier The service identifier associated with the specified token.
 @param securityAccessibility The Keychain security accessibility to store the credential with.

 @return Whether or not the credential was stored in the keychain.
 */
+ (BOOL)storeCredential:(AFOAuth1Token *)credential
         withIdentifier:(NSString *)identifier
      withAccessibility:(id)securityAccessibility;

/**
 Retrieves the OAuth credential stored with the specified service identifier from the Keychain.
 
 @param identifier The service identifier associated with the specified credential.
 
 @return The retrieved OAuth token.
 */
+ (AFOAuth1Token *)retrieveCredentialWithIdentifier:(NSString *)identifier;

/**
 Deletes the OAuth token stored with the specified service identifier from the Keychain.
 
 @param identifier The service identifier associated with the specified token.
 
 @return Whether or not the token was deleted from the keychain.
 */
+ (BOOL)deleteCredentialWithIdentifier:(NSString *)identifier;

@end

