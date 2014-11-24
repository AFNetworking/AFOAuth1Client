//
//  AFOAuth1Client.h
//
//  Created by Joel Chen on 3/4/14.
//  Copyright (c) 2014 Joel Chen [http://lnkd.in/bwwnBWR]
//

#import <Foundation/Foundation.h>
#import "AFNetworking.h"

typedef NS_ENUM(NSUInteger, AFOAuthSignatureMethod) {
    AFPlainTextSignatureMethod = 1,
    AFHMACSHA1SignatureMethod = 2,
};

typedef enum {
    AFFormURLParameterEncoding,
    AFJSONParameterEncoding,
    AFPropertyListParameterEncoding,
} AFHTTPClientParameterEncoding;

typedef void (^AFServiceProviderRequestHandlerBlock)(NSURLRequest *request);
typedef void (^AFServiceProviderRequestCompletionBlock)();

@class AFOAuth1Token;

@interface AFOAuth1Client : NSObject <NSCoding, NSCopying>
@property (readwrite, nonatomic, copy) NSURL *url;
@property (readwrite, nonatomic, copy) NSString *key;
@property (readwrite, nonatomic, copy) NSString *secret;
@property (readwrite, nonatomic, strong) id applicationLaunchNotificationObserver;
@property (readwrite, nonatomic, copy) AFServiceProviderRequestHandlerBlock serviceProviderRequestHandler;
@property (readwrite, nonatomic, copy) AFServiceProviderRequestCompletionBlock serviceProviderRequestCompletion;
///-----------------------------------
/// @name Managing OAuth Configuration
///-----------------------------------

/**
 
 */
@property (nonatomic, assign) AFOAuthSignatureMethod signatureMethod;

/**
 
 */
@property (nonatomic, copy) NSString *realm;

/**
 
 */
@property (nonatomic, strong) AFOAuth1Token *accessToken;

/**
 
 */
@property (nonatomic, strong) NSString *oauthAccessMethod;

@property (nonatomic, strong) NSMutableDictionary *defaultHeaders;

@property (nonatomic, assign) AFHTTPClientParameterEncoding parameterEncoding;

@property (nonatomic, assign) NSStringEncoding stringEncoding;

+ (NSString *)queryStringFromParameters:(NSDictionary *)parameters encoding:(NSStringEncoding)stringEncoding;

- (NSMutableURLRequest *)requestWithMethod:(NSString *)method path:(NSString *)path parameters:(NSDictionary *)parameters;

///---------------------
/// @name Initialization
///---------------------

/**
 
 */
- (id)initWithBaseURL:(NSURL *)url
                  key:(NSString *)key
               secret:(NSString *)secret;

///---------------------
/// @name Authenticating
///---------------------

/**
 
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
 
 */
- (void)acquireOAuthRequestTokenWithPath:(NSString *)path
                             callbackURL:(NSURL *)url
                            accessMethod:(NSString *)accessMethod
                                   scope:(NSString *)scope
                                 success:(void (^)(AFOAuth1Token *requestToken, id responseObject))success
                                 failure:(void (^)(NSError *error))failure;

/**
 
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
 
 */
@interface AFOAuth1Token : NSObject <NSCoding, NSCopying>

/**
 
 */
@property (readwrite, nonatomic, copy) NSString *key;

/**
 
 */
@property (readwrite, nonatomic, copy) NSString *secret;

/**
 
 */
@property (readwrite, nonatomic, copy) NSString *session;

@property (readwrite, nonatomic, strong) NSDate *expiration;
/**
 
 */
@property (nonatomic, copy) NSString *verifier;

/**
 
 */
@property (readwrite, nonatomic, assign, getter = canBeRenewed) BOOL renewable;

/**
 
 */
@property (readonly, nonatomic, assign, getter = isExpired) BOOL expired;

/**
 
 */
@property (nonatomic, strong) NSDictionary *userInfo;

/**
 
 */
- (id)initWithQueryString:(NSString *)queryString;

/**
 
 */
- (id)initWithKey:(NSString *)key
           secret:(NSString *)secret
          session:(NSString *)session
       expiration:(NSDate *)expiration
        renewable:(BOOL)canBeRenewed;

#ifdef _SECURITY_SECITEM_H_
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

#endif

@end
