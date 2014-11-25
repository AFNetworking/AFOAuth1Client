// AFOAuth1Token.h
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

#import <Foundation/Foundation.h>

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
- (instancetype)initWithQueryString:(NSString *)queryString;

/**
 Initializes an OAuth token with the specified key, secret, session, and expiration date.
 
 @param key The OAuth token key.
 @param secret The OAuth token secret.
 @param session The OAuth token session.
 @param expiration The OAuth token expiration date
 @param renewable Whether the OAuth token can be renewed.
 */
- (instancetype)initWithKey:(NSString *)key
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
