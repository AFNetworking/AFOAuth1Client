// AFOAuth1Client.m
//
// Copyright (c) 2011 Mattt Thompson (http://mattt.me/)
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

#import "AFHTTPClient.h"

extern NSString * const kAFOAuth1Version;

enum {
	AFOAuthSignatureMethodRejected = 0,
	AFOAuthParameterAbsent,
	AFOAuthVersionRejected,
	AFOAuthConsumerKeyUnknown,
	AFOAuthTokenRejected,
	AFOAuthSignatureInvalid,
	AFOAuthNonceUsed,
	AFOAuthTimestampRefused,
	AFOAuthTokenExpired,
	AFOAuthTokenNotRenewable,
};

typedef enum {
    AFHMACSHA1SignatureMethod = 0,
    AFPlaintextSignatureMethod,
} AFOAuthSignatureMethod;

@class AFOAuth1Token;

@interface AFOAuth1Client : AFHTTPClient

@property (nonatomic, assign) AFOAuthSignatureMethod signatureMethod;
@property (nonatomic, copy) NSString *realm;

// TODO set Nonce generator block property?

- (id)initWithBaseURL:(NSURL *)url
                  key:(NSString *)key
               secret:(NSString *)secret;

- (void)authorizeUsingOAuthWithRequestTokenPath:(NSString *)requestTokenPath
                          userAuthorizationPath:(NSString *)userAuthorizationPath
                                    callbackURL:(NSURL *)callbackURL
                                accessTokenPath:(NSString *)accessTokenPath
                                        success:(void (^)(AFOAuth1Token *accessToken))success 
                                        failure:(void (^)(NSError *error))failure;

- (void)acquireOAuthRequestTokenWithPath:(NSString *)path
                                callback:(NSURL *)url
                                 success:(void (^)(AFOAuth1Token *requestToken))success 
                                 failure:(void (^)(NSError *error))failure;

- (void)acquireOAuthAccessTokenWithPath:(NSString *)path
                           requestToken:(AFOAuth1Token *)requestToken
                               success:(void (^)(AFOAuth1Token *accessToken))success 
                               failure:(void (^)(NSError *error))failure;

@end

#pragma mark -

@interface AFOAuth1Token : NSObject {
@private
	NSString *_key;
	NSString *_secret;
    NSString *_verifier;
	NSString *_session;
	NSDate *_expiration;
    BOOL _renewable;
}

@property (readonly, nonatomic, copy) NSString *key;
@property (readonly, nonatomic, copy) NSString *secret;
@property (readonly, nonatomic, copy) NSString *verifier;
@property (readonly, nonatomic, copy) NSString *session;
@property (readonly, nonatomic, assign, getter = canBeRenewed) BOOL renewable;
@property (readonly, nonatomic, assign, getter = isExpired) BOOL expired;

- (id)initWithQueryString:(NSString *)queryString;

@end
