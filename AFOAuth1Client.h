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
extern NSString * const kAFApplicationLaunchedWithURLNotification;
extern NSString * const kAFApplicationLaunchOptionsURLKey;

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
@property (nonatomic, strong) AFOAuth1Token *accessToken;
@property (nonatomic, strong) NSString *oauthAccessMethod;

// TODO set Nonce generator block property?

- (id)initWithBaseURL:(NSURL *)url
                  key:(NSString *)key
               secret:(NSString *)secret;

- (void)authorizeUsingOAuthWithRequestTokenPath:(NSString *)requestTokenPath
                          userAuthorizationPath:(NSString *)userAuthorizationPath
                                    callbackURL:(NSURL *)callbackURL
                                accessTokenPath:(NSString *)accessTokenPath
                                   accessMethod:(NSString *)accessMethod
                                        success:(void (^)(AFOAuth1Token *accessToken))success 
                                        failure:(void (^)(NSError *error))failure;

- (void)acquireOAuthRequestTokenWithPath:(NSString *)path
                                callback:(NSURL *)url
                            accessMethod:(NSString *)accessMethod
                                 success:(void (^)(AFOAuth1Token *requestToken))success 
                                 failure:(void (^)(NSError *error))failure;

- (void)acquireOAuthAccessTokenWithPath:(NSString *)path
                           requestToken:(AFOAuth1Token *)requestToken
                           accessMethod:(NSString *)accessMethod
                                success:(void (^)(AFOAuth1Token *accessToken))success 
                                failure:(void (^)(NSError *error))failure;

#pragma mark -

///---------------------------
/// @name Making HTTP Requests
///---------------------------

/**
 Creates an `AFHTTPRequestOperation` with a `GET` request, and enqueues it to the HTTP client's operation queue.
 
 @param path The path to be appended to the HTTP client's base URL and used as the request URL.
 @param parameters The parameters to be encoded and appended as the query string for the request URL.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes two arguments: the created request operation and the object created from the response data of request.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the resonse data. This block has no return value and takes two arguments:, the created request operation and the `NSError` object describing the network or parsing error that occurred.
 
 @see HTTPRequestOperationWithRequest:success:failure
 */
- (void)getPath:(NSString *)path
     parameters:(NSDictionary *)parameters
        success:(void (^)(AFHTTPRequestOperation *operation, id responseObject))success
        failure:(void (^)(AFHTTPRequestOperation *operation, NSError *error))failure;

/**
 Creates an `AFHTTPRequestOperation` with a `POST` request, and enqueues it to the HTTP client's operation queue.
 
 @param path The path to be appended to the HTTP client's base URL and used as the request URL.
 @param parameters The parameters to be encoded and set in the request HTTP body.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes two arguments: the created request operation and the object created from the response data of request.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the resonse data. This block has no return value and takes two arguments:, the created request operation and the `NSError` object describing the network or parsing error that occurred.
 
 @see HTTPRequestOperationWithRequest:success:failure
 */
- (void)postPath:(NSString *)path 
      parameters:(NSDictionary *)parameters 
         success:(void (^)(AFHTTPRequestOperation *operation, id responseObject))success
         failure:(void (^)(AFHTTPRequestOperation *operation, NSError *error))failure;

/**
 Creates an `AFHTTPRequestOperation` with a `PUT` request, and enqueues it to the HTTP client's operation queue.
 
 @param path The path to be appended to the HTTP client's base URL and used as the request URL.
 @param parameters The parameters to be encoded and set in the request HTTP body.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes two arguments: the created request operation and the object created from the response data of request.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the resonse data. This block has no return value and takes two arguments:, the created request operation and the `NSError` object describing the network or parsing error that occurred.
 
 @see HTTPRequestOperationWithRequest:success:failure
 */
- (void)putPath:(NSString *)path 
     parameters:(NSDictionary *)parameters 
        success:(void (^)(AFHTTPRequestOperation *operation, id responseObject))success
        failure:(void (^)(AFHTTPRequestOperation *operation, NSError *error))failure;

/**
 Creates an `AFHTTPRequestOperation` with a `DELETE` request, and enqueues it to the HTTP client's operation queue.
 
 @param path The path to be appended to the HTTP client's base URL and used as the request URL.
 @param parameters The parameters to be encoded and set in the request HTTP body.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes two arguments: the created request operation and the object created from the response data of request.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the resonse data. This block has no return value and takes two arguments:, the created request operation and the `NSError` object describing the network or parsing error that occurred.
 
 @see HTTPRequestOperationWithRequest:success:failure
 */
- (void)deletePath:(NSString *)path 
        parameters:(NSDictionary *)parameters 
           success:(void (^)(AFHTTPRequestOperation *operation, id responseObject))success
           failure:(void (^)(AFHTTPRequestOperation *operation, NSError *error))failure;

/**
 Creates an `AFHTTPRequestOperation` with a `PATCH` request, and enqueues it to the HTTP client's operation queue.
 
 @param path The path to be appended to the HTTP client's base URL and used as the request URL.
 @param parameters The parameters to be encoded and set in the request HTTP body.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes two arguments: the created request operation and the object created from the response data of request.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the resonse data. This block has no return value and takes two arguments:, the created request operation and the `NSError` object describing the network or parsing error that occurred.
 
 @see HTTPRequestOperationWithRequest:success:failure
 */
- (void)patchPath:(NSString *)path
       parameters:(NSDictionary *)parameters 
          success:(void (^)(AFHTTPRequestOperation *operation, id responseObject))success
          failure:(void (^)(AFHTTPRequestOperation *operation, NSError *error))failure;


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
