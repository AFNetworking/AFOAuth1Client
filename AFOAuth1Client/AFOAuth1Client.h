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

#import "AFHTTPSessionManager.h"

///---------------------------
/// @name Forward Declarations
///---------------------------

@class AFOAuth1Token;

///-----------------------
/// @name Type Definitions
///-----------------------

typedef void (^AFServiceProviderRequestHandlerBlock)(NSURLRequest *request);
typedef void (^AFServiceProviderRequestCompletionBlock)();

///----------------
/// @name Constants
///----------------

/**
 
 */
extern NSString * const kAFApplicationLaunchedWithURLNotification;

/**
 
 */
extern NSString * const kAFApplicationLaunchOptionsURLKey;

/**
 `AFOAuth1Client` encapsulates common patterns to authenticate against a resource server conforming to the behavior outlined in the OAuth 1.0a specification.
 
 @see RFC 5849 The OAuth 1.0 Protocol: https://tools.ietf.org/html/rfc5849
 */
@interface AFOAuth1Client : AFHTTPSessionManager <NSCoding, NSCopying>

///---------------------
/// @name Initialization
///---------------------

/**
 Initializes an `AFOAuth1Client` object with the specified base URL, key, and secret.
 
 @param url The base URL for the HTTP client. This argument must not be `nil`.
 @param key The client key.
 @param secret The client secret.
 */
- (instancetype)initWithBaseURL:(NSURL *)url
                            key:(NSString *)key
                         secret:(NSString *)secret;

///---------------------
/// @name Authenticating
///---------------------

/**
 Perform some `NSURLSessionDataTask`s objects to make the necessary request token and access token requests using the specified parameters.
 
 @discussion This is a convenience for doing `acquireOAuthRequestTokenWithURLString:callbackURL:accessMethod:scope:success:failure` and then `acquireOAuthAccessTokenWithURLString:requestToken:accessMethod:success:failure:`.
 
 @param requestTokenURLString The request token URL string.
 @param userAuthorizationURLString The user authorization URL string.
 @param callbackURL The callback URL.
 @param accessTokenURLString The URL string for requesting an access token.
 @param accessMethod The HTTP method for requesting an access token.
 @param scope The requested authorization scope.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes two arguments: the OAuth credential returned by the server, and the response object sent from the server.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a single argument: the error returned from the server.
 */
- (void)authorizeUsingOAuthWithRequestTokenURLString:(NSString *)requestTokenURLString
                          userAuthorizationURLString:(NSString *)userAuthorizationURLString
                                         callbackURL:(NSURL *)callbackURL
                                accessTokenURLString:(NSString *)accessTokenURLString
                                        accessMethod:(NSString *)accessMethod
                                               scope:(NSString *)scope
                                             success:(void (^)(AFOAuth1Token *accessToken, id responseObject))success
                                             failure:(void (^)(NSError *error))failure;

/**
 Performs a `NSURLSessionDataTask` to acquire an OAuth request token with the specified URL string, callback URL, access method, and scope.
 
 @param URLString The URL string.
 @param callbackURL The URL to be set for `oauth_callback`. If `nil`, "oob" (out-of-band) is specified.
 @param accessMethod The HTTP method.
 @param scope The requested authorization scope.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes two arguments: the OAuth credential returned by the server, and the response object sent from the server.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a single argument: the error returned from the server.
 */
- (NSURLSessionDataTask *)acquireOAuthRequestTokenWithURLString:(NSString *)URLString
                                                    callbackURL:(NSURL *)callbackURL
                                                   accessMethod:(NSString *)accessMethod
                                                          scope:(NSString *)scope
                                                        success:(void (^)(AFOAuth1Token *requestToken, id responseObject))success
                                                        failure:(void (^)(NSError *error))failure;

/**
 Performs a `NSURLSessionDataTask` to acquire an OAuth access token with the specified URL string, request token and access method.
 
 @param URLString The URL string.
 @param requestToken The request token.
 @param accessMethod The HTTP method.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes two arguments: the OAuth credential returned by the server, and the response object sent from the server.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a single argument: the error returned from the server.
 */
- (NSURLSessionDataTask *)acquireOAuthAccessTokenWithURLString:(NSString *)URLString
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
- (void)setServiceProviderRequestHandler:(AFServiceProviderRequestHandlerBlock)block
                              completion:(AFServiceProviderRequestCompletionBlock)completion;

@end
