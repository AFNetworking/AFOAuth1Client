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

 */
@interface AFOAuth1Client : AFHTTPSessionManager <NSCoding, NSCopying>

///---------------------
/// @name Initialization
///---------------------

/**

 */
- (instancetype)initWithBaseURL:(NSURL *)url
                            key:(NSString *)key
                         secret:(NSString *)secret;

///---------------------
/// @name Authenticating
///---------------------

/**

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

 */
- (NSURLSessionDataTask *)acquireOAuthRequestTokenWithURLString:(NSString *)URLString
                                                    callbackURL:(NSURL *)callbackURL
                                                   accessMethod:(NSString *)accessMethod
                                                          scope:(NSString *)scope
                                                        success:(void (^)(AFOAuth1Token *requestToken, id responseObject))success
                                                        failure:(void (^)(NSError *error))failure;

/**

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
 
 */
- (void)setServiceProviderRequestHandler:(AFServiceProviderRequestHandlerBlock)block
                              completion:(AFServiceProviderRequestCompletionBlock)completion;

@end
