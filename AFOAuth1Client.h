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
//
// Version modded by Cristiano Severini (crino)
//

#import "AFHTTPClient.h"


typedef enum {
    AFSignatureMethodHMACSHA1 = 0,
    AFSignatureMethodPlaintext,
} AFOAuthSignatureMethod;

typedef enum {
    AFOAuthMethodHeader = 0,
    AFOAuthMethodGet,
    AFOAuthMethodPost,
} AFOAuthMethod;

extern NSString * const kAFOAuth1Version;

@class AFOAuth1Token;


@interface AFOAuth1Client : AFHTTPClient

@property (nonatomic, copy, readonly) NSString* clientKey;
@property (nonatomic, copy, readonly) NSString* clientSecret;
@property (nonatomic, copy) NSString *realm;
@property (nonatomic, strong) AFOAuth1Token* accessToken;
@property (nonatomic, assign) AFOAuthMethod oauthMethod;
@property (nonatomic, assign) AFOAuthSignatureMethod signatureMethod;


-(id)initWithBaseURL:(NSURL *)url clientKey:(NSString *)clientKey clientSecret:(NSString *)clientSecret;

-(void)setNonceBlock:(NSString*(^)())block;

-(BOOL)handleURL:(NSURL*)url;

-(void)authorizeUsingOAuthWithRequestTokenPath:(NSString *)requestTokenPath
                         userAuthorizationPath:(NSString *)userAuthorizationPath
                                   callbackURL:(NSURL *)callbackURL
                               accessTokenPath:(NSString *)accessTokenPath
                                  accessMethod:(NSString *)accessMethod
                                       success:(void (^)(AFOAuth1Token *accessToken))success
                                       failure:(void (^)(NSError *error))failure;

-(void)acquireOAuthRequestTokenWithPath:(NSString *)path
                               callback:(NSURL *)url
                           accessMethod:(NSString *)accessMethod
                                success:(void (^)(AFOAuth1Token *requestToken))success
                                failure:(void (^)(NSError *error))failure;

-(void)acquireOAuthAccessTokenWithPath:(NSString *)path
                          requestToken:(AFOAuth1Token *)requestToken
                          accessMethod:(NSString *)accessMethod
                               success:(void (^)(AFOAuth1Token *accessToken))success
                               failure:(void (^)(NSError *error))failure;

-(void)enqueueOAuthOperationWithMethod:(NSString*)method
                                  path:(NSString*)path
                            parameters:(NSDictionary*)parameters
                               success:(void(^)(AFHTTPRequestOperation *operation, id responseObject))success
                               failure:(void(^)(AFHTTPRequestOperation *operation, NSError *error))failure;

-(NSMutableURLRequest*)multipartFormOAuthRequestWithMethod:(NSString *)method
                                                      path:(NSString *)path
                                                parameters:(NSDictionary *)parameters
                                 constructingBodyWithBlock:(void (^)(id<AFMultipartFormData>))block;

-(void)getOAuthPath:(NSString *)path
         parameters:(NSDictionary *)parameters
            success:(void (^)(AFHTTPRequestOperation *, id))success
            failure:(void (^)(AFHTTPRequestOperation *, NSError *))failure;

-(void)postOAuthPath:(NSString *)path
          parameters:(NSDictionary *)parameters
             success:(void (^)(AFHTTPRequestOperation *, id))success
             failure:(void (^)(AFHTTPRequestOperation *, NSError *))failure;

@end



@interface AFOAuth1Token : NSObject

@property (nonatomic, copy, readonly) NSDictionary *extras;

@property (nonatomic, copy, readonly) NSString *token;
@property (nonatomic, copy, readonly) NSString *tokenSecret;
@property (nonatomic, copy, readonly) NSString *verifier;
@property (nonatomic, copy, readonly) NSString *session;
@property (nonatomic, assign, readonly, getter = canBeRenewed) BOOL renewable;
@property (nonatomic, assign, readonly, getter = isExpired) BOOL expired;

-(id)initWithToken:(NSString*)token tokenSecret:(NSString*)tokenSecret;
-(id)initWithToken:(NSString*)token tokenSecret:(NSString*)tokenSecret session:(NSString*)session expiration:(NSDate*)expiration reneable:(BOOL)renewable;
-(id)initWithQueryString:(NSString *)queryString;

@end


