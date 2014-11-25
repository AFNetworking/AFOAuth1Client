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

#import "AFOAuth1Client.h"

#import "AFOAuth1RequestSerializer.h"
#import "AFOAuth1Token.h"
#import "AFOAuth1Utils.h"
#import "AFURLResponseSerialization.h"

NSString * const kAFApplicationLaunchedWithURLNotification = @"kAFApplicationLaunchedWithURLNotification";
#if __IPHONE_OS_VERSION_MIN_REQUIRED
NSString * const kAFApplicationLaunchOptionsURLKey = @"UIApplicationLaunchOptionsURLKey";
#else
NSString * const kAFApplicationLaunchOptionsURLKey = @"NSApplicationLaunchOptionsURLKey";
#endif

#pragma mark -

@interface AFOAuth1Client ()
@property (nonatomic, strong) id applicationLaunchNotificationObserver;
@property (nonatomic, copy) AFServiceProviderRequestHandlerBlock serviceProviderRequestHandler;
@property (nonatomic, copy) AFServiceProviderRequestCompletionBlock serviceProviderRequestCompletion;
@end

@implementation AFOAuth1Client

#pragma mark - Properties

+ (BOOL)automaticallyNotifiesObserversOfApplicationLaunchNotificationObserver {
    return NO;
}

- (void)setApplicationLaunchNotificationObserver:(id)applicationLaunchNotificationObserver {
    if (_applicationLaunchNotificationObserver) {
        [[NSNotificationCenter defaultCenter] removeObserver:_applicationLaunchNotificationObserver];
    }
    
    [self willChangeValueForKey:@"applicationLaunchNotificationObserver"];
    _applicationLaunchNotificationObserver = applicationLaunchNotificationObserver;
    [self didChangeValueForKey:@"applicationLaunchNotificationObserver"];
}

#pragma mark - Object Life Cycle

- (instancetype)initWithBaseURL:(NSURL *)URL
                            key:(NSString *)key
                         secret:(NSString *)secret {
    NSParameterAssert(key);
    NSParameterAssert(secret);
    
    self = [super initWithBaseURL:URL];
    if (!self) {
        return nil;
    }
    
    self.requestSerializer = [AFOAuth1RequestSerializer serializerWithKey:key secret:secret];
    self.responseSerializer = [AFHTTPResponseSerializer serializer]; // FIXME: (me@lxcid.com) Review to see whether we should introduce our own response serializer?
    
    return self;
}

- (void)dealloc {
    self.applicationLaunchNotificationObserver = nil;
}

#pragma mark - OAuth 1.0a

- (void)authorizeUsingOAuthWithRequestTokenURLString:(NSString *)requestTokenURLString
                          userAuthorizationURLString:(NSString *)userAuthorizationURLString
                                         callbackURL:(NSURL *)callbackURL
                                accessTokenURLString:(NSString *)accessTokenURLString
                                        accessMethod:(NSString *)accessMethod
                                               scope:(NSString *)scope
                                             success:(void (^)(AFOAuth1Token *accessToken, id responseObject))success
                                             failure:(void (^)(NSError *error))failure {
    NSURLSessionDataTask * __unused acquireOAuthRequestTokenTask = [self acquireOAuthRequestTokenWithURLString:requestTokenURLString callbackURL:callbackURL accessMethod:(NSString *)accessMethod scope:scope success:^(AFOAuth1Token *requestToken, id responseObject) {
        __block AFOAuth1Token *currentRequestToken = requestToken;
        
        NSNotificationCenter *defaultNotificationCenter = [NSNotificationCenter defaultCenter];
        self.applicationLaunchNotificationObserver = [defaultNotificationCenter addObserverForName:kAFApplicationLaunchedWithURLNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *notification) {
            NSURL *URL = [notification.userInfo valueForKey:kAFApplicationLaunchOptionsURLKey];
            
            currentRequestToken.verifier = [[AFOAuth1Utils parametersFromQueryString:URL.query] valueForKey:@"oauth_verifier"];
            
            NSURLSessionDataTask * __unused acquireOAuthAccessTokenTask = [self acquireOAuthAccessTokenWithURLString:accessTokenURLString requestToken:currentRequestToken accessMethod:accessMethod success:^(AFOAuth1Token * accessToken, id responseObject) {
                if (self.serviceProviderRequestCompletion) {
                    self.serviceProviderRequestCompletion();
                }
                
                self.applicationLaunchNotificationObserver = nil;
                if (accessToken) {
                    if (![self.requestSerializer isKindOfClass:[AFOAuth1RequestSerializer class]]) {
                        if (failure) {
                            NSError *error = nil; // FIXME: (me@lxcid.com) Provides error info.
                            failure(error);
                        }
                        return;
                    }
                    AFOAuth1RequestSerializer *oauth1RequestSerializer = (AFOAuth1RequestSerializer *)self.requestSerializer;
                    oauth1RequestSerializer.accessToken = accessToken;
                    
                    if (success) {
                        success(accessToken, responseObject);
                    }
                } else {
                    if (failure) {
                        NSError *error = nil; // FIXME: (me@lxcid.com) Provides error info.
                        failure(error);
                    }
                }
            } failure:^(NSError *error) {
                self.applicationLaunchNotificationObserver = nil;
                if (failure) {
                    failure(error);
                }
            }];
        }];
        
        NSMutableDictionary *mutableParameters = [NSMutableDictionary dictionary];
        mutableParameters[@"oauth_token"] = requestToken.key;
        NSError *error = nil;
        NSMutableURLRequest *request = [[AFHTTPRequestSerializer serializer] requestWithMethod:@"GET" URLString:[[NSURL URLWithString:userAuthorizationURLString relativeToURL:self.baseURL] absoluteString] parameters:mutableParameters error:&error];
        if (!request) {
            if (failure) {
                failure(error);
            }
            return;
        }
        [request setHTTPShouldHandleCookies:NO];
        
        if (self.serviceProviderRequestHandler) {
            self.serviceProviderRequestHandler(request);
        } else {
#if __IPHONE_OS_VERSION_MIN_REQUIRED
            [[UIApplication sharedApplication] openURL:[request URL]];
#else
            [[NSWorkspace sharedWorkspace] openURL:[request URL]];
#endif
        }
        
    } failure:^(NSError *error) {
        if (failure) {
            failure(error);
        }
    }];
}

- (NSURLSessionDataTask *)acquireOAuthRequestTokenWithURLString:(NSString *)URLString
                                                    callbackURL:(NSURL *)callbackURL
                                                   accessMethod:(NSString *)accessMethod
                                                          scope:(NSString *)scope
                                                        success:(void (^)(AFOAuth1Token *requestToken, id responseObject))success
                                                        failure:(void (^)(NSError *error))failure {
    if (![self.requestSerializer isKindOfClass:[AFOAuth1RequestSerializer class]]) {
        if (failure) {
            NSError *error = nil; // FIXME: (me@lxcid.com) Provides error info.
            failure(error);
        }
        return nil;
    }
    AFOAuth1RequestSerializer *oauth1RequestSerializer = (AFOAuth1RequestSerializer *)self.requestSerializer;
    
    NSMutableDictionary *mutableParameters = [oauth1RequestSerializer.oauthParameters mutableCopy];
    if (callbackURL) {
        mutableParameters[@"oauth_callback"] = [callbackURL absoluteString];
    } else {
        mutableParameters[@"oauth_callback"] = @"oob";
    }
    if (scope && scope.length > 0 && !oauth1RequestSerializer.accessToken) {
        mutableParameters[@"scope"] = scope;
    }
    
    NSDictionary *parameters = [mutableParameters copy];
    NSError *error = nil;
    NSMutableURLRequest *request = [oauth1RequestSerializer requestWithMethod:accessMethod URLString:[[NSURL URLWithString:URLString relativeToURL:self.baseURL] absoluteString] parameters:parameters error:&error];
    if (error) {
        if (failure) {
            failure(error);
        }
        return nil;
    }
    
    NSURLSessionDataTask *dataTask = [self dataTaskWithRequest:request completionHandler:^(NSURLResponse *response, id responseObject, NSError *error) {
        if (error) {
            if (failure) {
                failure(error);
            }
            return;
        }
        
        if (success) {
            NSStringEncoding stringEncoding = NSUTF8StringEncoding;
            if (response.textEncodingName) {
                CFStringRef cfTextEncodingName = (__bridge CFStringRef)response.textEncodingName;
                CFStringEncoding cfStringEncoding = CFStringConvertIANACharSetNameToEncoding(cfTextEncodingName);
                if (cfStringEncoding != kCFStringEncodingInvalidId) {
                    stringEncoding = CFStringConvertEncodingToNSStringEncoding(cfStringEncoding);
                }
            }
            NSString *queryString = [[NSString alloc] initWithData:responseObject encoding:stringEncoding];
            AFOAuth1Token *accessToken = [[AFOAuth1Token alloc] initWithQueryString:queryString];
            success(accessToken, responseObject);
        }
    }];
    [dataTask resume];
    return dataTask;
}

- (NSURLSessionDataTask *)acquireOAuthAccessTokenWithURLString:(NSString *)URLString
                                                  requestToken:(AFOAuth1Token *)requestToken
                                                  accessMethod:(NSString *)accessMethod
                                                       success:(void (^)(AFOAuth1Token *accessToken, id responseObject))success
                                                       failure:(void (^)(NSError *error))failure {
    if (![self.requestSerializer isKindOfClass:[AFOAuth1RequestSerializer class]]) {
        if (failure) {
            NSError *error = nil; // FIXME: (me@lxcid.com) Provides error info.
            failure(error);
        }
        return nil;
    }
    
    AFOAuth1RequestSerializer *oauth1RequestSerializer = (AFOAuth1RequestSerializer *)self.requestSerializer;
    if (!requestToken.key) {
        NSDictionary *userInfo = [NSDictionary dictionaryWithObject:NSLocalizedStringFromTable(@"Bad OAuth response received from the server.", @"AFNetworking", nil) forKey:NSLocalizedFailureReasonErrorKey];
        NSError *error = [[NSError alloc] initWithDomain:AFURLResponseSerializationErrorDomain code:NSURLErrorBadServerResponse userInfo:userInfo];
        if (failure) {
            failure(error);
        }
        return nil;
    }
    
    oauth1RequestSerializer.accessToken = requestToken;
    
    NSMutableDictionary *mutableParameters = [oauth1RequestSerializer.oauthParameters mutableCopy];
    mutableParameters[@"oauth_token"] = requestToken.key;
    if (requestToken.verifier) {
        mutableParameters[@"oauth_verifier"] = requestToken.verifier;
    }
    
    NSDictionary *parameters = [mutableParameters copy];
    NSError *error = nil;
    NSMutableURLRequest *request = [oauth1RequestSerializer requestWithMethod:accessMethod URLString:[[NSURL URLWithString:URLString relativeToURL:self.baseURL] absoluteString] parameters:parameters error:&error];
    if (error) {
        if (failure) {
            failure(error);
        }
        return nil;
    }
    NSURLSessionDataTask *dataTask = [self dataTaskWithRequest:request completionHandler:^(NSURLResponse *response, id responseObject, NSError *error) {
        if (error) {
            if (failure) {
                failure(error);
            }
            return;
        }
        
        if (success) {
            NSStringEncoding stringEncoding = NSUTF8StringEncoding;
            if (response.textEncodingName) {
                CFStringRef cfTextEncodingName = (__bridge CFStringRef)response.textEncodingName;
                CFStringEncoding cfStringEncoding = CFStringConvertIANACharSetNameToEncoding(cfTextEncodingName);
                if (cfStringEncoding != kCFStringEncodingInvalidId) {
                    stringEncoding = CFStringConvertEncodingToNSStringEncoding(cfStringEncoding);
                }
            }
            NSString *queryString = [[NSString alloc] initWithData:responseObject encoding:stringEncoding];
            AFOAuth1Token *accessToken = [[AFOAuth1Token alloc] initWithQueryString:queryString];
            success(accessToken, responseObject);
        }
    }];
    [dataTask resume];
    return dataTask;
}

#pragma mark - Configuring Service Provider Request Handling

- (void)setServiceProviderRequestHandler:(AFServiceProviderRequestHandlerBlock)block
                              completion:(AFServiceProviderRequestCompletionBlock)completion {
    self.serviceProviderRequestHandler = block;
    self.serviceProviderRequestCompletion = completion;
}

@end
