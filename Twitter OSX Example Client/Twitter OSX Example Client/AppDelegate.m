//
//  AppDelegate.m
//  Twitter OSX Example Client
//
//  Created by Enrico "cHoco" Ghirardi on 01/08/12.
//  Copyright (c) 2012 Just a Dream. All rights reserved.
//

#import "AppDelegate.h"

@implementation AppDelegate

@synthesize twitterClient;

- (void)dealloc
{
    [twitterClient release];
    [super dealloc];
}

- (void)getUrl:(NSAppleEventDescriptor *)event withReplyEvent:(NSAppleEventDescriptor *)replyEvent
{
    NSString *urlStr = [[event paramDescriptorForKeyword:keyDirectObject] stringValue];
    NSURL *url = [NSURL URLWithString:urlStr];
    NSLog(@"Callback: %@", url);
    NSDictionary *info = [NSDictionary dictionaryWithObject:url forKey:kAFApplicationLaunchOptionsURLKey];
    NSNotification *notification = [NSNotification notificationWithName:kAFApplicationLaunchedWithURLNotification object:self userInfo:info];
    [[NSNotificationCenter defaultCenter] postNotification:notification];
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    [[NSAppleEventManager sharedAppleEventManager] setEventHandler:self andSelector:@selector(getUrl:withReplyEvent:) forEventClass:kInternetEventClass andEventID:kAEGetURL];
    LSSetDefaultHandlerForURLScheme((CFStringRef)@"af-twitter", (CFStringRef)[[NSBundle mainBundle] bundleIdentifier]);
    
    twitterClient = [[[AFOAuth1Client alloc] initWithBaseURL:[NSURL URLWithString:@"https://api.twitter.com/"] key:@"4oFCF0AjP4PQDUaCh5RQ" secret:@"NxAihESVsdUXSUxtHrml2VBHA0xKofYKmmGS01KaSs"] autorelease];
    
    // Your application will be sent to the background until the user authenticates, and then the app will be brought back using the callback URL
    [twitterClient authorizeUsingOAuthWithRequestTokenPath:@"oauth/request_token" userAuthorizationPath:@"oauth/authorize" callbackURL:[NSURL URLWithString:@"af-twitter://success"] accessTokenPath:@"oauth/access_token" accessMethod:@"POST" success:^(AFOAuth1Token *accessToken) {
        NSLog(@"Success: %@", accessToken);
        NSLog(@"Your OAuth credentials are now set in the `Authorization` HTTP header");
        
        [twitterClient registerHTTPOperationClass:[AFJSONRequestOperation class]];
        [twitterClient getPath:@"1/statuses/user_timeline.json" parameters:nil success:^(AFHTTPRequestOperation *operation, id responseObject) {
            NSArray *responseArray = (NSArray *)responseObject;
            [responseArray enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
                NSLog(@"obj: %@", obj);
            }];
        } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
            NSLog(@"error: %@", error);
        }];
    } failure:^(NSError *error) {
        NSLog(@"Error: %@", error);
    }];
}

@end
