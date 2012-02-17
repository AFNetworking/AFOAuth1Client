//
//  AppDelegate.m
//  TwitterMacExample
//
//  Created by David Keegan on 12/28/11.
//  Copyright (c) 2011 __MyCompanyName__. All rights reserved.
//

#import "AppDelegate.h"
#import "AFOAuth1Client.h"

@implementation AppDelegate

@synthesize window = _window;

- (void)dealloc
{
    [super dealloc];
}

- (void)getUrl:(NSAppleEventDescriptor *)event withReplyEvent:(NSAppleEventDescriptor *)replyEvent
{
    NSString *urlStr = [[event paramDescriptorForKeyword:keyDirectObject] stringValue];
    NSLog(@"Callback: %@", urlStr);
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    [[NSAppleEventManager sharedAppleEventManager] setEventHandler:self andSelector:@selector(getUrl:withReplyEvent:) forEventClass:kInternetEventClass andEventID:kAEGetURL];
    LSSetDefaultHandlerForURLScheme((CFStringRef)@"af-twitter", (CFStringRef)[[NSBundle mainBundle] bundleIdentifier]);
    
    AFOAuth1Client *twitterClient = [[[AFOAuth1Client alloc] initWithBaseURL:[NSURL URLWithString:@"https://api.twitter.com/oauth/"] key:@"4oFCF0AjP4PQDUaCh5RQ" secret:@"NxAihESVsdUXSUxtHrml2VBHA0xKofYKmmGS01KaSs"] autorelease];
    
    // Your application will be sent to the background until the user authenticates, and then the app will be brought back using the callback URL
    [twitterClient authorizeUsingOAuthWithRequestTokenPath:@"request_token" userAuthorizationPath:@"authorize" callbackURL:[NSURL URLWithString:@"af-twitter://success"] accessTokenPath:@"access_token" success:^(AFOAuth1Token *accessToken) {
        NSLog(@"Success: %@", accessToken);
        NSLog(@"Your OAuth credentials are now set in the `Authorization` HTTP header");
    } failure:^(NSError *error) {
        NSLog(@"Error: %@", error);
    }];
}

@end
