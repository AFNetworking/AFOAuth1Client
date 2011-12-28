//
//  ViewController.m
//  Twitter Example Client
//
//  Created by Mattt Thompson on 11/12/27.
//  Copyright (c) 2011年 __MyCompanyName__. All rights reserved.
//

#import "ViewController.h"

#import "AFOAuth1Client.h"

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    AFOAuth1Client *twitterClient = [[[AFOAuth1Client alloc] initWithBaseURL:[NSURL URLWithString:@"https://api.twitter.com/oauth/"] key:@"4oFCF0AjP4PQDUaCh5RQ" secret:@"NxAihESVsdUXSUxtHrml2VBHA0xKofYKmmGS01KaSs"] autorelease];
    
    // Your application will be sent to the background until the user authenticates, and then the app will be brought back using the callback URL
    [twitterClient authorizeUsingOAuthWithRequestTokenPath:@"request_token" userAuthorizationPath:@"authorize" callbackURL:[NSURL URLWithString:@"af-twitter://success"] accessTokenPath:@"access_token" success:^(AFOAuth1Token *accessToken) {
        NSLog(@"Success: %@", accessToken);
        NSLog(@"Your OAuth credentials are now set in the `Authorization` HTTP header");
    } failure:^(NSError *error) {
        NSLog(@"Error: %@", error);
    }];
    
    
}

- (void)viewDidUnload {
    [super viewDidUnload];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
}

- (void)viewWillDisappear:(BOOL)animated {
	[super viewWillDisappear:animated];
}

- (void)viewDidDisappear:(BOOL)animated {
	[super viewDidDisappear:animated];
}

@end
