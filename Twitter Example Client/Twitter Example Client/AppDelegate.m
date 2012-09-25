//
//  AppDelegate.m
//  Twitter Example Client
//
//  Created by Cristiano Severini on 25/09/12.
//  Copyright (c) 2012 Crino. All rights reserved.
//

#import "AppDelegate.h"

#import "ViewController.h"

#import "AFJSONRequestOperation.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    // Override point for customization after application launch.
    self.viewController = [[ViewController alloc] initWithNibName:@"ViewController" bundle:nil];
    self.window.rootViewController = self.viewController;
    [self.window makeKeyAndVisible];
    
    
    self.twitterClient = [[AFOAuth1Client alloc] initWithBaseURL:[NSURL URLWithString:@"https://api.twitter.com/"]
                                                       clientKey:@"4oFCF0AjP4PQDUaCh5RQ"
                                                    clientSecret:@"NxAihESVsdUXSUxtHrml2VBHA0xKofYKmmGS01KaSs"];
    self.twitterClient.oauthMethod = AFOAuthMethodGet;
    
    // Your application will be sent to the background until the user authenticates, and then the app will be brought back using the callback URL
    [self.twitterClient authorizeUsingOAuthWithRequestTokenPath:@"oauth/request_token"
                                          userAuthorizationPath:@"oauth/authorize"
                                                    callbackURL:[NSURL URLWithString:@"af-twitter://success"]
                                                accessTokenPath:@"oauth/access_token"
                                                   accessMethod:@"POST"
                                                        success:^(AFOAuth1Token *accessToken) {
                                                            NSLog(@"Success: %@", accessToken);
                                                            NSLog(@"Your OAuth credentials are now set in the `Authorization` HTTP header");
                                                            
                                                            [self.twitterClient registerHTTPOperationClass:[AFJSONRequestOperation class]];
                                                            [self.twitterClient getOAuthPath:@"1/statuses/user_timeline.json" parameters:nil success:^(AFHTTPRequestOperation *operation, id responseObject) {
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
    
    return YES;
}

// forward callback to client
-(BOOL)application:(UIApplication *)application handleOpenURL:(NSURL *)url {
    return [self.twitterClient handleURL:url];
}
-(BOOL)application:(UIApplication *)application openURL:(NSURL *)url sourceApplication:(NSString *)sourceApplication annotation:(id)annotation {
    return [self.twitterClient handleURL:url];
}

- (void)applicationWillResignActive:(UIApplication *)application
{
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application
{
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later. 
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}

- (void)applicationWillEnterForeground:(UIApplication *)application
{
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application
{
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application
{
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}

@end
