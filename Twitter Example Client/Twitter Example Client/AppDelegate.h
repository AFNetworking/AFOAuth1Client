//
//  AppDelegate.h
//  Twitter Example Client
//
//  Created by Cristiano Severini on 25/09/12.
//  Copyright (c) 2012 Crino. All rights reserved.
//

#import <UIKit/UIKit.h>

@class ViewController;

#import "AFOAuth1Client.h"

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property (strong, nonatomic) ViewController *viewController;

@property (strong, nonatomic) AFOAuth1Client* twitterClient;

@end
