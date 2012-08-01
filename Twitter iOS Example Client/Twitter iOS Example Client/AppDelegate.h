//
//  AppDelegate.h
//  Twitter iOS Example Client
//
//  Created by Enrico "cHoco" Ghirardi on 01/08/12.
//  Copyright (c) 2012 Just a Dream. All rights reserved.
//

#import <UIKit/UIKit.h>

#import "AFOAuth1Client.h"
#import "AFJSONRequestOperation.h"

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;
@property (retain) AFOAuth1Client *twitterClient;

@end
