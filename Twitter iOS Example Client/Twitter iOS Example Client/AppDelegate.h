//
//  AppDelegate.h
//  Twitter iOS Example Client
//
//  Created by Enrico Ghirardi on 02/01/13.
//  Copyright (c) 2013 Just a Dream. All rights reserved.
//

#import <UIKit/UIKit.h>

#import "AFOAuth1Client.h"
#import "AFJSONRequestOperation.h"

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) AFOAuth1Client *twitterClient;

@end
