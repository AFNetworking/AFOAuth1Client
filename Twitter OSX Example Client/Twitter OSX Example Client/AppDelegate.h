//
//  AppDelegate.h
//  Twitter OSX Example Client
//
//  Created by Enrico "cHoco" Ghirardi on 01/08/12.
//  Copyright (c) 2012 Just a Dream. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#import "AFOAuth1Client.h"
#import "AFJSONRequestOperation.h"

@interface AppDelegate : NSObject <NSApplicationDelegate>

@property (assign) IBOutlet NSWindow *window;
@property (retain) AFOAuth1Client *twitterClient;

@end
