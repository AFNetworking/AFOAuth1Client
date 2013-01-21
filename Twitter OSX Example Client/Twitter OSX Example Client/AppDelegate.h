//
//  AppDelegate.h
//  Twitter OSX Example Client
//
//  Created by Enrico Ghirardi on 02/01/13.
//  Copyright (c) 2013 Just a Dream. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#import "AFOAuth1Client.h"
#import "AFJSONRequestOperation.h"

@interface AppDelegate : NSObject <NSApplicationDelegate>

@property (weak) IBOutlet NSWindow *window;
@property (strong) AFOAuth1Client *twitterClient;

@end
