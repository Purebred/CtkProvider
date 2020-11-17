//
//  TokenDriver.m
//  CtkProviderToken
//
//  Created by on 10/16/20.
//

#import "Token.h"
#include "TokenUtils.h"

@implementation TokenDriver

- (TKToken *)tokenDriver:(TKTokenDriver *)driver tokenForConfiguration:(TKTokenConfiguration *)configuration error:(NSError **)error {
    NSLog(@"%s: tokenForConfiguration", g_logPrefix);
    NSLog(@"%s: *TKToken.tokenDriver: %@ \n", g_logPrefix, driver);

    return [[Token alloc] initWithTokenDriver:self instanceID:configuration.instanceID];
}

@end
