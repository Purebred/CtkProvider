//
//  Token.m
//  CtkProviderToken
//
//  Created by on 10/16/20.
//

#import "Token.h"
#include "TokenUtils.h"

@implementation Token

- (TKTokenSession *)token:(TKToken *)token createSessionWithError:(NSError **)error {
    NSLog(@"%s: createSessionWithError", g_logPrefix);
    NSLog(@"%s: TKToken.tokenDriver: %@ \n", g_logPrefix, [token tokenDriver]);
    NSLog(@"%s: TKToken.delegate: %@ \n", g_logPrefix, [token delegate]);
    NSLog(@"%s: TKToken.configuration: %@ \n", g_logPrefix, [token configuration]);

    int itemCount = 0;
    TKTokenKeychainContents* tkc = [token keychainContents];
    NSArray<__kindof TKTokenKeychainItem *>* items = [tkc items];
    for ( int i = 0; i < [items count]; i++ ) {
        NSString* ilabel = [NSString stringWithFormat:@"keychainitem[%i]", itemCount++];
        TKTokenKeychainItem* tki = [items objectAtIndex:i];
        if(tki){
            NSLog(@"%s: %@.objectID: %@ \n", g_logPrefix, ilabel, [tki objectID]);
            NSLog(@"%s: %@.label: %@ \n", g_logPrefix, ilabel, [tki label]);
            NSLog(@"%s: %@.constraints: %@ \n", g_logPrefix, ilabel, [tki constraints]);
        }
    }

    return [[TokenSession alloc] initWithToken:self];
}

@end
