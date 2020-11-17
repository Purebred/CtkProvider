//
//  ViewController.m
//  CtkProvider
//
//  Created by on 10/16/20.
//

#import "ViewController.h"
#import "CryptoTokenKit/CryptoTokenKit.h"
#include "CtkProviderUtils.h"

@interface ViewController ()

@end

@implementation ViewController

//-----------------------------------------------------------------------
// Utility functions
//-----------------------------------------------------------------------
-(void)resetKeychain {
    [self deleteAllKeysForSecClass:kSecClassGenericPassword];
    [self deleteAllKeysForSecClass:kSecClassInternetPassword];
    [self deleteAllKeysForSecClass:kSecClassCertificate];
    [self deleteAllKeysForSecClass:kSecClassKey];
    [self deleteAllKeysForSecClass:kSecClassIdentity];
}

-(void)deleteAllKeysForSecClass:(CFTypeRef)secClass {
    NSMutableDictionary* dict = [NSMutableDictionary dictionary];
    [dict setObject:(__bridge id)secClass forKey:(__bridge id)kSecClass];
    OSStatus result = SecItemDelete((__bridge CFDictionaryRef) dict);
    if(0 != result)
    {
    }
}

//-----------------------------------------------------------------------
// Lifecycle functions
//-----------------------------------------------------------------------

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

//-----------------------------------------------------------------------
// Click handlers
//-----------------------------------------------------------------------
- (IBAction)onDump:(id)sender {
    NSLog(@"CtkProvider log: onDump");

    TKTokenDriverConfiguration* tdc1 = nil;
    NSDictionary<TKTokenDriverClassID, TKTokenDriverConfiguration *> *l2 = [TKTokenDriverConfiguration driverConfigurations];
    int driverCount = 0;
    for (id key in l2) {
        NSString* dclabel = [NSString stringWithFormat:@"driverConfigurations[%i]", driverCount++];
        NSLog(@"CtkProvider log: %@.key: %@ \n", dclabel, key);
        tdc1 = [l2 objectForKey:key];
        NSLog(@"CtkProvider log: %@.TKTokenDriverConfiguration classID: %@ \n", dclabel, [tdc1 classID]);

        NSDictionary<TKTokenInstanceID, TKTokenConfiguration *> *l3 = [tdc1 tokenConfigurations];
        if(0 < [l3 count])
        {
            int tokenCount = 0;
            for (id key in l3) {
                NSString* tclabel = [NSString stringWithFormat:@"tokenConfiguration[%i]", tokenCount++];
                NSLog(@"CtkProvider log: %@.%@.key: %@ \n", dclabel, tclabel, key);
                
                TKTokenConfiguration* tc = [l3 objectForKey:key];
                NSLog(@"CtkProvider log: %@.%@.TKTokenConfiguration instanceID: %@ \n", dclabel, tclabel, [tc instanceID]);
                NSLog(@"CtkProvider log: %@.%@.TKTokenConfiguration configurationData: %@ \n", dclabel, tclabel, [tc configurationData]);

                int itemCount = 0;
                NSArray<__kindof TKTokenKeychainItem *>* items = [tc keychainItems];
                for ( int i = 0; i < [items count]; i++ ) {
                    NSString* ilabel = [NSString stringWithFormat:@"keychainitem[%i]", itemCount++];
                    TKTokenKeychainItem* tki = [items objectAtIndex:i];
                    if(tki){
                        NSLog(@"CtkProvider log: %@.%@.%@.TKTokenKeychainItem objectID: %@ \n", dclabel, tclabel, ilabel, [tki objectID]);
                        NSLog(@"CtkProvider log: %@.%@.%@.TKTokenKeychainItem label: %@ \n", dclabel, tclabel, ilabel, [tki label]);
                        NSLog(@"CtkProvider log: %@.%@.%@.TKTokenKeychainItem constraints: %@ \n", dclabel, tclabel, ilabel, [tki constraints]);
                    }
                }
            }
        }
        else{
            NSLog(@"CtkProvider log: no token configurations \n");
        }
    }
}

- (IBAction)onRemoveAllTokens:(id)sender {
    NSLog(@"CtkProvider log: onRemoveAllTokens");

    TKTokenDriverConfiguration* tdc1 = nil;
    NSDictionary<TKTokenDriverClassID, TKTokenDriverConfiguration *> *l2 = [TKTokenDriverConfiguration driverConfigurations];
    for (id key in l2) {
        tdc1 = [l2 objectForKey:key];

        NSDictionary<TKTokenInstanceID, TKTokenConfiguration *> *l3 = [tdc1 tokenConfigurations];
        if(0 < [l3 count])
        {
            for (id key in l3) {
                TKTokenConfiguration* tc = [l3 objectForKey:key];
                NSLog(@"CtkProvider log: removing token: %@ \n", [tc instanceID]);
                [tdc1 removeTokenConfigurationForTokenInstanceID:[tc instanceID]];
            }
        }
        else{
            NSLog(@"CtkProvider log: no token configurations to remove \n");
        }
    }

    [self resetKeychain];
}

- (IBAction)onAddDecryptionToken:(id)sender {
    NSLog(@"CtkProvider log: onAddDecryptionToken");

    SecIdentityRef identity = GetIdentity(@"decryption", @"password");
    AddItem(identity);
    CFRelease(identity);
}

- (IBAction)onAddAuthenticationToken:(id)sender {
    NSLog(@"CtkProvider log: onAddAuthenticationToken");

    SecIdentityRef identity = GetIdentity(@"authentication", @"password");
    AddItem(identity);
    CFRelease(identity);
}

- (IBAction)onAddSignatureToken:(id)sender {
    NSLog(@"CtkProvider log: onAddSignatureToken");

    SecIdentityRef identity = GetIdentity(@"signature", @"password");
    AddItem(identity);
    CFRelease(identity);
}

@end
