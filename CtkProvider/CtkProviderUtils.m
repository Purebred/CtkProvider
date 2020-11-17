//
//  CtkProviderUtils.m
//  CtkProvider
//
//  Created on 10/22/20.
//

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#import "CryptoTokenKit/CryptoTokenKit.h"

NSString* GetAsHex(const unsigned char* buf, int len)
{
    NSMutableString* retval = [NSMutableString stringWithCapacity:(len * 2 + 1)];
    NSInteger t;
    for (t=0; t<len; ++t) {
      [retval appendFormat:@"%02X", buf[t]];
    }
    return retval;
}

NSString* HashAndHexCert(SecCertificateRef certificateRef)
{
    NSData* certificateData = (__bridge_transfer NSData*)SecCertificateCopyData(certificateRef);
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256([certificateData bytes], (CC_LONG)[certificateData length], result);
    NSString* label = GetAsHex(result, CC_SHA256_DIGEST_LENGTH);
    return label;
}

SecIdentityRef GetIdentity(NSString* label, NSString* password)
{
    OSStatus securityError = errSecSuccess;

    // Read data from file bundled with app
    NSURL* pkcs12Url = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:label ofType:@"p12"]];
    if(nil == pkcs12Url)
    {
        NSString* baseError = @"Failed to prepare path to PKCS12 file with label";
        NSLog(@"%s %d %s - %s:  %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, [baseError UTF8String], [label UTF8String]);
        return nil;
    }
    
    NSData *PKCS12Data = [NSData dataWithContentsOfURL:pkcs12Url];
    if(nil == PKCS12Data)
    {
        PKCS12Data = [NSData dataWithContentsOfFile:[pkcs12Url absoluteString]];
    }
    
    if(nil == PKCS12Data)
    {
        NSString* baseError = @"Error following failure to read PKCS #12 data";
        NSLog(@"%s %d %s - %s:  %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, [baseError UTF8String], [[pkcs12Url absoluteString] UTF8String]);
        return nil;
    }

    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    
    // Define options for SecPKCS12Import
    NSMutableDictionary * optionsDictionary = [[NSMutableDictionary alloc] init];
    [optionsDictionary setObject:(id)password forKey:(id)kSecImportExportPassphrase];
    [optionsDictionary setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
    [optionsDictionary setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
    
    //Define an array to receive the data parsed from the PKCS12 blob
    CFArrayRef items = nil;
    
    //Parse the PKCS12 blob
    securityError = SecPKCS12Import(inPKCS12Data, (CFDictionaryRef)optionsDictionary, &items);
    if(errSecSuccess != securityError)
    {
        NSString* baseError = @"Error following failure to parse PKCS #12 data";
        NSLog(@"%s %d %s - %s %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, [baseError UTF8String], [[[NSNumber numberWithInt:securityError] stringValue] UTF8String]);
        return nil;
    }
    else
    {
        CFDictionaryRef pkcs12Contents = (CFDictionaryRef)CFArrayGetValueAtIndex(items, 0);
        if(CFDictionaryContainsKey(pkcs12Contents, kSecImportItemIdentity))
        {
            //Grab the identity from the dictionary
            SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(pkcs12Contents, kSecImportItemIdentity);
            CFRetain(identity);
            
            //To associate an ACL with the private key, it must be added as a private key (not as part of an identity).
            //See https://developer.apple.com/forums/thread/664413
            SecCertificateRef certificateRef = nil;
            SecKeyRef privKey = nil;

            securityError = SecIdentityCopyCertificate(identity, &certificateRef);
            if(errSecSuccess != securityError)
            {
                CFRelease(items);
                CFRelease(identity);
                NSString* baseError = @"Failed to copy certificate reference from identity read from PKCS #12 data";
                NSLog(@"%s %d %s - %s %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, [baseError UTF8String], [[[NSNumber numberWithInt:securityError] stringValue] UTF8String]);
                return nil;
            }

            securityError = SecIdentityCopyPrivateKey(identity, &privKey);
            if(errSecSuccess != securityError)
            {
                CFRelease(identity);
                CFRelease(items);
                NSString* baseError = @"Failed to copy private key reference from identity read from PKCS #12 data";
                NSLog(@"%s %d %s - %s %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, [baseError UTF8String], [[[NSNumber numberWithInt:securityError] stringValue] UTF8String]);
                return nil;
            }

            //Keys and tokens are labeled using a hash of the certificate for convenience.
            NSString* label = HashAndHexCert(certificateRef);

            //create an access control object. the second parameter is chosen from accessibility values:
            // https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values?language=objc.
            //the third parameter is one of more SecAccessControlCreateFlags:
            // https://developer.apple.com/documentation/security/secaccesscontrolcreateflags?language=objc
            //In this case, the key is only available on one device when a passcode is set and user must authenticate to
            //use the key (with either device passcode or biometric).
            SecAccessControlRef access =
                SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                kSecAccessControlUserPresence,
                                                nil);
            
            NSMutableDictionary* dict = [[NSMutableDictionary alloc]init];
            [dict setObject:label forKey:(id)kSecAttrLabel];
            [dict setObject:(__bridge id)privKey forKey:(id)kSecValueRef];
            [dict setObject:(__bridge id)access forKey:(id)kSecAttrAccessControl];

            securityError = SecItemAdd((CFDictionaryRef)dict, nil);
            if(errSecSuccess != securityError && errSecDuplicateItem != securityError)
            {
                NSLog(@"%s %d %s - %s %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, "SecItemAdd failed to import key harvested from PKCS #12 data with error code ", [[[NSNumber numberWithInt:securityError] stringValue] UTF8String]);
            }

            NSMutableDictionary* dict2 = [[NSMutableDictionary alloc]init];
            [dict2 setObject:(__bridge id)certificateRef forKey:(id)kSecValueRef];
            [dict2 setObject:label forKey:(id)kSecAttrLabel];
            
            securityError = SecItemAdd((CFDictionaryRef)dict2, nil);
            if(errSecSuccess != securityError && errSecDuplicateItem != securityError)
            {
                NSLog(@"%s %d %s - %s %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, "SecItemAdd failed to import certificate harvested from PKCS #12 data with error code ", [[[NSNumber numberWithInt:securityError] stringValue] UTF8String]);
            }

            CFRelease(certificateRef);
            CFRelease(privKey);
            CFRelease(access);
            CFRelease(items);

            return identity;
        }
    }
    return nil;
}

void AddItem(SecIdentityRef identity)
{
    // Read the certificate from the identity
    SecCertificateRef certificateRef;
    OSStatus securityError = SecIdentityCopyCertificate(identity, &certificateRef);
    if(errSecSuccess != securityError)
    {
        NSLog(@"%s %d %s - %s %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, "SecIdentityCopyCertificate failed with error code ", [[[NSNumber numberWithInt:securityError] stringValue] UTF8String]);
        return;
    }

    // Generate a SHA256 hash of the certificate and convert to ASCII hex for use as label
    NSString* label = HashAndHexCert(certificateRef);
    
    // Access the driver configurations available to the containing app
    TKTokenDriverConfiguration* tokenDriverConfiguration = nil;
    NSDictionary<TKTokenDriverClassID, TKTokenDriverConfiguration *>* driverConfigurations = [TKTokenDriverConfiguration driverConfigurations];

    // There should be just one named with the bundle identifier of the extension
    for (id key in driverConfigurations) {
        tokenDriverConfiguration = [driverConfigurations objectForKey:key];
    }

    // Add a token configuration to the driver using the SHA256 hash as the label
    TKTokenConfiguration* tokenConfiguration = [tokenDriverConfiguration addTokenConfigurationForTokenInstanceID:label];

    // Create a certificate and a key object to add to the keychain
    TKTokenKeychainCertificate* tokenKeychainCertificate = [[TKTokenKeychainCertificate alloc]initWithCertificate:certificateRef objectID:label];
    TKTokenKeychainKey* tokenKeychainKey = [[TKTokenKeychainKey alloc]initWithCertificate:certificateRef objectID:label];

    // Create an array with the items and assign to the token configuration
    NSArray<TKTokenKeychainItem *>* keychainItems = [NSArray arrayWithObjects:tokenKeychainCertificate, tokenKeychainKey, nil];
    tokenConfiguration.keychainItems = keychainItems;
    CFRelease(certificateRef);
}
