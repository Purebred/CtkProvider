//
//  TokenSession.m
//  CtkProviderToken
//
//  Created by on 10/16/20.
//

#import "Token.h"
#include <CommonCrypto/CommonDigest.h>
#include "TokenUtils.h"
#include "NSData+Conversion.h"

//XXX***SET THIS TO 0 TO AVOID LOGGING SENSITIVE DATA
#define USE_LOG_SPECIAL 1
#ifdef USE_LOG_SPECIAL
#define LOG_SPECIAL(f,p,s) NSLog(f,p,s);
#else
#define LOG_SPECIAL(f,p,s)
#endif

/*
 This global keyCache was added because Mail.app abusively invokes decryptData. The first
 attempt at using a cache was via the TokenSession object. Unfortunately, the session varies
 across calls for the same decryption event, so the cache was moved to this global variable.
 */
#define USE_CACHE 1
NSMutableDictionary *keyCache, *timeCache;
NSLock* keyCacheLock;
SecKeyRef getKey(NSString* label)
{
#if USE_CACHE
    if(nil == keyCache)
    {
        keyCacheLock = [[NSLock alloc]init];
        NSLog(@"Initializing cache: %i", [[NSProcessInfo processInfo]processIdentifier]);
        keyCache = [[NSMutableDictionary alloc]init];
        timeCache = [[NSMutableDictionary alloc]init];
    }
    
    NSLog(@"Checking cache %i for key %@", [[NSProcessInfo processInfo]processIdentifier], label);

    if(0 == [keyCache count])
    {
        NSLog(@"Cache is empty: %i", [[NSProcessInfo processInfo]processIdentifier]);
    }
    else{
        for(id key in keyCache)
        {
            if([timeCache objectForKey:key])
            {
                NSLog(@"Key %@ in cache with %@", key, [timeCache objectForKey:key]);
            }
            else
            {
                NSLog(@"Key %@ in cache without time value", key);
            }
        }
    }
    
    SecKeyRef retval = nil;
    
    SecCertificateRef certificateRef = GetCertificateRef(label);
    if(!certificateRef)
    {
        [keyCacheLock lock];
        [keyCache removeObjectForKey:label];
        [timeCache removeObjectForKey:label];
        [keyCacheLock unlock];
        return nil;
    }
    CFRelease(certificateRef);

    NSDate* n = [NSDate date];
    NSDate* c = [timeCache objectForKey:label];
    if(c)
    {
        NSTimeInterval d = [n timeIntervalSinceDate:c];
        if(d > 180.0){
            NSLog(@"Removing %@ item from cache with elapsed time %g", label, d);
            [keyCacheLock lock];
            [keyCache removeObjectForKey:label];
            [timeCache removeObjectForKey:label];
            [keyCacheLock unlock];
        }
    }
    [keyCacheLock lock];
    if(keyCache[label]) {
        NSLog(@"Returning %@ item from cache", label);
        retval = (__bridge SecKeyRef)keyCache[label];
    }
    else {
        NSLog(@"Cache miss for key %@", label);
    }
    [keyCacheLock unlock];
    return retval;
#else
    return nil;
#endif
}

void putKey(NSString*label, SecKeyRef pk)
{
    if(nil == pk)
        return;
#if USE_CACHE
    NSDate* n = [NSDate date];
    [keyCacheLock lock];
    if(![keyCache objectForKey:label])
    {
        NSLog(@"Putting %@ item into cache", label);
        [keyCache setObject:(__bridge id)pk forKey:label];
        [timeCache setObject:n forKey:label];
    }
    [keyCacheLock unlock];
#endif
}


@implementation TokenSession

//------------------------------------------------------------------------------------------
// Unsupported interfaces
//------------------------------------------------------------------------------------------
/**
 beginAuthForOperation is not supported. The auto-generated return was replaced with nil.
 */
- (TKTokenAuthOperation *)tokenSession:(TKTokenSession *)session
                 beginAuthForOperation:(TKTokenOperation)operation
                            constraint:(TKTokenOperationConstraint)constraint
                                 error:(NSError **)error {
    // Insert code here to create an instance of TKTokenAuthOperation based on the specified
    // operation and constraint. Note that the constraint was previously established when
    // creating token configuration with keychain items.
    NSLog(@"%s: inside beginAuthForOperation", g_logPrefix);
    NSLog(@"%s: operation: %@", g_logPrefix, GetOperationStringFromTkTokenOperation(operation));
    NSLog(@"%s: constraint: %@", g_logPrefix, constraint);

    //return [TKTokenPasswordAuthOperation new];
    if(error)
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeNotImplemented userInfo:@{NSLocalizedDescriptionKey: @"beginAuthForOperation not implemented"}];

    return nil;
}

/**
 performKeyExchangeWithPublicKey is not supported. The auto-generated code that returns nil is in place.
 */
- (NSData *)tokenSession:(TKTokenSession *)session
performKeyExchangeWithPublicKey:(NSData *)otherPartyPublicKeyData
                usingKey:(TKTokenObjectID)objectID
               algorithm:(TKTokenKeyAlgorithm *)algorithm
              parameters:(TKTokenKeyExchangeParameters *)parameters
                   error:(NSError **)error
{
    NSLog(@"%s: inside performKeyExchangeWithPublicKey", g_logPrefix);
    NSLog(@"%s: otherPartyPublicKeyData: %@", g_logPrefix, [otherPartyPublicKeyData hexadecimalString]);
    NSLog(@"%s: objectID: %@", g_logPrefix, objectID);
    NSLog(@"%s: algorithm: %@", g_logPrefix, algorithm);
    NSLog(@"%s: parameters: %@", g_logPrefix, parameters);

    NSData *secret;

    // Insert code here to perform Diffie-Hellman style key exchange.
    secret = nil;

    if(error)
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeNotImplemented userInfo:@{NSLocalizedDescriptionKey: @"performKeyExchangeWithPublicKey not implemented"}];

    /*
    if (!secret) {
        if (error) {
            // If the operation failed for some reason, fill in an appropriate error like
            // TKErrorCodeObjectNotFound, TKErrorCodeCorruptedData, etc.
            // Note that responding with TKErrorCodeAuthenticationNeeded will trigger user
            // authentication after which the current operation will be re-attempted.
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationNeeded userInfo:@{NSLocalizedDescriptionKey: @"Authentication required!"}];
        }
    }
     */
    
    return secret;
}

//------------------------------------------------------------------------------------------
// Supported interfaces
//------------------------------------------------------------------------------------------

/**
 supportsOperation will return YES when the following conditions are satisfied:
    - algorithm is an RSA algorithm
    - operation is sign or decrypt
    - a certificate is available with kSetAttrLabel set to keyObjectID (a key with the same label is assumed to exist)
 
 supportsOperation will return NO when any of the following conditions are satisfied:
    - algorithm is not an RSA algorithm
    - operation is other than sign or decrypt
    - no certificate can be found with kSecAttrLabel set to keyObjectID
 */
- (BOOL)tokenSession:(TKTokenSession *)session
   supportsOperation:(TKTokenOperation)operation
            usingKey:(TKTokenObjectID)keyObjectID
           algorithm:(TKTokenKeyAlgorithm *)algorithm
{
    // Indicate whether the given key supports the specified operation and algorithm.
    NSLog(@"%s: inside supportsOperation", g_logPrefix);
    NSLog(@"%s: operation: %@", g_logPrefix, GetOperationStringFromTkTokenOperation(operation));
    NSLog(@"%s: keyObjectID: %@", g_logPrefix, keyObjectID);
    NSLog(@"%s: algorithm: %@", g_logPrefix, GetAlgorithmStringFromTKTokenKeyAlgorithm(algorithm));
    
    // TKTokenOperationNone, TKTokenOperationReadData and TKTokenOperationPerformKeyExchange are
    // not supported.
    if(TKTokenOperationSignData != operation && TKTokenOperationDecryptData != operation)
    {
        NSLog(@"%s: unsupported operation: %@", g_logPrefix, GetOperationStringFromTkTokenOperation(operation));
        return NO;
    }
    
    // Confirm the algorithm is an RSA algorithm.
    if(!IsAlgorithmSupported(algorithm))
    {
        // Log TKTokenAlgorithm directly since we don't know what the value is to render a string
        NSLog(@"%s: unsupported algorithm: %@", g_logPrefix, algorithm);
        return NO;
    }
    
    // Confirm a certificate with kSecAttrLabel set to keyObjectID is available
    SecCertificateRef certificateRef = GetCertificateRef(keyObjectID);
    if(!certificateRef)
    {
        NSLog(@"%s: unsupported keyObjectId: %@", g_logPrefix, keyObjectID);
        return NO;
    }
    CFRelease(certificateRef);
    return YES;
}

/*
 signData retrieves a SecKeyRef with kSecAttrLabel set to keyObjectID. It derives a
 SecPadding value from the TKTokenKeyAlgorithm instance. For algorithm values of
 the "message" variety, the dataToSign is hashed using a hash algorithm derived from
 the TKTokenKeyAlgorithm instance. SecKeyRawSign is then invoked using the SecKeyRef,
 padding and data to sign (either raw data or hash of raw data). The signature is
 returned upon success. Nil is returned upon error with message written to NSLog.
 */
- (NSData *)tokenSession:(TKTokenSession *)session
                signData:(NSData *)dataToSign
                usingKey:(TKTokenObjectID)keyObjectID
               algorithm:(TKTokenKeyAlgorithm *)algorithm
                   error:(NSError **)error
{
    NSLog(@"%s: inside signData", g_logPrefix);
    LOG_SPECIAL(@"%s: dataToSign: %@", g_logPrefix, [dataToSign hexadecimalString]);
    NSLog(@"%s: dataToSign length: %li", g_logPrefix, (unsigned long)[dataToSign length]);
    NSLog(@"%s: keyObjectID: %@", g_logPrefix, keyObjectID);
    NSLog(@"%s: algorithm: %@", g_logPrefix, GetAlgorithmStringFromTKTokenKeyAlgorithm(algorithm));

    SecKeyRef privateKeyRef = nil;
    @try
    {
        // Get reference to private key (should have kSecAttrLabel set to keyObjectID)
        privateKeyRef = getKey(keyObjectID);
        if(nil == privateKeyRef)
        {
            privateKeyRef = GetPrivateKeyRef(keyObjectID);
            if(!privateKeyRef)
            {
                NSLog(@"%s: failed to load private key reference for keyObjectId: %@", g_logPrefix, keyObjectID);
                *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:@{NSLocalizedDescriptionKey: @"Failed to load private key in signData"}];
                return nil;
            }
            
            putKey(keyObjectID, privateKeyRef);
        }
        else {
            CFRetain(privateKeyRef);
        }

        SecKeyAlgorithm a = GetAlgorithmFromTKTokenKeyAlgorithm(algorithm);
        if(!SecKeyIsAlgorithmSupported(privateKeyRef, kSecKeyOperationTypeSign, a))
        {
            // Log TKTokenAlgorithm directly since we don't know what the value is to render a string
            NSLog(@"%s: unsupported algorithm passed to signData: %@", g_logPrefix, algorithm);
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:@{NSLocalizedDescriptionKey: @"Unsupported algorithm passed to signData"}];
            return nil;
        }

        CFErrorRef cferror;
        CFDataRef cfsignature = SecKeyCreateSignature(privateKeyRef, a, (CFDataRef)dataToSign, &cferror);
        CFRelease(privateKeyRef);
        if(!cfsignature) {
            NSError* e = (__bridge_transfer NSError*)cferror;
            NSLog(@"%s: SecKeyCreateSignature failed: %@", g_logPrefix, [e localizedDescription]);
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:@{NSLocalizedDescriptionKey: @"SecKeyRawSign failed"}];
            return nil;
        }

        NSData* signature = (__bridge_transfer NSData*)cfsignature;
        LOG_SPECIAL(@"%s: signature value: %@", g_logPrefix, [signature hexadecimalString]);
        NSLog(@"%s: signature length: %li", g_logPrefix, (unsigned long)[signature length]);
        return signature;
    }
    @catch (NSException* exception)
    {
        if(privateKeyRef)
            CFRelease(privateKeyRef);
        
        NSLog(@"%s: unexpected exception in signData: %@", g_logPrefix, exception);
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:@{NSLocalizedDescriptionKey: @"Unexpected exception in signData"}];
        
        return nil;
    }
}

/**
 
 */
- (NSData *)tokenSession:(TKTokenSession *)session
             decryptData:(NSData *)ciphertext
                usingKey:(TKTokenObjectID)keyObjectID
               algorithm:(TKTokenKeyAlgorithm *)algorithm
                   error:(NSError **)error
{
    NSLog(@"%s: inside decryptData", g_logPrefix);
    LOG_SPECIAL(@"%s: ciphertext: %@", g_logPrefix, [ciphertext hexadecimalString]);
    NSLog(@"%s: ciphertext length: %li", g_logPrefix, (unsigned long)[ciphertext length]);
    NSLog(@"%s: keyObjectID: %@", g_logPrefix, keyObjectID);
    NSLog(@"%s: algorithm: %@", g_logPrefix, GetAlgorithmStringFromTKTokenKeyAlgorithm(algorithm));

    SecKeyRef privateKeyRef = nil;
    @try
    {
        // Confirm the algorithm is an RSA algorithm.
        if(!IsAlgorithmSupported(algorithm))
        {
            // Log TKTokenAlgorithm directly since we don't know what the value is to render a string
            NSLog(@"%s: unsupported algorithm passed to decryptData: %@", g_logPrefix, algorithm);
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:@{NSLocalizedDescriptionKey: @"Unsupported algorithm passed to decryptData"}];
            return nil;
        }

        privateKeyRef = getKey(keyObjectID);
        if(nil == privateKeyRef)
        {
            privateKeyRef = GetPrivateKeyRef(keyObjectID);
            if(!privateKeyRef)
            {
                NSLog(@"%s: failed to load private key reference for keyObjectId: %@", g_logPrefix, keyObjectID);
                *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:@{NSLocalizedDescriptionKey: @"Failed to load private key reference in decryptData"}];
                return nil;
            }

            putKey(keyObjectID, privateKeyRef);
        }
        else {
            CFRetain(privateKeyRef);
        }

        SecPadding padding = GetPaddingForAlg(algorithm);
        if(kSecPaddingNone == padding)
        {
            NSLog(@"%s: kSecPaddingNone in use (continuing but likely wrong) for algorithm %@", g_logPrefix, GetAlgorithmStringFromTKTokenKeyAlgorithm(algorithm));
        }

        unsigned long pLen = (unsigned long)[ciphertext length];
        NSMutableData *plaintext = [[NSMutableData alloc] initWithLength:pLen];
        unsigned char* p = (unsigned char*)[plaintext bytes];

        OSStatus status = SecKeyDecrypt(privateKeyRef, padding, [ciphertext bytes], [ciphertext length], p, &pLen);
        CFRelease(privateKeyRef);
        if(errSecSuccess != status) {
            NSLog(@"%s: SecKeyDecrypt failed: %d", g_logPrefix, status);
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:@{NSLocalizedDescriptionKey: @"SecKeyDecrypt failed"}];
            return nil;
        }
        else {
            [plaintext setLength:pLen];
        }

        LOG_SPECIAL(@"%s: plaintext value: %@", g_logPrefix, [plaintext hexadecimalString]);
        NSLog(@"%s: plaintext length: %li", g_logPrefix, (unsigned long)[plaintext length]);
        return plaintext;
    }
    @catch (NSException* exception)
    {
        if(privateKeyRef)
            CFRelease(privateKeyRef);
        
        NSLog(@"%s: unexpected exception in decryptData: %@", g_logPrefix, exception);
        *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:@{NSLocalizedDescriptionKey: @"Unexpected exception in decryptData"}];
        
        return nil;
    }
}

@end
