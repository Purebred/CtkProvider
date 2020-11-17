# CtkProvider

This document describes implementation of a Persistent Token Extension for iOS. Persistent Token Extensions allow an app to enable system and third-party apps to use cryptographic keys similar to Android KeyChain or Microsoft Crypto API (CAPI). The Crypto Token Kit is used to implement Persistent Token Extensions. Current Crypto Token Kit documentation can be found [here](https://developer.apple.com/documentation/cryptotokenkit?language=objc). Documentation available at the time this was written is [here](https://web.archive.org/web/20200809130700if_/https://developer.apple.com/documentation/cryptotokenkit?language=objc). The process described below was developed using Xcode 12.2 beta 12B5025f and tested on iPhones running 14.0.1 and various 14.2 beta releases.

In this sample, the containing app adds one or more PKCS12 files to the key chain and creates a token for each. The label attriubte is set to a SHA256 hash of certificate. The containing app and extension share a key chain access group. The extension provides service using the keys stored in the key chain. Keys are stored with kSecAccessControlUserPresence access control, causing the user to be required to enter the device passcode prior to exercising the key. To build the sample app, first adjust bundle identifiers and key chain access group identifiers. The steps below can be used to create a similar project from scratch.

## Preparing Xcode project

- Launch Xcode.
- Click **Create a new Xcode project** (or open existing project if adding Persistent Token Extension to existing project and skip to next section).
- Choose type of Application. In this sample **App** was elected.
- Click **Next** then enter name, bundle identifer, select team, etc.
- Click **Next** and choose location where project should be saved.

## Adding extension to project

- Choose **File->New->Target** menu item.
- Choose **Persistent Token Extension**.
- Click **Next** then enter name, bundle identifer, select team, etc.
- Click **Activate** on the resulting dialog.

Build the app for good measure.

## Adding some user interface elements

- Open the storyboard in one view and ViewController.h in a companion view
- Click **View->Show Library** menu item
- In this sample, added buttons labeled **Add Signing Token**, **Add Authentication Token**, **Add Decryption Token**, **Remove All Tokens**, **Dump to NSLog** to a stack view. Size to taste.
- Open ViewController.h in a companion window then ctrl-drag each button to ViewController.h and add an action for each button.

## Adding sample keys to the project

- Copy three PKCS12 files containing signature credentials, authentication credential and decryption credential beside the project file.
- Right-click top-most CtkProvider item in the solution view and choose **Add Files to \<project name\>**.
- Browse to and select the three p12 files then click **Add**.

In this example the PKCS12 files are named symbolically: signature.p12, authentication.p12 and decryption.p12. Each requires 'password' to decrypt the contents. Installing any necessary trust anchors or intermediate CA certificates is not covered here.

## Setting up key chain access group

- Browse to the **Signing & Capabilities** tab in the project settings for the containing app.
- Click the **+Capability** button then choose the **Keychain Sharing** item.
- Click the **+** button below the **Keychain Groups** list in the resulting view.
- Enter a keychain access group.
- Repeat for these steps for the project settings for the extension.
- Inspect the Info.plist file for each project and confirm the values match. Adjust if not.

These steps are necessary because the extension is providing access to keys installed by the containing app into a shared key chain access.

## Implementing the containing app

Implement three utility methods:

- **NSString\* GetAsHex(const unsigned char\* buf, int len)**
  - convert NSData objects to NSString objects containing ASCII hex of the data
- **SecIdentityRef GetIdentity(NSString\* label, NSString\* password)**
  - parse a SecIdentityRef from a PKCS12 file included in the app
- **void AddItem(SecIdentityRef identity)**
  - add a TKTokenConfiguration containing components from the identity to the extension

This leaves the click handlers for adding tokens to code similar to the following:

```objective-c
    SecIdentityRef identity = GetIdentity(@"signature", @"password");
    AddItem(identity);
    CFRelease(identity);
```

Implement **Remove All Tokens** and **Dump** methods as desired.

### GetIdentity implementation notes

Parsing a PKCS12 object using **SecPKCS12Import** results in a SecIdentityRef object that contains the private key and corresponding certificate to import. When importing without setting up an access control for the private key, the SecIdentityRef object can be imported by simply invoking SecItemAdd. However, when an access control (like kSecAccessControlUserPresence) is desired, a SecCertificateRef and SecKeyRef must be copied from the SecIdentityRef then added using SecItemAdd independently, with access control associated with the SecKeyRef.

### AddItem implementation notes

The first step in adding a token is obtaining the driver configuration, as below. The dictionary should contain exactly one **TKTokenDriverConfiguration** item. The key for the item is the bundle identifier of the extension.

```objective-c
    TKTokenDriverConfiguration* tokenDriverConfiguration = nil;
    NSDictionary<TKTokenDriverClassID, TKTokenDriverConfiguration *>* driverConfigurations = [TKTokenDriverConfiguration driverConfigurations];

    // There should be just one named with the bundle identifier of the extension
    for (id key in driverConfigurations) {
        tokenDriverConfiguration = [driverConfigurations objectForKey:key];
    }
```

Next, add a token configuration to the token driver.

```objective-c
    TKTokenConfiguration* tokenConfiguration = [tokenDriverConfiguration addTokenConfigurationForTokenInstanceID:label];
```

In the sample, the label value is set to an ASCII hexadecimal representation of the SHA256 hash of the certificate extracted from the SecIdentityRef. To add a SecIdentityRef to the key chain corresponding to the desired token contents, a TKTokenKeychainCertificate object and a TKTokenKeychainKey object must be created. These are created using the certificate and packaged as an array before adding to the token configuration.

```objective-c
    NSArray<TKTokenKeychainItem *>* keychainItems = [[NSMutableArray<TKTokenKeychainItem*> alloc]init];
    TKTokenKeychainCertificate* tokenKeychainCertificate = [[TKTokenKeychainCertificate alloc]initWithCertificate:certificateRef objectID:label];
    keychainItems = [keychainItems arrayByAddingObject:tokenKeychainCertificate];

    TKTokenKeychainKey* tokenKeychainKey = [[TKTokenKeychainKey alloc]initWithCertificate:certificateRef objectID:label];
    tokenConfiguration.keychainItems = [keychainItems arrayByAddingObject:tokenKeychainKey];
```

## Implementing the extension

When the Persistent Token Extension is added to the project, four files with skeleton code are generated:

- Token.h
- Token.m
- TokenDriver.m
- TokenSession.m

In the sample, only TokenSession.m was substantively changed. This file includes implementation of the interface for supporting cryptographic operations with a token:

- beginAuthForOperation
- supportsOperation
- signData
- decryptData
- performKeyExchangeWithPublicKey

Of these, only supportsOperation, signData and decryptData were meaningfully implemented. The beginAuthForOperation and methods were left in default form, with performKeyExchangeWithPublicKey essentially blocked from by a check in supports operation that returns NO when a key exchange operation is requested.
