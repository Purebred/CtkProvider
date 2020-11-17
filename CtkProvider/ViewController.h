//
//  ViewController.h
//  CtkProvider
//
//  Created by on 10/16/20.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController
- (IBAction)onAddSignatureToken:(id)sender;
- (IBAction)onAddAuthenticationToken:(id)sender;
- (IBAction)onAddDecryptionToken:(id)sender;
- (IBAction)onRemoveAllTokens:(id)sender;
- (IBAction)onDump:(id)sender;
@end

