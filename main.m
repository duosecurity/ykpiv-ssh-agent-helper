//
//  main.m
//  ykpiv-ssh-agent-helper
//
//  Created by Adam Goodman on 2/24/16.
//  Copyright © 2016 Duo Security. All rights reserved.
//


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <Security/Security.h>
#import <Security/SecRandom.h>

#import <sys/socket.h>
#import <sys/un.h>
#import <pwd.h>
#import <unistd.h>
#import <getopt.h>
#import <stdio.h>
#include <IOKit/hid/IOHIDManager.h>

// ssh-agent protocol constants
const int SSH_AGENTC_ADD_SMARTCARD_KEY = 20;
const int SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21;

const int SSH_AGENT_FAILURE = 5;
const int SSH_AGENT_SUCCESS = 6;

// keychain identifiers
static NSString * const KEYCHAIN_SERVICE = @"ykpiv-ssh-agent-helper";
static NSString * const KEYCHAIN_ACCOUNT = @"PIN";

// somehow I ended up writing a state machine
enum {
    STATE_IDLE,
    STATE_REMOVING,
    STATE_ADDING
};

// basically NSLog() then quit.
void fail(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSLogv(fmt, ap);
    va_end(ap);

    NSLog(@"Fatal Error! Terminating.");
    exit(-1);
}

NSString *generateNewPin(int length) {
    static NSString * const pinCharacters = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *newPin = [NSMutableString stringWithCapacity:length];

    while (newPin.length != length) {
        unsigned char nextByte;
        OSStatus status;
        status = SecRandomCopyBytes(kSecRandomDefault, sizeof(nextByte), &nextByte);
        NSCAssert(status == noErr, @"Failed to get random bytes.");

        // pinCharacters.length is 62; we can mask off the random byte to be
        // between 0 and 64 without introducing any bias.
        int index = nextByte & 0x3F;
        // and then skip values that are still out-of-range
        if (index < pinCharacters.length) {
            [newPin appendFormat:@"%lc", [pinCharacters characterAtIndex:index]];
        }
    }

    return [newPin copy];
}

NSData *getPin(SecKeychainItemRef *itemRefReturn) {
    OSStatus status;
    void *passwordBytes;
    uint32_t passwordLength;

    status = SecKeychainFindGenericPassword(NULL,
                                            (uint32_t)[KEYCHAIN_SERVICE lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                                            [KEYCHAIN_SERVICE cStringUsingEncoding:NSUTF8StringEncoding],
                                            (uint32_t)[KEYCHAIN_ACCOUNT lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                                            [KEYCHAIN_ACCOUNT cStringUsingEncoding:NSUTF8StringEncoding],
                                            &passwordLength,
                                            &passwordBytes,
                                            itemRefReturn
                                            );
    if (status == noErr) {
        NSData *passwordData = [[NSData alloc] initWithBytesNoCopy:passwordBytes
                                                            length:passwordLength
                                                       deallocator:^(void *bytes, NSUInteger length) {
                                                           // SCARY HACK: Erase PIN from memory, because source-code
                                                           // inspection suggests SecKeychainItemFreeContent won't do it
                                                           // for us.
                                                           memset(bytes, 0, length);
                                                           SecKeychainItemFreeContent(NULL, bytes);
                                                       }];
        return passwordData;
    } else {
        NSLog(@"Failed to retrieve existing PIN from keychain: %d", status);
    }

    return nil;
}

@interface YKPIVSSHAgentHelper : NSObject <NSStreamDelegate>
@property (nonatomic) NSInputStream *inputStream;
@property (nonatomic) NSOutputStream *outputStream;
@property (nonatomic) NSString *pkcs11Path;
@property int state;
- (YKPIVSSHAgentHelper *)initWithPKCS11Path:(NSString *)thePkcs11Path;
- (void)stream:(NSStream *)theStream handleEvent:(NSStreamEvent)eventCode;
- (NSMutableData *)buildAgentSmartcardRequest:(uint8_t)messageType;
- (void)refreshPkcs11Module:(id)whatever;
@end

@implementation YKPIVSSHAgentHelper
- (YKPIVSSHAgentHelper *)initWithPKCS11Path:(NSString *)thePkcs11Path {
    if ((self = [super init])) {
        self.inputStream = nil;
        self.outputStream = nil;
        self.state = STATE_IDLE;
        self.pkcs11Path = thePkcs11Path;
    }
    return self;
}

- (void)refreshPkcs11Module:(id)whatever
{
    if (self.state != STATE_IDLE) {
        NSLog(@"Communication with ssh-agent is already in progress!");
        return;
    }
    self.state = STATE_REMOVING;

    // dig SSH_AUTH_SOCK out of environment
    const char *auth_socket_path = getenv("SSH_AUTH_SOCK");
    if (!auth_socket_path) {
        fail(@"No SSH_AUTH_SOCK in environment!");
        return;
    }

    // create sockaddr_un struct
    struct sockaddr_un auth_socket_address;
    auth_socket_address.sun_family = AF_UNIX;
    size_t path_length = strlcpy(auth_socket_address.sun_path,
                                 auth_socket_path,
                                 sizeof(auth_socket_address.sun_path));
    if (path_length >= sizeof(auth_socket_address.sun_path)) {
        fail(@"SSH_AUTH_SOCK too long: '%s'", auth_socket_path);
        return;
    }

    CFSocketNativeHandle s = socket(PF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
        fail(@"socket() failed! errno %d", errno);
        return;
    }
    int res = connect(s, (const struct sockaddr *)&auth_socket_address, sizeof(auth_socket_address));
    if (res < 0) {
        fail(@"connect() failed! errno %d", errno);
        return;
    }

    // create streams
    CFReadStreamRef readStreamCF = nil;
    CFWriteStreamRef writeStreamCF = nil;
    CFStreamCreatePairWithSocket(NULL, s, &readStreamCF, &writeStreamCF);

    self.inputStream = (__bridge_transfer NSInputStream *)readStreamCF;
    self.outputStream = (__bridge_transfer NSOutputStream *)writeStreamCF;

    [self.inputStream setDelegate:self];
    [self.outputStream setDelegate:self];
    [self.inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.inputStream open];
    [self.outputStream open];
}

- (void)stream:(NSStream *)theStream handleEvent:(NSStreamEvent)eventCode
{
    NSMutableData *message = nil;
    uint32_t responseLength;
    uint8_t response;
    uint8_t messageType;

    switch (eventCode) {
        case NSStreamEventHasSpaceAvailable:
            if (self.state == STATE_REMOVING) {
                messageType = SSH_AGENTC_REMOVE_SMARTCARD_KEY;
                NSLog(@"Send SSH_AGENTC_REMOVE_SMARTCARD_KEY request");
            } else {
                messageType = SSH_AGENTC_ADD_SMARTCARD_KEY;
                NSLog(@"Send SSH_AGENTC_ADD_SMARTCARD_KEY request");
            }
            message = [self buildAgentSmartcardRequest:messageType];
            [self.outputStream write:[message bytes] maxLength:[message length]];
            // erase PIN from memory!
            memset([message mutableBytes], 0, [message length]);
            [theStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
            break;
        case NSStreamEventHasBytesAvailable:
            [self.inputStream read:(void *)&responseLength maxLength:sizeof(responseLength)];
            responseLength = ntohl(responseLength);
            if (responseLength != 1) {
                fail(@"Unexpected response from ssh_agent - length %d", responseLength);
            }
            [self.inputStream read:&response maxLength:sizeof(response)];
            NSLog(@"Response from ssh-agent: %d", response);
            if (self.state == STATE_REMOVING) {
                self.state = STATE_ADDING;
                // time to send another message!
                [self.outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
            } else if (response == SSH_AGENT_SUCCESS) {
                [self.inputStream close];
                [self.outputStream close];
                self.inputStream = nil;
                self.outputStream = nil;
                self.state = STATE_IDLE;
            } else {
                NSLog(@"ssh_agent reported failure adding PKCS#11 module. Maybe the Yubikey is currently not plugged in?");
                self.state = STATE_IDLE;
            }
            break;
        case NSStreamEventErrorOccurred:
        case NSStreamEventEndEncountered:
            fail(@"Error communicating with ssh_agent: %@", [theStream streamError]);
            break;
        case NSStreamEventOpenCompleted:
        case NSStreamEventNone:
            // ignore
            break;
    }
}

- (NSMutableData *)buildAgentSmartcardRequest:(uint8_t)messageType
{
    NSMutableData *message = [NSMutableData data];

    // add placeholder for length. we'll fill this in later!
    uint32_t messageLength = 0;
    [message appendBytes:&messageLength length:sizeof(messageLength)];

    // add message type
    [message appendBytes:&messageType length:sizeof(messageType)];

    // add reader_id (i.e. patch to pkcs#11 module)
    NSData *pkcs11PathBytes = [self.pkcs11Path dataUsingEncoding:NSUTF8StringEncoding];
    uint32_t pkcs11PathLength = htonl([pkcs11PathBytes length]);
    [message appendBytes:&pkcs11PathLength length:sizeof(pkcs11PathLength)];
    [message appendData:pkcs11PathBytes];

    // pin
    NSData *pinBytes = getPin(nil);
    if (!pinBytes) {
        fail(@"Failed to read PIN from keychain!");
    }

    uint32_t pinLength = htonl([pinBytes length]);
    [message appendBytes:&pinLength length:sizeof(pinLength)];
    [message appendData:pinBytes];

    // write the actual length into the first four bytes of "message"
    messageLength = htonl([message length] - sizeof(messageLength));
    memcpy([message mutableBytes], &messageLength, sizeof(messageLength));

    return message;
}
@end


void doReloadService(NSString *launchAgentPlist) {
    NSTask *task;
    NSFileHandle *nullFile = [NSFileHandle fileHandleForWritingAtPath:@"/dev/null"];
    if ([launchAgentPlist length]) {
        printf("Restarting ykpiv-ssh-agent-helper LaunchAgent\n");

        // for stopping the agent process, squelch the output, because we don't
        // particularly care about the results of this operation
        task = [[NSTask alloc] init];
        task.launchPath = @"/bin/launchctl";
        task.arguments = @[@"unload", launchAgentPlist];
        task.standardOutput = nullFile;
        task.standardError = nullFile;
        [task launch];
        [task waitUntilExit];

        task = [NSTask launchedTaskWithLaunchPath:@"/bin/launchctl"
                                        arguments:@[@"load", launchAgentPlist]];
        [task waitUntilExit];
    }
}

void doResetPin(NSString *launchAgentPlist, NSString *yubicoPivToolDir) {
    NSString *oldPin = [NSString stringWithUTF8String:getpass("Enter your current PIN: ")];
    NSString *newPin = generateNewPin(8);

    NSString *yubicoPivToolPath = [yubicoPivToolDir stringByAppendingPathComponent:@"bin/yubico-piv-tool"];
    NSTask *task = [NSTask launchedTaskWithLaunchPath:yubicoPivToolPath
                                            arguments:@[@"-a", @"change-pin", @"--pin",
                                                        oldPin, @"--new-pin", newPin]];
    [task waitUntilExit];
    printf("\n");
    if ([task terminationStatus] != 0) {
        printf("Could not change YubiKey PIV PIN. Did you enter the current PIN correctly?\n");
        exit(-1);
    } else {
        // Definitely want to printf(), not NSLog here;
        // the latter would store this in system logs
        printf("Changed YubiKey PIV PIN to %s\n", [newPin UTF8String]);
    }

    SecKeychainItemRef oldItemRef;
    NSData *oldKeychainPin = getPin(&oldItemRef);
    if (oldKeychainPin) {
        SecKeychainItemDelete(oldItemRef);
        CFRelease(oldItemRef);
    }

    OSStatus status = SecKeychainAddGenericPassword(NULL,
                                                    (uint32_t)[KEYCHAIN_SERVICE lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                                                    [KEYCHAIN_SERVICE cStringUsingEncoding:NSUTF8StringEncoding],
                                                    (uint32_t)[KEYCHAIN_ACCOUNT lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                                                    [KEYCHAIN_ACCOUNT cStringUsingEncoding:NSUTF8StringEncoding],
                                                    (uint32_t)[newPin lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                                                    [newPin cStringUsingEncoding:NSUTF8StringEncoding],
                                                    NULL);
    if (status != noErr) {
        printf("Failed to store new PIN in keychain: %d\n", status);
    } else {
        printf("Stored new PIN in keychain!\n");
        doReloadService(launchAgentPlist);
        printf("Done!\n");
    }
}

// Yubico
#define     idVendor           0x1050

static void match_set(CFMutableDictionaryRef dict, CFStringRef key, int value) {
    CFNumberRef number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &value);
    CFDictionarySetValue(dict, key, number);
    CFRelease(number);
}

static CFDictionaryRef matching_dictionary_create(int vendorID) {
    CFMutableDictionaryRef match =
        CFDictionaryCreateMutable(kCFAllocatorDefault,
                                  0,
                                  &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);

    if (vendorID) {
        match_set(match, CFSTR(kIOHIDVendorIDKey), vendorID);
    }

    return match;
}


static void match_callback(void *context, IOReturn result, void *sender,
                           IOHIDDeviceRef device) {
    NSLog(@"Matching USB device appeared");
    YKPIVSSHAgentHelper *helper = (__bridge YKPIVSSHAgentHelper*)context;
    [helper performSelector:@selector(refreshPkcs11Module:)
                                                          withObject:nil
                                                          afterDelay:1];
}

void doWakeLoop(NSString *yubicoPivToolDir) {
    // XXX ideally, we should read this from the keychain every time we wake up
    // and then (attempt to?) scrub it from memory when we're done with it.


    NSString *pkcs11Module = @"/usr/local/lib/opensc-pkcs11.so";
    YKPIVSSHAgentHelper *helper = [[YKPIVSSHAgentHelper alloc] initWithPKCS11Path:pkcs11Module];

    // We assume this process will be started by launchd upon interactive login
    // so add the pkcs#11 module to ssh-agent immediately on launch
    [helper refreshPkcs11Module:nil];

    // Then, register for wake notifications.
    NSNotificationCenter *workspaceNotificationCenter = [[NSWorkspace sharedWorkspace] notificationCenter];
    [workspaceNotificationCenter addObserverForName:NSWorkspaceDidWakeNotification
                                             object:nil
                                              queue:[NSOperationQueue mainQueue]
                                         usingBlock:^(NSNotification *note) {
                                             NSLog(@"Received wake notification.");
                                             // doing this *immediately* upon wakeup appears to fail
                                             // so let's insert a few seconds' delay
                                             [helper performSelector:@selector(refreshPkcs11Module:)
                                                          withObject:nil
                                                          afterDelay:6];
                                         }];

    // register for Device Plug / Unplug events; code roughly taken from https://github.com/pallotron/yubiswitch/blob/master/yubiswitch.helper/main.c
    IOHIDManagerRef hidManager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);

    IOHIDManagerRegisterDeviceMatchingCallback(hidManager, match_callback, (__bridge void *)helper);
    IOHIDManagerScheduleWithRunLoop(hidManager, CFRunLoopGetMain(), kCFRunLoopCommonModes);

    CFDictionaryRef match = matching_dictionary_create((int)idVendor);
    IOHIDManagerSetDeviceMatching(hidManager, match);
    CFRelease(match);

    // loop forever!
    [[NSRunLoop mainRunLoop] run];
}

static NSString * const usageString = @"\
usage: ykpiv-ssh-agent-helper [-h] [-r]\n\
                            [--yubico_piv_tool_dir YUBICO_PIV_TOOL_DIR]\n\
                            [--launch_agent_plist LAUNCH_AGENT_PLIST]\n\
\n\
optional arguments:\n\
  -h, --help            show this help message and exit\n\
  -r, --reset_pin       Reset the PIV PIN on your YubiKey to a new, randomly-\n\
                        generated one, and store the new PIN in the keychain.\n\
  --yubico_piv_tool_dir YUBICO_PIV_TOOL_DIR\n\
                        Directory containing yubico-piv-tool installation\n\
                        (Default: /opt/yubico-piv-tool)\n\
  --launch_agent_plist LAUNCH_AGENT_PLIST\n\
                        Path to LaunchAgent plist. If '-r' is specified, we\n\
                        will automatically reload this LaunchAgent. (Default:\n\
                        /Library/LaunchAgents/com.duosecurity.ykpiv-ssh-agent-\n\
                        helper.plist)\n";

void usage(int argc, const char *argv[]) {
    const char *command = "ykpiv-ssh-agent-helper";
    if (argc > 0) {
        command = argv[0];
    }
    printf([usageString UTF8String], command);
    exit(-1);
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        bool resetPin = NO;
        bool reloadService = NO;
        NSString *yubicoPivToolDir = @"/opt/yubico-piv-tool";
        NSString *launchAgentPlist = @"/Library/LaunchAgents/com.duosecurity.ykpiv-ssh-agent-helper.plist";

        struct option longopts[] = {
            { "reload-service", no_argument, NULL, 'r' },
            { "reset-pin", no_argument, NULL, 'p' },
            { "yubico-piv-tool-dir", required_argument, NULL, 'm'},
            { "launch-agent-plist", required_argument, NULL, 'l'},
            { "help", no_argument, NULL, 'h'},
            { NULL, 0, NULL, 0 }
        };
        int ch;
        while ((ch = getopt_long(argc, argv, "rh", longopts, NULL)) != -1) {
            switch (ch) {
                case 'r':
                    reloadService = YES;
                    break;
                case 'p':
                    resetPin = YES;
                    break;
                case 'm':
                    yubicoPivToolDir = [NSString stringWithUTF8String:optarg];
                    break;
                case 'l':
                    launchAgentPlist = [NSString stringWithUTF8String:optarg];
                    break;
                default:
                    usage(argc, argv);
            }
        }
        if (reloadService) {
            doReloadService(launchAgentPlist);
        } else if (resetPin) {
            doResetPin(launchAgentPlist, yubicoPivToolDir);
        } else {
            doWakeLoop(yubicoPivToolDir);
        }
    }
    return 0;
}
