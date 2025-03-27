#import "ModuleBiometrics.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

@implementation ModuleBiometrics
RCT_EXPORT_MODULE()

// Example method
// See // https://reactnative.dev/docs/native-modules-ios
RCT_EXPORT_METHOD(multiply:(double)a
                  b:(double)b
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
    NSNumber *result = @(a * b);

    resolve(result);
}

RCT_EXPORT_METHOD(checkAvailableBiometrics:(RCTPromiseResolveBlock)resolve
                          reject:(RCTPromiseRejectBlock)reject)
{
   LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;
    BOOL available = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    NSString *biometryType = @"None";
  if (available) {
    if (@available(iOS 11.0, *)) {
      if (context.biometryType == LABiometryTypeFaceID) {
        biometryType = @"FaceID";
      } else if (context.biometryType == LABiometryTypeTouchID) {
        biometryType = @"TouchID";
      }
    } else {
      biometryType = @"Unknown";
    }
  }
  NSString *message = available
      ? [NSString stringWithFormat:@"Biometrics available (%@)", biometryType]
      : [NSString stringWithFormat:@"Unavailable Biometrics (%@)", biometryType];
  
    resolve(@{
      @"status": @(available),
      @"message": message
    });
}

RCT_EXPORT_METHOD(getAvailableBiometrics:(RCTPromiseResolveBlock)resolve
                        reject:(RCTPromiseRejectBlock)reject)
{
    LAContext *context = [[LAContext alloc] init];
  NSError *error = nil;
  NSMutableArray *types = [NSMutableArray array];

  BOOL hasAny = NO;

  // Check Passcode
  if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
    [types addObject:@"Passcode"];
    hasAny = YES;
  }

  // Reset error
  error = nil;

  // Check Biometrics
  if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
    if (@available(iOS 11.0, *)) {
      if (context.biometryType == LABiometryTypeFaceID) {
        [types addObject:@"FaceID"];
      } else if (context.biometryType == LABiometryTypeTouchID) {
        [types addObject:@"TouchID"];
      }
    } else {
      [types addObject:@"Biometrics"];
    }
    hasAny = YES;
  }

  if (hasAny) {
    resolve(types);
  } else {
    reject(@"UNAVAILABLE", @"No available authentication methods", error ?: nil);
  }
}

RCT_EXPORT_METHOD(authenticate:(NSDictionary *)value
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
   LAContext *context = [[LAContext alloc] init];
   NSError *error = nil;
   NSString *reason = value[@"title"] ?: @"Authenticate using biometrics";

   if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
       [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
               localizedReason:reason
                         reply:^(BOOL success, NSError * _Nullable error) {
           NSString *biometryType = @"None";
           if (@available(iOS 11.0, *)) {
               if (context.biometryType == LABiometryTypeFaceID) {
                   biometryType = @"FaceID";
               } else if (context.biometryType == LABiometryTypeTouchID) {
                   biometryType = @"TouchID";
               }
           } else {
               biometryType = @"Unknown";
           }
         
           if (success) {
               resolve(@{ @"status": @(YES), @"authenticationType": biometryType });
           } else {
               reject(@"AUTH_FAILED", error.localizedDescription, error);
           }
       }];
   } else {
       reject(@"BIOMETRICS_NOT_AVAILABLE", error.localizedDescription, error);
   }
}

RCT_EXPORT_METHOD(authenticateWithKey:(NSDictionary *)value
                    resolve:(RCTPromiseResolveBlock)resolve
                     reject:(RCTPromiseRejectBlock)reject)
{
   LAContext *context = [[LAContext alloc] init];
   NSError *error = nil;
   NSString *key = value[@"key"] ?: @"default_key";

   if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
       NSString *retrieved = [self readFromKeychainWithBiometrics:key context:context error:&error];

       if (retrieved != nil) {
           resolve(@{ @"status": @(YES), @"value": retrieved });
       } else {
           reject(@"KEY_NOT_FOUND", [NSString stringWithFormat:@"No found key: (%@)", key], nil);
       }
   } else {
       reject(@"BIOMETRICS_NOT_AVAILABLE", error.localizedDescription, error);
   }
}

RCT_EXPORT_METHOD(setSecretValue:(NSDictionary *)props
               resolve:(RCTPromiseResolveBlock)resolve
                reject:(RCTPromiseRejectBlock)reject)
{
   LAContext *context = [[LAContext alloc] init];
   NSError *error = nil;
   NSString *key = props[@"key"];
   NSString *value = props[@"value"];

   if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
       BOOL success = [self saveToKeychainWithBiometrics:key value:value context:context error:&error];
       if (success) {
           resolve(@{ @"status": @(YES), @"value": value });
       } else {
           reject(@"STORE_FAILED", @"Unable to store value in keychain", nil);
       }
   } else {
       reject(@"BIOMETRICS_NOT_AVAILABLE", error.localizedDescription, error);
   }
}

#pragma mark - Keychain helpers

- (BOOL)saveToKeychainWithBiometrics:(NSString *)key
                               value:(NSString *)value
                             context:(LAContext *)context
                               error:(NSError **)error {
  CFErrorRef accessError = nil;

  SecAccessControlRef accessControl = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    kSecAccessControlUserPresence,
    &accessError
  );

  if (!accessControl || accessError) {
    if (error) *error = (__bridge_transfer NSError *)accessError;
    if (accessControl) CFRelease(accessControl);
    return NO;
  }

  NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];

  // Remove existing item
  NSDictionary *deleteQuery = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrAccount: key
  };
  SecItemDelete((__bridge CFDictionaryRef)deleteQuery);

  NSDictionary *addQuery = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrAccount: key,
    (__bridge id)kSecValueData: data,
    (__bridge id)kSecAttrAccessControl: (__bridge id)accessControl,
    (__bridge id)kSecUseAuthenticationContext: context
  };

  OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
  CFRelease(accessControl);

  if (status != errSecSuccess) {
    if (error) {
      *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    }
    return NO;
  }

  return YES;
}

- (NSString *)readFromKeychainWithBiometrics:(NSString *)key
                                     context:(LAContext *)context
                                       error:(NSError **)error {

  NSDictionary *query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrAccount: key,
    (__bridge id)kSecReturnData: @YES,
    (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    (__bridge id)kSecUseAuthenticationContext: context
  };

  CFDataRef dataRef = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&dataRef);

  if (status == errSecSuccess && dataRef) {
    NSData *data = (__bridge_transfer NSData *)dataRef;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  }

  if (error) {
    *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
  }

  return nil;
}

@end
