import { NativeModules, Platform } from 'react-native';

export type AuthenticateProps = {
  title?: string;
  subTitle?: string;
};

export type TSecretValue = {
  value: string;
  key: string;
};

export type AuthenticateWithKeyProps = AuthenticateProps & {
  key: string;
};

export type ResponseCheck = { status: boolean; message: string };
export type ResponseAuth = {
  status: boolean;
  authenticationType: string;
  value?: string | null;
};

const LINKING_ERROR =
  `The package 'react-native-module-biometrics' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const ModuleBiometrics = NativeModules.ModuleBiometrics
  ? NativeModules.ModuleBiometrics
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

export function multiply(a: number, b: number): Promise<number> {
  return ModuleBiometrics.multiply(a, b);
}
export function checkAvailableBiometrics(): Promise<ResponseCheck> {
  return ModuleBiometrics.checkAvailableBiometrics();
}
export function getAvailableBiometrics(): Promise<string> {
  return ModuleBiometrics.getAvailableBiometrics();
}
export function authenticate(
  value: AuthenticateProps = {}
): Promise<ResponseAuth> {
  return ModuleBiometrics.authenticate(value);
}
export function setSecretValue(props: TSecretValue): Promise<ResponseAuth> {
  return ModuleBiometrics.setSecretValue(props);
}
export function authenticateWithKey(
  value: AuthenticateWithKeyProps
): Promise<ResponseAuth> {
  return ModuleBiometrics.authenticateWithKey(value);
}
