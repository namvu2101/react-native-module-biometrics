import { Alert, Button, StyleSheet, View } from 'react-native';
import {
  authenticate,
  authenticateWithKey,
  checkAvailableBiometrics,
  getAvailableBiometrics,
  setSecretValue,
} from 'react-native-module-biometrics';

export default function App() {
  return (
    <View style={styles.container}>
      <Button
        title="checkBiometrics"
        onPress={async () => {
          try {
            const check = await checkAvailableBiometrics();
            Alert.alert(
              'checkBiometrics',
              `Status: ${check.status} , message: ${check.message}`
            );
          } catch (error) {
            console.log(error);
          }
        }}
      />
      <Button
        title="Auth"
        onPress={async () => {
          try {
            const check = await checkAvailableBiometrics();
            if (!check.status) {
              Alert.alert('Error', `${check.message}`);
              return;
            }
            const res = await authenticate({ title: 'Authentication' });
            console.log(res);
            Alert.alert(
              'authentication',
              `Status: ${res.status} , message: ${res.authenticationType}`
            );
          } catch (error) {
            Alert.alert('Error', `${error}`);
            console.log(error);
          }
        }}
      />
      <Button
        title="getAvailableBiometrics"
        onPress={async () => {
          try {
            const name = await getAvailableBiometrics();
            Alert.alert('Name', `${name}`);
          } catch (error) {
            Alert.alert('Error', `${error}`);
          }
        }}
      />
      <Button
        title="setSecretKey"
        onPress={async () => {
          try {
            const res = await setSecretValue({
              value: 'newValue223',
              key: 'new_key',
            });
            Alert.alert('set Secret Key', `key: new_key, value: ${res.value}`);
          } catch (error) {
            Alert.alert('Error setSecretKey', `${error}`);
            console.log(error);
          }
        }}
      />
      <Button
        title="authenticate new_key"
        onPress={async () => {
          try {
            const res = await authenticateWithKey({ key: 'new_key' });
            Alert.alert('authenticate with key', `value: ${res.value}`);
          } catch (error) {
            Alert.alert('Error authenticate with key', `${error}`);
          }
        }}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
  },
});
