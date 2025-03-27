package com.modulebiometrics

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReadableMap
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class ModuleBiometricsModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {
  private lateinit var executor: Executor
  private lateinit var biometricPrompt: BiometricPrompt
  private lateinit var promptInfo: BiometricPrompt.PromptInfo

  override fun getName(): String {
    return NAME
  }

  private fun checkBiometrics(): WritableMap {
    val statusMap: WritableMap = Arguments.createMap()
    try {
        val manager = BiometricManager.from(reactApplicationContext)
        val status = manager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
        val (success, msg) = when (status) {
            BiometricManager.BIOMETRIC_SUCCESS -> true to "BIOMETRIC_SUCCESS"
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> false to "BIOMETRIC_ERROR_NO_HARDWARE"
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> false to "BIOMETRIC_ERROR_HW_UNAVAILABLE"
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> false to "BIOMETRIC_ERROR_NONE_ENROLLED"
            else -> false to "BIOMETRIC_UNKNOWN_ERROR"
        }
        statusMap.putBoolean("status", success)
        statusMap.putString("message", msg)
    } catch (e: Exception) {
        statusMap.putBoolean("status", false)
        statusMap.putString("message", "CHECK_BIOMETRIC_ERROR: ${e.localizedMessage}")
    }
    return statusMap
}

@ReactMethod
fun checkAvailableBiometrics(promise: Promise) {
    try {
        val checkResult = checkBiometrics()
        promise.resolve(checkResult)
    } catch (e: Exception) {
        promise.reject("CHECK_BIOMETRIC_ERROR", e.localizedMessage, e)
    }
}

  @ReactMethod
  fun getAvailableBiometrics(promise: Promise?) {
    try {
      val context = reactApplicationContext
      val result = Arguments.createArray()
      val packageManager = context.packageManager
      val biometricManager = BiometricManager.from(context)

      // Check fingerprint
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
        packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
        result.pushString("FINGERPRINT")
      }

      // Check faceID (từ Android Q - 10+)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
        packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)) {
        result.pushString("FaceID")
      }

      // (optional) Check iris
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
        packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS)) {
        result.pushString("iris")
      }

      // Check device credentials: pin/pattern/password
      val credentialAvailable = biometricManager.canAuthenticate(
        BiometricManager.Authenticators.DEVICE_CREDENTIAL
      ) == BiometricManager.BIOMETRIC_SUCCESS

      if (credentialAvailable) {
        result.pushString("PIN/PASS")
      }

      promise?.resolve(result)
    } catch (e: Exception) {
      promise?.reject("GET_BIOMETRIC_ERROR", e.message, e)
    }
  }

  @ReactMethod
  fun authenticate(value: ReadableMap?, promise: Promise?) {
    val activity = currentActivity as? FragmentActivity ?: return promise?.reject("NO_ACTIVITY", "Invalid or missing activity.")!!

    try {
      executor = ContextCompat.getMainExecutor(reactApplicationContext)
      val fragmentActivity = activity as? FragmentActivity
      if (fragmentActivity == null) {
        promise?.reject("INVALID_ACTIVITY", "Current activity is not a FragmentActivity.")
        return
      }

      biometricPrompt = BiometricPrompt(
        fragmentActivity,
        executor,
        object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            super.onAuthenticationError(errorCode, errString)
            promise?.reject("AUTH_ERROR", errString.toString())
          }

          override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            try {
              val res = Arguments.createMap()
              res.putBoolean("status", true)
              res.putString("authenticationType", when (result.authenticationType) {
                BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC -> "BIOMETRIC"
                BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL -> "DEVICE_CREDENTIAL"
                else -> "UNKNOWN"
              })
              promise?.resolve(res)
            } catch (e: Exception) {
              promise?.reject("DECRYPT_FAILED", e.message, e)
            }
          }

          override fun onAuthenticationFailed() {
            super.onAuthenticationFailed()
          }
        }
      )

      promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle(value?.getString("title") ?: "Xác thực")
        .setSubtitle(value?.getString("subTitle") ?: "Vui lòng xác thực bằng sinh trắc học hoặc mật khẩu thiết bị")
        .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL or BIOMETRIC_WEAK)
        .build()

      activity.runOnUiThread {
        biometricPrompt.authenticate(promptInfo)
      }

    } catch (e: Exception) {
      promise?.reject("AUTH_INIT_ERROR", e.message, e)
    }
  }

  @ReactMethod
  fun authenticateWithKey(value: ReadableMap?, promise: Promise?) {

    val activity = currentActivity as? FragmentActivity ?: return promise?.reject("NO_ACTIVITY", "Invalid or missing activity.")!!

    try {
      val key = value?.getString("key") ?: "default_key"
      val prefs = reactApplicationContext.getSharedPreferences("auth_prefs", Context.MODE_PRIVATE)
      val encryptedBase64 = prefs.getString("encrypted_token_$key", null)
      val ivBase64 = prefs.getString("iv_$key", null)

      if (encryptedBase64.isNullOrEmpty() || ivBase64.isNullOrEmpty()) {
        promise?.reject("DATA_NOT_FOUND", "Encrypted value or IV not found for key: $key")
        return
      }

      val encryptedBytes = Base64.decode(encryptedBase64, Base64.DEFAULT)
      val ivBytes = Base64.decode(ivBase64, Base64.DEFAULT)

      // 🔐 Prepare cipher for decryption
      val cipher = getCipher()
      cipher.init(Cipher.DECRYPT_MODE, getSecretKey(key), IvParameterSpec(ivBytes))

      // Setup executor and prompt
      executor = ContextCompat.getMainExecutor(reactApplicationContext)
      val fragmentActivity = activity as? FragmentActivity
      if (fragmentActivity == null) {
        promise?.reject("INVALID_ACTIVITY", "Current activity is not a FragmentActivity.")
        return
      }

      biometricPrompt = BiometricPrompt(
        fragmentActivity,
        executor,
        object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            super.onAuthenticationError(errorCode, errString)
            promise?.reject("AUTH_ERROR", errString.toString())
          }

          override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            val finalCipher = result.cryptoObject?.cipher
            try {
              val decryptedBytes = finalCipher?.doFinal(encryptedBytes)
              val decrypted = decryptedBytes?.toString(Charsets.UTF_8)

              val res = Arguments.createMap()
              res.putBoolean("status", true)
              res.putString("authenticationType", when (result.authenticationType) {
                BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC -> "BIOMETRIC"
                BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL -> "DEVICE_CREDENTIAL"
                else -> "UNKNOWN"
              })
              res.putString("value", decrypted)
              promise?.resolve(res)
            } catch (e: Exception) {
              promise?.reject("DECRYPT_FAILED", e.message, e)
            }
          }

          override fun onAuthenticationFailed() {
            super.onAuthenticationFailed()
          }
        }
      )

      promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle(value?.getString("title") ?: "Xác thực")
        .setSubtitle(value?.getString("subTitle") ?: "Vui lòng xác thực bằng sinh trắc học hoặc mật khẩu thiết bị")
        .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
        .build()

      activity.runOnUiThread {
        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
      }

    } catch (e: Exception) {
      promise?.reject("AUTH_INIT_ERROR", e.message, e)
    }
  }

  @ReactMethod
  fun setSecretValue(props: ReadableMap, promise: Promise?) {
    val key = props.getString("key")!!
    val value = props.getString("value")!!
    generateNewKey(key)

    val cipher = getCipher()
    cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(key))

    val activity = currentActivity as? FragmentActivity ?: return promise?.reject("NO_ACTIVITY", "Invalid or missing activity.")!!

    val fragmentActivity = activity as? FragmentActivity
    if (fragmentActivity == null) {
      promise?.reject("INVALID_ACTIVITY", "Current activity is not a FragmentActivity.")
      return
    }

    executor = ContextCompat.getMainExecutor(reactApplicationContext)

    biometricPrompt = BiometricPrompt(
      fragmentActivity,
      executor,
      object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          super.onAuthenticationError(errorCode, errString)
          promise?.reject("AUTH_ERROR", errString.toString())
        }

        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          super.onAuthenticationSucceeded(result)
          val finalCipher = result.cryptoObject?.cipher
          if (finalCipher != null) {
            try {
              val encryptedBytes = finalCipher.doFinal(value.toByteArray(Charsets.UTF_8))
              val encoded = Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
              val iv = finalCipher.iv
              val encodedIV = Base64.encodeToString(iv, Base64.DEFAULT)

              val prefs = reactApplicationContext.getSharedPreferences("auth_prefs", Context.MODE_PRIVATE)
              prefs.edit()
                .putString("encrypted_token_$key", encoded)
                .putString("iv_$key", encodedIV)
                .apply()

              val res = Arguments.createMap()
              res.putBoolean("status", true)
              res.putString("authenticationType", when (result.authenticationType) {
                BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC -> "BIOMETRIC"
                BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL -> "DEVICE_CREDENTIAL"
                else -> "UNKNOWN"
              })
              res.putString("value",value)
              promise?.resolve(res)

            } catch (e: Exception) {
              promise?.reject("ENCRYPTION_FAILED", e.message, e)
            }
          } else {
            promise?.reject("CIPHER_NULL", "Cipher is null after authentication.")
          }
        }

        override fun onAuthenticationFailed() {
          super.onAuthenticationFailed()
        }
      }
    )

    promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Xác thực")
      .setSubtitle("Vui lòng xác thực bằng sinh trắc học hoặc mật khẩu thiết bị")
      .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
      .build()

    // ⚠ Đây là phần QUAN TRỌNG: truyền cipher vào cryptoObject
    activity.runOnUiThread {
      biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }
  }

  private fun generateNewKey(key:String){
    val keyStore = KeyStore.getInstance("AndroidKeyStore")
    keyStore.load(null)
    if (keyStore.containsAlias(key)) return // Đã có key rồi

    generateSecretKey(KeyGenParameterSpec.Builder(
      key,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
      .setUserAuthenticationRequired(true)
      // Invalidate the keys if the user has registered a new biometric
      // credential, such as a new fingerprint. Can call this method only
      // on Android 7.0 (API level 24) or higher. The variable
      // "invalidatedByBiometricEnrollment" is true by default.
      .setInvalidatedByBiometricEnrollment(true)
      .build())
  }

  private fun generateSecretKey(keyGenParameterSpec: KeyGenParameterSpec) {
    val keyGenerator = KeyGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    keyGenerator.init(keyGenParameterSpec)
    keyGenerator.generateKey()
  }

  private fun getSecretKey(keyName:String): SecretKey {
    val keyStore = KeyStore.getInstance("AndroidKeyStore")

    // Before the keystore can be accessed, it must be loaded.
    keyStore.load(null)
    return keyStore.getKey(keyName, null) as SecretKey
  }

  private fun getCipher(): Cipher {
    return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
      + KeyProperties.BLOCK_MODE_CBC + "/"
      + KeyProperties.ENCRYPTION_PADDING_PKCS7)
  }

  companion object {
    const val NAME = "ModuleBiometrics"
  }
}
