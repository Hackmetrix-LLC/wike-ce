### Descripción

La recuperación de información a través de bases de datos locales y archivos de respaldo, se produce a partir de funciones internas del sistema operativo o bien, desde métodos propios de la aplicación. Con frecuencia ocurre que este tipo de datos son de carácter sensible, como pueden ser Tokens de sesiones, nombres de usuario, claves o coordenadas GPS. Un atacante con acceso físico puede acceder a esta información y comprometer el perfil de un usuario víctima.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

Hackmetrix logró acceder a datos confidenciales desde los directorios internos de la aplicación a través de la herramienta **adb**:

El equipo de AppSec procedió a ejecutar el siguiente comando utilizando la herramienta **adb** con la finalidad de poder visualizar el contenido del archivo *§NOMBRE ARCHIVO§*:

*Code:*

```
§ root@shamu:/data/data/com.example.app/shared_prefs # cat FlutterSharedPreferences.xml §
```

Luego de ejecutar el comando, fue posible visualizar el contenido del archivo el cual contenía datos sensible tales como nombre de usuario, empresas, dominio y tokens de sesión:

*File:*

```
§CONTENIDO ARCHIVO§
```

### Impacto

Consiguiendo acceso físico al dispositivo, un atacante podría obtener datos sensible tales como nombre de usuario, empresas, dominio y tokens de sesión. También, debido a la existencia de la vulnerabilidad **Allow Rooted Android Devices (CWE-250)** otras aplicaciones maliciosas podrían acceder al contenido del directorio **/data/data/§NOMBRE_APP§/** y obtener dichos datos sensibles.

### Remediación

El equipo de AppSec recomienda evitar almacenar información sensible perteneciente a los usuarios en el dispositivo local. En caso de ser necesario realizar una nueva sesión en la aplicación se debería solicitar a un canal externo, como puede ser una aplicación web o una API.

Además, se debe utilizar protecciones de cifrado, como AES 256, en caso de almacenar ficheros que contengan información sensible perteneciente al usuario que utiliza la aplicación y asegurándose de que la clave empleada esté almacenada del lado del servidor. A continuación, se detalla a modo de prueba de concepto cómo es posible implementar AES 256 en [Kotlin/Flutter/React Native].

§[KOTLIN]§

En el siguiente fragmento de código, se específica como crear una clase para utilizar el **Android Keystore** para almacenar la clave secreta de forma segura y **javax.crypto** para el cifrado y descifrado de archivos:

*Code:*

```
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream// Creación de la clase FileEncryptorDecrypto
object FileEncryptorDecryptor {
    // Especifica el algoritmo y modo de cifrado.
    private const val TRANSFORMATION = "AES/CBC/PKCS7Padding"
    // Usa Android Keystore para el almacenamiento seguro de claves.
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    // Alias para la clave en el Keystore.
    private const val ALIAS = "MyKeyAlias"    /**
     * Genera y almacena una clave AES en el Android Keystore.
     */
    fun generateKey() {
        // Configura el generador de claves para AES y el Keystore.
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setKeySize(256)
            .build()
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey() // Genera la clave.
    }    /**
     * Obtiene la clave AES almacenada en el Android Keystore.
     */
    private fun getSecretKey(): SecretKey {
        val keyStore = java.security.KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null) // Carga el Keystore.
        return keyStore.getKey(ALIAS, null) as SecretKey
    }    /**
     * Cifra un archivo y lo guarda con extensión ".enc".
     * @return IV utilizado para el cifrado.
     */
    fun encryptFile(context: Context, file: File): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
        val fileInputStream = FileInputStream(file)
        val encryptedBytes = cipher.doFinal(fileInputStream.readBytes()) // Cifra los datos del archivo.
        fileInputStream.close()
        val iv = cipher.iv // Obtiene el vector de inicialización (IV).
        // Guarda el archivo cifrado.
        val encryptedFile = File(context.filesDir, file.name + ".enc")
        FileOutputStream(encryptedFile).apply {
            write(iv) // Guarda el IV con el archivo cifrado para su uso en el descifrado.
            write(encryptedBytes)
            flush()
            close()
        }
        return iv
    }    /**
     * Descifra un archivo cifrado utilizando el IV proporcionado.
     */
    fun decryptFile(context: Context, file: File, iv: ByteArray): File {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), IvParameterSpec(iv)) // Inicializa el cifrador en modo descifrado.
        val fileInputStream = FileInputStream(file)
        // Lee el archivo excluyendo el IV.
        val fileBytes = fileInputStream.readBytes().sliceArray(iv.size until fileBytes.size)
        val decryptedBytes = cipher.doFinal(fileBytes) // Descifra los datos.
        fileInputStream.close()
        // Guarda el archivo descifrado.
        val decryptedFile = File(context.filesDir, file.name.removeSuffix(".enc"))
        FileOutputStream(decryptedFile).apply {
            write(decryptedBytes)
            flush()
            close()
        }
        return decryptedFile
    }
}
```

Por otra parte, en el siguiente fragmento de código podemos observar a modo de ejemplo, como utilizar dicha clase para encriptar y desencriptar un archivo:

*Code:*

```
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import java.io.Fileclass MainActivity : AppCompatActivity() {    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)        // Inicializa el sistema de cifrado generando la clave si es necesario.
        FileEncryptorDecryptor.generateKey()        // Define el archivo a cifrar.
        val fileToEncrypt = File(filesDir, "file_to_encrypt.txt")
        // Asegúrate de que el archivo exista para este ejemplo.
        if (!fileToEncrypt.exists()) {
            fileToEncrypt.writeText("Contenido secreto")
        }        // Cifra el archivo.
        val iv = FileEncryptorDecryptor.encryptFile(this, fileToEncrypt)
        //Log.d("Encryption", "Archivo cifrado: ${fileToEncrypt.name}.enc")        // El archivo cifrado tiene la extensión .enc.
        val encryptedFile = File(filesDir, "${fileToEncrypt.name}.enc")        // Descifra el archivo. Necesitarás el IV que se utilizó para cifrarlo.
        val decryptedFile = FileEncryptorDecryptor.decryptFile(this, encryptedFile, iv)
        //Log.d("Decryption", "Archivo descifrado: ${decryptedFile.name}")
    }
}
```

§[FIN DE KOTLIN]§

§FLUTTER]§

En el siguiente fragmento de código, se específica como se puede utilizar los paquetes **flutter_secure_storage** y **encrypt** en conjunto para almacenar y recuperar claves de forma segura y para encriptar y desencriptar los archivos:

*secure_file_storage.dart*

```
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'dart:io';
import 'package:path_provider/path_provider.dart';class SecureFileStorage {
  final _storage = FlutterSecureStorage();
  final iv = encrypt.IV.fromLength(16);
  late encrypt.Encrypter encrypter;  // Inicializa el objeto Encrypter con una clave AES generada aleatoriamente
  // y almacena esta clave de forma segura en el almacenamiento del dispositivo.
  Future<void> init() async {
    String? keyBase64 = await _storage.read(key: 'encryptionKey');    // Si no existe una clave previa, genera una nueva y la almacena.
    if (keyBase64 == null) {
      final key = encrypt.Key.fromSecureRandom(32); // AES 256
      encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.cbc));
      await _storage.write(key: 'encryptionKey', value: key.base64);
    } else {
      // Si ya existe, utiliza la clave almacenada para el cifrador.
      final key = encrypt.Key.fromBase64(keyBase64);
      encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.cbc));
    }
  }  // Toma un archivo como entrada, cifra su contenido y guarda el resultado
  // en un nuevo archivo con la extensión ".enc", incluyendo el IV al principio.
  Future<void> encryptFile(File file) async {
    final content = await file.readAsBytes();
    final encrypted = encrypter.encryptBytes(content, iv: iv);    final directory = await getApplicationDocumentsDirectory();
    final encryptedFile = File('${directory.path}/${file.path.split('/').last}.enc');
    await encryptedFile.writeAsBytes(iv.bytes + encrypted.bytes);
  }  // Toma un archivo cifrado como entrada, extrae el IV, descifra el contenido
  // y guarda el resultado en un nuevo archivo, eliminando la extensión ".enc".
  Future<File> decryptFile(File encryptedFile) async {
    final content = await encryptedFile.readAsBytes();
    final iv = encrypt.IV(content.sublist(0, 16));
    final encryptedContent = content.sublist(16);
    final decrypted = encrypter.decryptBytes(encrypt.Encrypted(encryptedContent), iv: iv);    final directory = await getApplicationDocumentsDirectory();
    final decryptedFile = File('${directory.path}/${encryptedFile.path.split('/').last.replaceFirst('.enc', '')}');
    await decryptedFile.writeAsBytes(decrypted);
    return decryptedFile;
  }
}
```

Por otra parte, en el siguiente fragmento de código podemos observar a modo de ejemplo, como utilizar dicha clase para encriptar y desencriptar un archivo:

*main.dart:*

```
import 'dart:io';
import 'package:flutter/material.dart';
import 'secure_file_storage.dart'; // Asegúrate de tener este archivo en tu proyecto.
import 'package:path_provider/path_provider.dart';void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final storage = SecureFileStorage();
  await storage.init(); // Asegura que la clave de cifrado esté lista para usar.
  runApp(MyApp(storage: storage));
}class MyApp extends StatelessWidget {
  final SecureFileStorage storage;  MyApp({required this.storage});  // Función para demostrar cifrado y descifrado automáticamente.
  void demoEncryption() async {
    final directory = await getApplicationDocumentsDirectory();
    final file = File('${directory.path}/example.txt'); // Especificar archive a cifrar o desifrar    // Asegura que el archivo de ejemplo exista.
    if (!file.existsSync()) {
      await file.writeAsString('Hello, Secure World!');
    }    // Cifra el archivo de ejemplo.
    await storage.encryptFile(file);
    print('File encrypted');    // Descifra el archivo.
    final encryptedFile = File('${directory.path}/example.txt.enc');
    await storage.decryptFile(encryptedFile);
    print('File decrypted');
  }  @override
  Widget build(BuildContext context) {
    demoEncryption(); // Ejecuta demo de cifrado y descifrado al iniciar.
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: Text('Simple Secure Storage Demo')),
        body: Center(
          child: Text('Check your console logs for encryption and decryption status.'),
        ),
      ),
    );
  }
}
```

§FIN DE FLUTTER]§

§REACT NATIVE]§

En el siguiente fragmento de código, se específica como se puede utilizar los paquetes **react-native-keychain** y **NativeModules.Aes** en conjunto para almacenar y recuperar claves de forma segura y para encriptar y desencriptar los archivos:

*EncryptionManager.js*

```
import * as Keychain from 'react-native-keychain';
import { NativeModules } from 'react-native';
import RNFS from 'react-native-fs';
const Aes = NativeModules.Aes;class EncryptionManager {
  static service = 'myAppEncryption';  /**
   * Genera una nueva clave de cifrado de 256 bits y la almacena de forma segura.
   * @returns {Promise<string>} La clave generada.
   */
  static async generateAndStoreKey() {
    const key = await Aes.randomKey(32); // Generate a 256-bit key
    await Keychain.setGenericPassword('encryptionKeyUser', key, { service: EncryptionManager.service });
    return key;
  }  /**
   * Obtiene la clave de cifrado almacenada de forma segura. Si no existe, genera una nueva.
   * @returns {Promise<string|null>} La clave de cifrado o null en caso de error.
   */
  static async getSecureKey() {
    try {
      const credentials = await Keychain.getGenericPassword({ service: EncryptionManager.service });
      if (credentials) {
        return credentials.password;
      } else {
        // If no key found, generate a new one
        return await EncryptionManager.generateAndStoreKey();
      }
    } catch (error) {
      console.log('Error handling the encryption key.', error);
      return null;
    }
  }  /**
   * Cifra un archivo utilizando AES-256-CBC y guarda el resultado en un nuevo archivo.
   * @param {string} filePath Ruta del archivo a cifrar.
   * @param {string} key Clave de cifrado.
   * @returns {Promise<{encryptedFilePath: string, iv: string}>} Objeto con la ruta del archivo cifrado y el IV utilizado.
   */
  static async encryptFile(filePath, key) {
    try {
      const iv = await Aes.randomKey(16); // Generate a 16-byte IV
      const fileContent = await RNFS.readFile(filePath, 'base64');
      const encryptedContent = await Aes.encrypt(fileContent, key, iv, 'aes-256-cbc');
      const encryptedFilePath = `${filePath}.enc`;
      await RNFS.writeFile(encryptedFilePath, encryptedContent, 'base64');
      return { encryptedFilePath, iv };
    } catch (error) {
      console.log('Error encrypting the file:', error);
    }
  }  /**
   * Descifra un archivo cifrado con AES-256-CBC.
   * @param {string} encryptedFilePath Ruta del archivo cifrado.
   * @param {string} key Clave de cifrado.
   * @param {string} iv Vector de inicialización utilizado al cifrar.
   * @returns {Promise<string>} Ruta del archivo descifrado.
   */
  static async decryptFile(encryptedFilePath, key, iv) {
    try {
      const encryptedContent = await RNFS.readFile(encryptedFilePath, 'base64');
      const decryptedContent = await Aes.decrypt(encryptedContent, key, iv, 'aes-256-cbc');
      const decryptedFilePath = encryptedFilePath.replace('.enc', '');
      await RNFS.writeFile(decryptedFilePath, decryptedContent, 'base64');
      return decryptedFilePath;
    } catch (error) {
      console.log('Error decrypting the file:', error);
    }
  }
}export default EncryptionManager;
```

Por otra parte, en el siguiente fragmento de código podemos observar a modo de ejemplo, la implementación de una clase Main para encriptar y desencriptar un archivo:

*Code:*

```
import EncryptionManager from './EncryptionManager';const filePath = 'path/to/your/file.txt'; // Actualiza esto con la ruta de tu archivoconst runEncryptionDemo = async () => {
  const secureKey = await EncryptionManager.getSecureKey();  if (secureKey) {
    const { encryptedFilePath, iv } = await EncryptionManager.encryptFile(filePath, secureKey);
    console.log(`Encrypted file saved at: ${encryptedFilePath}`);    const decryptedFilePath = await EncryptionManager.decryptFile(encryptedFilePath, secureKey, iv);
    console.log(`Decrypted file restored at: ${decryptedFilePath}`);
  }
};runEncryptionDemo();
```

§FIN DE REACT NATIVE]§

### Referencias

- Top 10 Mobile Risks 2016 – M2: Insecure Data Storagehttps://owasp.org/www-project-mobile-top-10/2014-risks/m2-insecure-data-storage
- CWE-922: Insecure Storage of Sensitive Informationhttps://cwe.mitre.org/data/definitions/922.html

