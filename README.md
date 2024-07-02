 HandshakeCrack

`HandshakeCrack` es una herramienta para probar combinaciones de contraseñas contra un archivo de handshake de red Wi-Fi. Utiliza el algoritmo PBKDF2 para generar la clave maestra (PMK) y el algoritmo HMAC-SHA1 para verificar el MIC.

 Requisitos

- Java 12 o superior
- Biblioteca BouncyCastle

Instalación

1. Clonar el repositorio:

   ```sh
   git clone https://github.com/tu-usuario/HandshakeCrack.git
   cd HandshakeCrack
   ```

2. Agregar la biblioteca BouncyCastle:

   Descarga la biblioteca BouncyCastle desde [aquí](https://www.bouncycastle.org/latest_releases.html) y agrégala a tu proyecto.

3. Compilar el proyecto:

   ```sh
   javac -cp "ruta/a/bouncycastle.jar" src/main/java/com/example/HandshakeCrack.java
   ```

 Uso

1. Ejecutar el programa:

   ```sh
   java -cp "ruta/a/bouncycastle.jar:src/main/java" com.example.HandshakeCrack <ruta_al_archivo_handshake>
   ```

   Reemplaza `<ruta_al_archivo_handshake>` con la ruta al archivo de handshake que deseas probar.

2. Formato del archivo de handshake:

   El archivo de handshake debe tener el siguiente formato:

   ```
   SSID: nombre_de_la_red
   AP_NONCE: valor_hexadecimal
   CLIENT_NONCE: valor_hexadecimal
   AP_MAC: valor_hexadecimal
   CLIENT_MAC: valor_hexadecimal
   MIC: valor_hexadecimal
   EAPOL: valor_hexadecimal
   ```

 Ejemplo

```sh
java -cp "ruta/a/bouncycastle.jar:src/main/java" com.example.HandshakeCrack handshake.txt
```

 Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue o envía un pull request.

 Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

 Contacto

Para cualquier pregunta o sugerencia, por favor contacta a [abraham_moyo@hotmail.com]
```
