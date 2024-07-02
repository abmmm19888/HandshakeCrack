HandshakeCrack

`HandshakeCrack` es una herramienta de fuerza bruta para probar combinaciones de contraseñas contra un archivo de handshake. Este proyecto está escrito en Java y utiliza un enfoque de fuerza bruta para encontrar la contraseña correcta.

 Características

- Prueba combinaciones de contraseñas utilizando un conjunto de caracteres predefinido.
- Registra solo la combinación correcta en un archivo de log.
- Simula la autenticación de WPA/WPA2 utilizando un archivo de handshake.

Requisitos

- Java 8 o superior

 Uso

Para ejecutar `HandshakeCrack`, sigue estos pasos:

1. Compila el código fuente:

    ```sh
    javac -d bin src/com/example/HandshakeCrack.java
    ```

2. Ejecuta el programa con la ruta al archivo de handshake como argumento:

    ```sh
    java -cp bin com.example.HandshakeCrack <ruta_al_archivo_handshake>
    ```

    Reemplaza `<ruta_al_archivo_handshake>` con la ruta real al archivo de handshake que deseas utilizar.

 Ejemplo

```sh
java -cp bin com.example.HandshakeCrack /ruta/a/tu/archivo_handshake.cap
```

 Código Fuente

```java
package com.example;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HandshakeCrack {
    private static final char[] CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?/"
            .toCharArray();
    private static final String LOG_FILE = "password_attempts.log";
    private static final Logger LOGGER = Logger.getLogger(HandshakeCrack.class.getName());

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Uso: java PasswordCracker <ruta_al_archivo_handshake>");
            return;
        }

        String handshakeFilePath = args[0];
        byte[] handshakeData;

        try {
            handshakeData = Files.readAllBytes(Paths.get(handshakeFilePath));
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error al leer el archivo de handshake", e);
            return;
        }

        int length = 8; // Longitud de la contraseña
        char[] currentCombination = new char[length];
        Arrays.fill(currentCombination, CHARACTERS[0]);

        while (true) {
            String combination = new String(currentCombination);
            System.out.println("Probando combinación: " + combination);

            // Probar la combinación contra el archivo de handshake
            if (testHandshake(combination, handshakeData)) {
                System.out.println("Contraseña encontrada: " + combination);

                // Registrar la combinación correcta en el archivo de log
                try (BufferedWriter logWriter = new BufferedWriter(new FileWriter(LOG_FILE, true))) {
                    logWriter.write(combination);
                    logWriter.newLine();
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Error al escribir en el archivo de log", e);
                }
                break;
            }

            // Generar la siguiente combinación
            if (!incrementCombination(currentCombination)) {
                break;
            }
        }

        System.out.println("Todas las combinaciones procesadas.");
    }

    private static boolean incrementCombination(char[] combination) {
        int position = combination.length - 1;
        while (position >= 0) {
            if (combination[position] == CHARACTERS[CHARACTERS.length - 1]) {
                combination[position] = CHARACTERS[0];
                position--;
            } else {
                combination[position] = CHARACTERS[getIndex(combination[position]) + 1];
                return true;
            }
        }
        return false;
    }

    private static int getIndex(char c) {
        for (int i = 0; i < CHARACTERS.length; i++) {
            if (CHARACTERS[i] == c) {
                return i;
            }
        }
        return -1; // Nunca debería suceder
    }

    private static boolean testHandshake(String combination, byte[] handshakeData) {
        // Aquí deberías implementar la lógica para probar la combinación contra el
        // archivo de handshake
        // Esto puede implicar el uso de bibliotecas de red y criptografía para
        // autenticar WPA/WPA2
        // Por ahora, simularemos la prueba con una contraseña correcta simulada
        String correctPassword = "password"; // Simulación de la contraseña correcta
        // Simulate using handshakeData in some way
        return combination.equals(correctPassword) && handshakeData.length > 0;
    }
}
```

 Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue o un pull request para discutir cualquier cambio que te gustaría hacer.

 Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
```
