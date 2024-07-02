package com.example;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class HandshakeCrack {
    private static final char[] CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?/"
            .toCharArray();
    private static final Logger LOGGER = Logger.getLogger(HandshakeCrack.class.getName());

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Uso: java HandshakeCrack <ruta_al_archivo_handshake>");
            return;
        }

        String handshakeFilePath = args[0];
        HandshakeData handshake = readHandshakeFile(handshakeFilePath);
        if (handshake == null) {
            System.out.println("No se pudo leer el archivo de handshake.");
            return;
        }

        int length = 8; // Longitud de la contraseña
        char[] currentCombination = new char[length];
        Arrays.fill(currentCombination, CHARACTERS[0]);

        while (true) {
            String combination = new String(currentCombination);
            System.out.println("Probando combinación: " + combination);

            // Probar la combinación contra el archivo de handshake
            if (testHandshake(combination, handshake)) {
                System.out.println("Contraseña encontrada: " + combination);
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

    private static boolean testHandshake(String combination, HandshakeData handshake) {
        byte[] pmk = generatePMK(combination, handshake.ssid);
        byte[] ptk = generatePTK(pmk, handshake.apNonce, handshake.clientNonce, handshake.apMac, handshake.clientMac);
        return verifyMIC(ptk, handshake.eapol, handshake.mic);
    }

    private static byte[] generatePMK(String password, String ssid) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA1Digest());
        generator.init(password.getBytes(), ssid.getBytes(), 4096);
        KeyParameter key = (KeyParameter) generator.generateDerivedParameters(256);
        return key.getKey();
    }

    private static byte[] generatePTK(byte[] pmk, byte[] apNonce, byte[] clientNonce, byte[] apMac, byte[] clientMac) {
        byte[] ptk = new byte[64];
        byte[] data = new byte[76];

        System.arraycopy(apMac, 0, data, 0, 6);
        System.arraycopy(clientMac, 0, data, 6, 6);
        System.arraycopy(apNonce, 0, data, 12, 32);
        System.arraycopy(clientNonce, 0, data, 44, 32);

        HMac hmac = new HMac(new SHA1Digest());
        hmac.init(new KeyParameter(pmk));

        for (int i = 0; i < 4; i++) {
            hmac.update(data, 0, data.length);
            hmac.update((byte) i);
            hmac.doFinal(ptk, i * 20);
        }

        return ptk;
    }

    private static boolean verifyMIC(byte[] ptk, byte[] eapol, byte[] mic) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(ptk, 0, 16, "HmacSHA1"));
            byte[] computedMic = mac.doFinal(eapol);

            return Arrays.equals(mic, Arrays.copyOf(computedMic, 16));
        } catch (NoSuchAlgorithmException e) {
            LOGGER.log(Level.SEVERE, "Algoritmo no encontrado", e);
            return false;
        } catch (InvalidKeyException e) {
            LOGGER.log(Level.SEVERE, "Clave inválida", e);
            return false;
        }
    }

    private static HandshakeData readHandshakeFile(String filePath) {
        HandshakeData handshakeData = new HandshakeData();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(": ");
                switch (parts[0]) {
                    case "SSID" -> handshakeData.ssid = parts[1];
                    case "AP_NONCE" -> handshakeData.apNonce = hexStringToByteArray(parts[1]);
                    case "CLIENT_NONCE" -> handshakeData.clientNonce = hexStringToByteArray(parts[1]);
                    case "AP_MAC" -> handshakeData.apMac = hexStringToByteArray(parts[1]);
                    case "CLIENT_MAC" -> handshakeData.clientMac = hexStringToByteArray(parts[1]);
                    case "MIC" -> handshakeData.mic = hexStringToByteArray(parts[1]);
                    case "EAPOL" -> handshakeData.eapol = hexStringToByteArray(parts[1]);
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error al leer el archivo de handshake", e);
            return null;
        }
        return handshakeData;
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    static class HandshakeData {
        String ssid;
        byte[] apNonce;
        byte[] clientNonce;
        byte[] apMac;
        byte[] clientMac;
        byte[] mic;
        byte[] eapol;
    }
}
