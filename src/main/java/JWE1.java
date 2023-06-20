import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;

import com.nimbusds.jose.crypto.DirectEncrypter;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;

public class JWE1 {

    public  String encrypt(String plainText, String secretKey) throws JOSEException, NoSuchAlgorithmException {
        // Create a symmetric key from the secret key string
        byte[] sharedKey = secretKey.getBytes();

        // Create a JWEHeader object with the specified JWE algorithm and encryption method
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);

        // Create a Payload object to hold the data to be encrypted
        Payload payload = new Payload(plainText);

        // Create a JWEObject with the encryption algorithm and symmetric key
        JWEObject jweObject = new JWEObject(header, payload);

        // Set the symmetric key
        jweObject.encrypt(new DirectEncrypter(sharedKey));

        // Return the serialized JWE string
        return jweObject.serialize();
    }

    public String decrypt(String encryptedJWE, String secretKey) throws JOSEException, ParseException {
        // Create a symmetric key from the secret key string
        byte[] sharedKey = secretKey.getBytes();

        // Parse the encrypted JWE string
        JWEObject jweObject = JWEObject.parse(encryptedJWE);

        // Decrypt the JWE using the symmetric key
        jweObject.decrypt(new DirectDecrypter(sharedKey));

        // Return the decrypted data
        return jweObject.getPayload().toString();
    }

    public static void main(String[] args) throws ParseException {
        try {
            JWE1 jwe = new JWE1();
            String secretKey = "12345678912345671234567891234567";
            String plainText = "Hello, World!";

            // Encrypt the data
            String encryptedJWE = jwe.encrypt(plainText,secretKey);
            System.out.println("Encrypted JWE: " + encryptedJWE);

            // Decrypt the data
            String decryptedText = jwe.decrypt(encryptedJWE, secretKey);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
