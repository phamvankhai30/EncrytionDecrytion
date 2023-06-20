import com.nimbusds.jose.*;
import java.security.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;


public class JWE {

    public  String encrypt(String plainText, RSAPublicKey rsaPublickey) throws JOSEException, NoSuchAlgorithmException, InvalidKeySpecException {

        // Create a JWEHeader object with the specified JWE algorithm and encryption method
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

        // Create a Payload object to hold the data to be encrypted
        Payload payload = new Payload(plainText);

        // Create a JWEObject with the encryption algorithm and symmetric key
        JWEObject jweObject = new JWEObject(header, payload);

        // Set the symmetric key
        jweObject.encrypt(new RSAEncrypter(rsaPublickey));

        // Return the serialized JWE string
        return jweObject.serialize();
    }

    public String decrypt(String encryptedJWE, RSAPrivateKey rsaPrivateKey) throws JOSEException, ParseException, NoSuchAlgorithmException, InvalidKeySpecException {

        // Parse the encrypted JWE string
        JWEObject jweObject = JWEObject.parse(encryptedJWE);

        // Decrypt the JWE using the symmetric key
        jweObject.decrypt(new RSADecrypter(rsaPrivateKey));

        // Return the decrypted data
        return jweObject.getPayload().toString();
    }

    public static void main(String[] args) throws ParseException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            JWE jwe = new JWE();
            String plainText = "Hello, World!";

            // Encrypt the data
            String encryptedJWE = jwe.encrypt(plainText,publicKey);
            System.out.println("Encrypted JWE: " + encryptedJWE);

            // Decrypt the data
             String decryptedText = jwe.decrypt(encryptedJWE, privateKey);
            System.out.println("Decrypted Text: " + decryptedText);

        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
