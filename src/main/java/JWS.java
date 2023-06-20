import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class JWS {
    private JWSSigner signer;
    private JWSVerifier verifier;

    public JWS(JWSSigner signer, JWSVerifier verifier) {
        this.signer = signer;
        this.verifier = verifier;
    }

    public String sign(String payload) throws JOSEException {
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload(payload));
        jwsObject.sign(signer);
        return jwsObject.serialize();
    }

    public boolean verify(String serializedJWS) throws JOSEException, ParseException {
        JWSObject jwsObject = JWSObject.parse(serializedJWS);
        return jwsObject.verify(verifier);
    }

    public static void main(String[] args) throws ParseException {
        try {

            // Generate an RSA key pair (public key and private key)
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            JWSSigner signer = new RSASSASigner(privateKey);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            // Create a JWS with signer and verifier
            JWS jws = new JWS(signer, verifier);

            // Sign date
            String payload = "Hello, world!";
            String serializedJWS = jws.sign(payload);
            System.out.println("Serialized JWS: " + serializedJWS);

            // Verify data
            boolean verified = jws.verify(serializedJWS);
            System.out.println("Verified: " + verified);

        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
