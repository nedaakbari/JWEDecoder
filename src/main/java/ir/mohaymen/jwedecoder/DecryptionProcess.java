package ir.mohaymen.jwedecoder;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jwt.EncryptedJWT;

import ir.mohaymen.jwedecoder.util.KeyGeneratorUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.text.ParseException;

@Component
public class DecryptionProcess {
    private static final String DATA = "data";
    private static final JWEAlgorithm ALGORITHM = JWEAlgorithm.ECDH_ES_A256KW;
    private static final EncryptionMethod ENC = EncryptionMethod.A256GCM;
    private final ECDHDecrypter decrypter;

    public DecryptionProcess(@Value("${encryption_data.privateKey}") String filePath)
            throws JOSEException, IOException, NoSuchAlgorithmException, InvalidParameterSpecException {
        ECPrivateKey ecPrivateKey = getPrivateKey(filePath);
        validatePrivateKey(ecPrivateKey);
        this.decrypter = new ECDHDecrypter(ecPrivateKey);
    }

    private void validatePrivateKey(ECPrivateKey privateKey)
            throws IOException, NoSuchAlgorithmException, InvalidParameterSpecException {
        AlgorithmParameters params = AlgorithmParameters.getInstance(privateKey.getAlgorithm());
        params.init(privateKey.getParams());
        String oid = params.getParameterSpec(ECGenParameterSpec.class).getName();
        if (!oid.equals("1.3.132.0.35")) { // secp521r1
            throw new IOException("size of key is not correct");
        }
    }

    public String decryptData(String encryptedData) throws ParseException, JOSEException {
        EncryptedJWT jwt = EncryptedJWT.parse(encryptedData);
        jwt.decrypt(decrypter);
        validateAlgorithm(jwt.getHeader());
        return (String) jwt.getJWTClaimsSet().getClaim(DATA);
    }

    private void validateAlgorithm(JWEHeader header) {
        if (!header.getAlgorithm().equals(ALGORITHM)) {
            throw new RuntimeException("algorithm is not supported. " + header.getAlgorithm());
        }
        if (header.getEncryptionMethod() != ENC) {
            throw new RuntimeException("encryption method is not supported. " + header.getEncryptionMethod());
        }
    }

    private ECPrivateKey getPrivateKey(String filePath) throws IOException {
        String privateKeyPath = Paths.get("").toAbsolutePath() + "/EC/" + filePath;
        return (ECPrivateKey) KeyGeneratorUtils.readPrivateKeyFromPem(new File(privateKeyPath));
    }
}