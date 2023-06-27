package ir.mohaymen.jwedecoder.util;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.security.PrivateKey;

public final class KeyGeneratorUtils {
    public static PrivateKey readPrivateKeyFromPem(File file) throws IOException {
        try (FileReader keyReader = new FileReader(file)) {
            return readPrivateKeyFromPem(keyReader);
        }
    }

    public static PrivateKey readPrivateKeyFromPem(Reader keyReader) throws IOException {
        try (PEMParser pemReader = new PEMParser(keyReader)) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            Object keyPair = pemReader.readObject();
            if (keyPair instanceof PEMKeyPair) {
                return converter.getPrivateKey(((PEMKeyPair) keyPair).getPrivateKeyInfo());
            } else {
                return converter.getPrivateKey((PrivateKeyInfo) keyPair);
            }
        }
    }
}