package ir.mohaymen.jwedecoder;

import com.nimbusds.jose.JOSEException;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Scanner;

@Component
@RequiredArgsConstructor
public class Runner implements CommandLineRunner {
    private final DecryptionProcess decryptionProcess;

    @Override
    public void run(String... args) throws JOSEException, ParseException {
        var scanner = new Scanner(System.in);
        while (true) {
            System.out.println("input encrypt data:");
            var input = scanner.nextLine();
            var jwe = decryptionProcess.decryptData(input);
            System.out.println("decrypted data:\n" + jwe);
        }
    }
}
