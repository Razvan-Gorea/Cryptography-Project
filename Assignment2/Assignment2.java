import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;

public class Assignment2 {
    public static void main(String[] args) {
        BigInteger prime1 = new BigInteger(
                "00f5a730477460462851ce0e08e98937a97ffe3bf7734418a9b09255df009c0a1fc99fa0444a484cb810e9189850d913faf13f466a1fdb09b6f2bcc555892244a1",
                16);

        BigInteger prime2 = new BigInteger(
                "00c2917e64e66e7692ccae1b5eadda7bd12c01fbfae73cf71bab7f7bbb44b11adb85b1ba25205cce4f4259047dd628e6f0211b0b2ac5bc2e9ac130b7590dbb30ad",
                16);

        BigInteger e = BigInteger.valueOf(65537);

        BigInteger n = prime1.multiply(prime2);

        write_to_a_file(n.toString(16), "Modulus.txt");

        BigInteger totient_result = euler_totient(prime1, prime2);

        BigInteger d = mod_inverse(e, totient_result);

        File input_file = new File(args[0]);

        try {
            byte[] file_as_bytes = Files.readAllBytes(input_file.toPath());
            byte[] message_digest = digest_method(file_as_bytes);
            BigInteger digest = new BigInteger(1, message_digest);
            BigInteger result = decryption_method(digest, d, prime1, prime2, n);

            System.out.print(result.toString(16));
        } catch (IOException | NoSuchAlgorithmException err) {
            err.printStackTrace();

        }
    }

    // function to get phi(n)
    public static BigInteger euler_totient(BigInteger prime1, BigInteger prime2) {
        BigInteger result = (prime1.subtract(BigInteger.ONE)).multiply(prime2.subtract(BigInteger.ONE));
        return result;
    }

    // modular inverse method
    public static BigInteger mod_inverse(BigInteger a, BigInteger m) {
        BigInteger m0 = m, t = BigInteger.ZERO, newT = BigInteger.ONE;
        BigInteger r = m, newR = a;

        while (!newR.equals(BigInteger.ZERO)) {
            BigInteger quotient = r.divide(newR);

            BigInteger tempT = t;
            t = newT;
            newT = tempT.subtract(quotient.multiply(newT));

            BigInteger tempR = r;
            r = newR;
            newR = tempR.subtract(quotient.multiply(newR));
        }

        // If gcd(a, m) != 1, then the inverse does not exist
        if (!r.equals(BigInteger.ONE)) {
            throw new ArithmeticException("Multiplicative inverse does not exist");
        }

        // Making sure the inverse result is positive
        if (t.compareTo(BigInteger.ZERO) < 0) {
            t = t.add(m0);
        }

        return t;
    }

    // method to take in a file at arg 0 and create a 256 SHA digest
    public static byte[] digest_method(byte[] input_file) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] checker = input_file;

        byte first_byte = checker[0];

        byte[] new_checker = checker;
        
        //checking for two's compliement
        if (first_byte == 0){
            new_checker = new byte[checker.length - 1];
            System.arraycopy(checker, 1, new_checker, 0, new_checker.length);
        }

        byte[] message_digest = digest.digest(new_checker);
        return message_digest;
    }

    // decryption method
    public static BigInteger decryption_method(BigInteger digest, BigInteger d, BigInteger p, BigInteger q,
            BigInteger n) {

        // Chinese Remainder Theorem

        BigInteger m1 = mod_inverse(p, q);

        // assert m1.equals(p.modInverse(q));

        BigInteger m2 = mod_inverse(q, p);

        // assert m2.equals(q.modInverse(p));

        BigInteger result = digest.modPow(d, q).multiply(m1).multiply(p)
                .add(digest.modPow(d, p).multiply(m2).multiply(q));

        return result.mod(n).mod(n);
    }

    // method to write n to a modulus.txt
    public static void write_to_a_file(String n, String file_path) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file_path))) {
            writer.write(n);
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
        }
    }
}