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
        //Random rand = new Random();
        //Random rand2 = new Random();

        // BigInteger e = new BigInteger("65537", 10);

        // BigInteger prime1 = BigInteger.probablePrime(512, rand);
        // BigInteger prime2 = BigInteger.probablePrime(512, rand2);

        // while (prime1 == prime2) {
        //     rand2 = new Random();
        //     prime2 = BigInteger.probablePrime(512, rand2);
        // }
        
        // BigInteger prime1 = BigInteger.probablePrime(512, rand);
        // BigInteger prime2 = BigInteger.probablePrime(512, rand2);
        
        // while (prime1 == prime2) {
            //     rand2 = new Random();
            //     prime2 = BigInteger.probablePrime(512, rand2);
            //}
            
            
            // while (!gcd_number.equals(BigInteger.ONE)) {
            //     rand = new Random();
            //     rand2 = new Random();
            //     prime1 = BigInteger.probablePrime(512, rand);
            //     prime2 = BigInteger.probablePrime(512, rand2);
            //     n = prime1.multiply(prime2);
            //     totient_result = euler_totient(prime1, prime2);
            //     gcd_number = gcd_method(totient_result, e);
            // }
            // BigInteger gcd_number = gcd_method(totient_result, e);
            
        
        BigInteger prime1 = new BigInteger("00f5a730477460462851ce0e08e98937a97ffe3bf7734418a9b09255df009c0a1fc99fa0444a484cb810e9189850d913faf13f466a1fdb09b6f2bcc555892244a1", 16);
        BigInteger prime2 = new BigInteger("00c2917e64e66e7692ccae1b5eadda7bd12c01fbfae73cf71bab7f7bbb44b11adb85b1ba25205cce4f4259047dd628e6f0211b0b2ac5bc2e9ac130b7590dbb30ad", 16);
        BigInteger e = BigInteger.valueOf(65537);
        

        BigInteger n = prime1.multiply(prime2);
        write_to_a_file(n.toString(16), "Modulus.txt");

        BigInteger totient_result = euler_totient(prime1, prime2);


        // change the prime values if e is not relative prime to phi(n)

        /*
         * Testing if gcd method works
         * 
         * BigInteger test1 = new BigInteger("17");
         * BigInteger test2 = new BigInteger("20"); = result 1
         * BigInteger test = gcd_method(test2, test1);
         * System.out.println(test);
         * 
         */

        /*
         * Testing if multiplicative inverse method works
         *
         * BigInteger test1 = new BigInteger("3");
         * BigInteger test2 = new BigInteger("11"); result = 4
         * BigInteger result = mod_inverse(test1, test2);
         * System.out.println(result);
         *
         */

        BigInteger d = mod_inverse(e, totient_result);

        System.out.printf("d: %x\n", d);
        File input_file = new File(args[0]);
        
        try {
            byte[] file_as_bytes = Files.readAllBytes(input_file.toPath());
            byte[] message_digest = digest_method(file_as_bytes);
            BigInteger digest = new BigInteger(message_digest);
            BigInteger result = decryption_method(digest, d, prime1, prime2, n);
            assert result.equals(digest.modPow(d, n));
            assert result.modPow(e, n).equals(digest.mod(n));
            System.out.print(result.toString(16));
        } catch (IOException | NoSuchAlgorithmException err) {
            err.printStackTrace();
        }

        
          //Testing modular exponentiation method works
          
         /*  BigInteger test1 = new BigInteger("5");
          BigInteger test2 = new BigInteger("3");
          BigInteger test3 = new BigInteger("7");
          
          BigInteger result = mod_exp(test1, test2, test3);
          System.out.println(result);
         */

        /*
         * Testing if the method that can power a big integer to another big integer
         * works
         * 
         * BigInteger test1 = new BigInteger("2");
         * BigInteger test2 = new BigInteger("10"); // result 1024
         * BigInteger result = power_big_integers(test1, test2);
         * System.out.println(result);
         */
    }

    // function to get phi(n)
    public static BigInteger euler_totient(BigInteger prime1, BigInteger prime2) {
        BigInteger result = (prime1.subtract(BigInteger.ONE)).multiply(prime2.subtract(BigInteger.ONE));
        return result;
    }

    // function to check if e is relative prime to phi(n), alternatively could be
    // used to get the gcd between two numbers
    public static BigInteger gcd_method(BigInteger result, BigInteger e) {
        while (!e.equals(BigInteger.ZERO)) {
            BigInteger tmp = e;
            e = result.mod(e);
            result = tmp;
        }
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
        byte[] message_digest = digest.digest(input_file);
        return message_digest;
    }


    // method to power to big integers
    public static BigInteger power_big_integers(BigInteger base, BigInteger exponent) {
        return base.modPow(exponent, BigInteger.ONE.shiftLeft(1024));

    }

    // decryption method
    public static BigInteger decryption_method(BigInteger digest, BigInteger d, BigInteger p, BigInteger q,
            BigInteger n) {

        // Chinese Remainder Theorem
        BigInteger m1 = mod_inverse(p, q);
        assert m1.equals(p.modInverse(q));
        BigInteger m2 = mod_inverse(q, p);
        assert m2.equals(q.modInverse(p));

        BigInteger result = digest.modPow(d, q).multiply(m1).multiply(p)
                .add(digest.modPow(d, p).multiply(m2).multiply(q));

        return result.mod(n).mod(n);
    }

    // method to write n to a modulus.txt
    public static void write_to_a_file(String n, String file_path) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file_path))) {
            writer.write(n);
        } catch (IOException e) {
            System.err.println("Error writing String to file: " + e.getMessage());
        }
    }
}
