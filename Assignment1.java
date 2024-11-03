import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import java.util.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileInputStream;

class Assignment1 {
    public static void main(String args[]) {
        // File at argv 0
        File input_file = new File(args[0]);

        try {
            byte[] file_as_bytes = padding(input_file);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // randomly created secret key (1023 bits)
        Random rand = new Random();
        BigInteger my_secret_key = new BigInteger(1023, rand);

        // randomly created IV (128 bits)
        Random rand2 = new Random();
        BigInteger iv_value = new BigInteger(128, rand2);

        // output files
        String dh_file = "DH.txt";
        String iv_file = "IV.txt";

        BigInteger p_value = new BigInteger(
                "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323",
                16);
        BigInteger g_value = new BigInteger(
                "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68",
                16);
        BigInteger a_value = new BigInteger(
                "5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d",
                16);

        BigInteger public_key = mod_exp_method(g_value, p_value, my_secret_key);
        BigInteger shared_secret_key = mod_exp_method(a_value, p_value, my_secret_key);
        String aes_key = sha_method(shared_secret_key);

        // hexadecimal value representations that will be output to a file
        String hex_public_value = to_hex(public_key);
        String hex_iv_value = to_hex(iv_value);
        write_to_IV_file(iv_file, hex_iv_value);
        write_to_DH_file(dh_file, hex_public_value);
    }

    // modular exponentiation method, g_value being the base, p_value being modulus
    // value, and secret key being the powered by value
    public static BigInteger mod_exp_method(BigInteger g_value, BigInteger p_value, BigInteger secret_key) {
        BigInteger key = BigInteger.ONE;

        while (secret_key.compareTo(BigInteger.ZERO) > 0) {
            if (secret_key.and(BigInteger.ONE).equals(BigInteger.ONE)) {
                key = key.multiply(g_value).mod(p_value);
            }
            g_value = g_value.multiply(g_value).mod(p_value);
            secret_key = secret_key.shiftRight(1);
        }

        return key;
    }

    // method to produce 256-digest using the shared secret key
    public static String sha_method(BigInteger shared_secret_key) {
        try {

            // SHA-256 instance
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Converting the shared secret key to the 256-bit digest

            byte[] checker = shared_secret_key.toByteArray();

            byte first_byte = checker[0];

            // removing twos compliment by creating a new byte array and copying over the
            // original byte array minus the first byte
            byte[] new_checker = checker;
            if (first_byte == 0) {
                new_checker = new byte[checker.length - 1];
                System.arraycopy(checker, 1, new_checker, 0, new_checker.length);
            }

            byte[] encodedHash = digest.digest(new_checker);

            // Twos Compliment Testing
            // BigInteger bigInt2 = new BigInteger("128");
            // System.out.println(Arrays.toString(bigInt2.toByteArray()));
            // System.out.println(bigInt2.toByteArray()[0]);

            // Turning the produced hash into a hexdecimal string representation
            StringBuilder hexString = new StringBuilder();
            for (byte b : encodedHash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Couldn't create SHA-256 hash", e);
        }
    }

    // method that turns a big integer into a hexadecimal
    public static String to_hex(BigInteger value) {
        return value.toString(16);
    }

    //method that takes the randomly produced IV value and writes it to its specific file
    public static void write_to_IV_file(String iv_file, String hex_iv_value) {
        try (FileWriter writer = new FileWriter(iv_file)) {
            writer.write(hex_iv_value);
        } catch (IOException e) {
            System.out.println("Couldn't write to file.");
            e.printStackTrace();
        }
    }

    //method that takes the DH value and writes it to its specific file
    public static void write_to_DH_file(String dh_file, String hex_public_value) {
        try (FileWriter writer = new FileWriter(dh_file)) {
            writer.write(hex_public_value);
        } catch (IOException e) {
            System.out.println("Couldn't write to file.");
            e.printStackTrace();
        }
    }

    //method that adds padding
    public static byte[] padding(File input_file) throws IOException {
        if (!input_file.exists()) {
            throw new IOException("File isn't discoverable: " + input_file.getAbsolutePath());
        }

        try (FileInputStream fis = new FileInputStream(input_file)) {
            byte[] file_as_bytes = new byte[(int) input_file.length()];
            int bytes_read = fis.read(file_as_bytes);

            if (bytes_read != input_file.length()) {
                throw new IOException("Could not read the entire file: " + input_file.getAbsolutePath());
            }

            // perfectly fitted message
            if (file_as_bytes.length % 16 == 0) {
                byte[] padded_input = new byte[file_as_bytes.length + 16];

                // Copy the original array to the new array
                System.arraycopy(file_as_bytes, 0, padded_input, 0, file_as_bytes.length);

                // Added a byte starting with a 1 bit
                padded_input[file_as_bytes.length] = (byte) 0x80;

                return padded_input;
            }

            // message less than the block size
            else {
                int startOfLastBlock = (file_as_bytes.length / 16) * 16;

                if (startOfLastBlock >= file_as_bytes.length) {
                    startOfLastBlock = file_as_bytes.length - 16;
                }

                // First byte of the last block to 0x80
                if (startOfLastBlock < file_as_bytes.length) {
                    file_as_bytes[startOfLastBlock] = (byte) 0x80; // 0x80 is equivalent to 10000000 in binary
                }

                // Every other byte in the last block is set to hexadecimal zero (0x00)
                for (int i = startOfLastBlock + 1; i < file_as_bytes.length; i++) {
                    file_as_bytes[i] = (byte) 0x00;
                }
                return file_as_bytes;
            }
        }
    }
}