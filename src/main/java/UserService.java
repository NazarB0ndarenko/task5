import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class UserService {
    private static final String USERS_FILE = "users.txt";
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    public UserService() {
        try {
            File file = new File(USERS_FILE);
            if (!file.exists()) {
                file.createNewFile();
            }
        } catch (IOException e) {
            System.err.println("Error creating users file: " + e.getMessage());
        }
    }

    public boolean register(String username, String password) {
        if (userExists(username)) {
            return false;
        }

        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            String hashedPassword = hashPassword(password, salt);

            try (BufferedWriter writer = new BufferedWriter(new FileWriter(USERS_FILE, true))) {
                writer.write(username + ":" + Base64.getEncoder().encodeToString(salt) + ":" + hashedPassword);
                writer.newLine();
            }

            File userFile = new File(username + ".txt");
            if (!userFile.exists()) {
                userFile.createNewFile();
            }

            return true;
        } catch (Exception e) {
            System.err.println("Error registering user: " + e.getMessage());
            return false;
        }
    }

    public boolean login(String username, String password) {
        try {
            if (!userExists(username)) {
                return false;
            }

            List<String> lines = Files.readAllLines(Paths.get(USERS_FILE));
            for (String line : lines) {
                String[] parts = line.split(":");
                if (parts.length == 3 && parts[0].equals(username)) {
                    byte[] salt = Base64.getDecoder().decode(parts[1]);
                    String hashedPassword = hashPassword(password, salt);
                    return hashedPassword.equals(parts[2]);
                }
            }

            return false;
        } catch (Exception e) {
            System.err.println("Error during login: " + e.getMessage());
            return false;
        }
    }

    private boolean userExists(String username) {
        try {
            List<String> lines = Files.readAllLines(Paths.get(USERS_FILE));
            for (String line : lines) {
                String[] parts = line.split(":");
                if (parts.length > 0 && parts[0].equals(username)) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    private String hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
        byte[] hash = factory.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(hash);
    }
}