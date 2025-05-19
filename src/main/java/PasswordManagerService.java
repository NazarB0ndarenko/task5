import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManagerService {
    private List<PasswordEntry> passwordEntries = new ArrayList<>();
    private String currentUsername;
    private String masterPassword;

    public void loadUserData(String username, String password) {
        this.currentUsername = username;
        this.masterPassword = password;

        File file = new File(username + ".txt");
        if (file.exists() && file.length() > 0) {
            try {
                String decryptedContent = decryptFile(file, password);
                loadEntriesFromContent(decryptedContent);
            } catch (Exception e) {
                System.err.println("Error loading user data: " + e.getMessage());
                passwordEntries = new ArrayList<>();
            }
        } else {
            passwordEntries = new ArrayList<>();
        }
    }

    public void saveAndEncrypt() {
        if (currentUsername == null || passwordEntries == null) {
            return;
        }

        try {
            StringBuilder content = new StringBuilder();
            for (PasswordEntry entry : passwordEntries) {
                content.append(entry.toString()).append("\n");
            }

            encryptAndSaveFile(content.toString(), currentUsername + ".txt", masterPassword);
        } catch (Exception e) {
            System.err.println("Error saving and encrypting data: " + e.getMessage());
        }
    }

    public void addPasswordEntry(String title, String password, String url, String notes) {
        String encryptedPassword = encryptPassword(password);

        PasswordEntry entry = new PasswordEntry(title, encryptedPassword, url, notes);

        passwordEntries.add(entry);

        saveAndEncrypt();
    }

    public PasswordEntry findPasswordEntry(String title) {
        return passwordEntries.stream()
                .filter(entry -> entry.getTitle().equalsIgnoreCase(title))
                .findFirst()
                .orElse(null);
    }

    public void updatePasswordEntry(String title, String newPassword, String newUrl, String newNotes) {
        PasswordEntry entry = findPasswordEntry(title);
        if (entry != null) {
            entry.setEncryptedPassword(encryptPassword(newPassword));
            entry.setUrl(newUrl);
            entry.setNotes(newNotes);
            saveAndEncrypt();
        }
    }

    public boolean deletePasswordEntry(String title) {
        PasswordEntry entry = findPasswordEntry(title);
        if (entry != null) {
            passwordEntries.remove(entry);
            saveAndEncrypt();
            return true;
        }
        return false;
    }

    public String decryptPassword(String encryptedPassword) {
        try {
            SecretKeySpec keySpec = generateKey(masterPassword);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            String[] parts = encryptedPassword.split(":");
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] ciphertext = Base64.getDecoder().decode(parts[1]);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

            byte[] decryptedBytes = cipher.doFinal(ciphertext);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("Error decrypting password: " + e.getMessage());
            return "[Decryption Error]";
        }
    }

    private String encryptPassword(String password) {
        try {
            SecretKeySpec keySpec = generateKey(masterPassword);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            AlgorithmParameters params = cipher.getParameters();

            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

            byte[] ciphertext = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ciphertext);
        } catch (Exception e) {
            System.err.println("Error encrypting password: " + e.getMessage());
            return "[Encryption Error]";
        }
    }

    private SecretKeySpec generateKey(String password) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] key = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(key, "AES");
    }

    private void loadEntriesFromContent(String content) {
        passwordEntries.clear();
        String[] lines = content.split("\n");
        for (String line : lines) {
            if (!line.trim().isEmpty()) {
                try {
                    passwordEntries.add(PasswordEntry.fromString(line));
                } catch (Exception e) {
                    System.err.println("Error parsing entry: " + e.getMessage());
                }
            }
        }
    }

    private String decryptFile(File file, String password) throws Exception {
        byte[] encryptedData = Files.readAllBytes(file.toPath());

        byte[] iv = Arrays.copyOfRange(encryptedData, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, 16, encryptedData.length);

        SecretKeySpec keySpec = generateKey(password);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

        byte[] decryptedData = cipher.doFinal(ciphertext);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    private void encryptAndSaveFile(String content, String filename, String password) throws Exception {
        SecretKeySpec keySpec = generateKey(password);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();

        byte[] encryptedData = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));

        byte[] dataToSave = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, dataToSave, 0, iv.length);
        System.arraycopy(encryptedData, 0, dataToSave, iv.length, encryptedData.length);

        Files.write(Paths.get(filename), dataToSave);
    }
}