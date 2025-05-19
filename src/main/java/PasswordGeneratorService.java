import java.security.SecureRandom;

public class PasswordGeneratorService {
    private static final String LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String NUMBER_CHARS = "0123456789";
    private static final String SPECIAL_CHARS = "!@#$%^&*()_-+=<>?/{}[]|";

    public String generatePassword(int length, boolean useUppercase, boolean useLowercase,
                                   boolean useNumbers, boolean useSpecial) {
        if (!useUppercase && !useLowercase && !useNumbers && !useSpecial) {
            useLowercase = true;
        }

        StringBuilder charPool = new StringBuilder();
        if (useLowercase) charPool.append(LOWERCASE_CHARS);
        if (useUppercase) charPool.append(UPPERCASE_CHARS);
        if (useNumbers) charPool.append(NUMBER_CHARS);
        if (useSpecial) charPool.append(SPECIAL_CHARS);

        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);

        if (useLowercase) password.append(LOWERCASE_CHARS.charAt(random.nextInt(LOWERCASE_CHARS.length())));
        if (useUppercase) password.append(UPPERCASE_CHARS.charAt(random.nextInt(UPPERCASE_CHARS.length())));
        if (useNumbers) password.append(NUMBER_CHARS.charAt(random.nextInt(NUMBER_CHARS.length())));
        if (useSpecial) password.append(SPECIAL_CHARS.charAt(random.nextInt(SPECIAL_CHARS.length())));

        for (int i = password.length(); i < length; i++) {
            int randomIndex = random.nextInt(charPool.length());
            password.append(charPool.charAt(randomIndex));
        }

        char[] passwordArray = password.toString().toCharArray();
        for (int i = 0; i < passwordArray.length; i++) {
            int randomIndex = random.nextInt(passwordArray.length);
            char temp = passwordArray[i];
            passwordArray[i] = passwordArray[randomIndex];
            passwordArray[randomIndex] = temp;
        }

        return new String(passwordArray);
    }
}