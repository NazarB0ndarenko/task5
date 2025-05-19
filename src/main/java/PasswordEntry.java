import java.util.ArrayList;
import java.util.List;

public class PasswordEntry {
    private String title;
    private String encryptedPassword;
    private String url;
    private String notes;


    public PasswordEntry(String title, String encryptedPassword, String url, String notes) {
        this.title = title;
        this.encryptedPassword = encryptedPassword;
        this.url = url;
        this.notes = notes;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    @Override
    public String toString() {
        return title + "," + encryptedPassword + "," + url + "," + notes;
    }

    public static PasswordEntry fromString(String line) {
        List<String> values = new ArrayList<>();
        StringBuilder currentValue = new StringBuilder();
        boolean inQuotes = false;

        for (char c : line.toCharArray()) {
            if (c == ',' && !inQuotes) {
                values.add(currentValue.toString());
                currentValue = new StringBuilder();
            } else if (c == '"') {
                inQuotes = !inQuotes;
                currentValue.append(c);
            } else {
                currentValue.append(c);
            }
        }
        values.add(currentValue.toString());

        if (values.size() < 4) {
            throw new IllegalArgumentException("Invalid password entry format: " + line);
        }

        return new PasswordEntry(values.get(0), values.get(1), values.get(2), values.get(3));
    }
}