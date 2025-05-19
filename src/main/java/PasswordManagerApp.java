import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.Scanner;

public class PasswordManagerApp {

    public static void main(String[] args) {
        UserService userService = new UserService();
        PasswordManagerService passwordManagerService = new PasswordManagerService();
        PasswordGeneratorService passwordGeneratorService = new PasswordGeneratorService();

        try (Scanner scanner = new Scanner(System.in)) {
            boolean isLoggedIn = false;
            String currentUser = null;
            System.out.println("===================================");
            System.out.println("Welcome to Secure Password Manager");
            System.out.println("===================================");
            while (true) {
                if (!isLoggedIn) {
                    System.out.println("\nPlease choose an option:");
                    System.out.println("1. Login");
                    System.out.println("2. Register");
                    System.out.println("3. Exit");
                    System.out.print("Enter your choice: ");
                    String authChoice = scanner.nextLine();

                    switch (authChoice) {
                        case "1":
                            System.out.print("Enter username: ");
                            String username = scanner.nextLine();
                            System.out.print("Enter password: ");
                            String password = scanner.nextLine();

                            if (userService.login(username, password)) {
                                isLoggedIn = true;
                                currentUser = username;
                                passwordManagerService.loadUserData(username, password);
                                System.out.println("Login successful!");
                            } else {
                                System.out.println("Invalid username or password.");
                            }
                            break;
                        case "2":
                            System.out.print("Enter new username: ");
                            String newUsername = scanner.nextLine();
                            System.out.print("Enter new password: ");
                            String newPassword = scanner.nextLine();

                            if (userService.register(newUsername, newPassword)) {
                                System.out.println("Registration successful! Please login.");
                            } else {
                                System.out.println("Username already exists.");
                            }
                            break;
                        case "3":
                            System.out.println("Exiting application...");
                            return;
                        default:
                            System.out.println("Invalid choice. Please try again.");
                    }
                } else {
                    System.out.println("\nHello, " + currentUser + "! What would you like to do?");
                    System.out.println("1. Add new password entry");
                    System.out.println("2. Search for a password");
                    System.out.println("3. Update a password");
                    System.out.println("4. Delete a password entry");
                    System.out.println("5. Generate a strong password");
                    System.out.println("6. Logout");
                    System.out.print("Enter your choice: ");

                    String choice = scanner.nextLine();

                    switch (choice) {
                        case "1":
                            addNewPassword(scanner, passwordManagerService);
                            break;
                        case "2":
                            searchPassword(scanner, passwordManagerService);
                            break;
                        case "3":
                            updatePassword(scanner, passwordManagerService, passwordGeneratorService);
                            break;
                        case "4":
                            deletePassword(scanner, passwordManagerService);
                            break;
                        case "5":
                            generatePassword(scanner, passwordGeneratorService);
                            break;
                        case "6":
                            passwordManagerService.saveAndEncrypt();
                            isLoggedIn = false;
                            currentUser = null;
                            System.out.println("Logged out successfully.");
                            break;
                        default:
                            System.out.println("Invalid choice. Please try again.");
                    }
                }
            }
        }
    }

    private static void addNewPassword(Scanner scanner, PasswordManagerService passwordManagerService) {
        System.out.println("\n=== Add New Password ===");
        System.out.print("Enter title (e.g., 'Facebook'): ");
        String title = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        System.out.print("Enter URL or application name: ");
        String url = scanner.nextLine();
        System.out.print("Enter additional notes: ");
        String notes = scanner.nextLine();

        passwordManagerService.addPasswordEntry(title, password, url, notes);
        System.out.println("Password entry added successfully!");
    }

    private static void searchPassword(Scanner scanner, PasswordManagerService passwordManagerService) {
        System.out.println("\n=== Search Password ===");
        System.out.print("Enter title to search: ");
        String title = scanner.nextLine();

        PasswordEntry entry = passwordManagerService.findPasswordEntry(title);
        if (entry != null) {
            System.out.println("\nEntry found:");
            System.out.println("Title: " + entry.getTitle());
            System.out.println("URL/Application: " + entry.getUrl());
            System.out.println("Notes: " + entry.getNotes());
            System.out.println("\nOptions:");
            System.out.println("1. Show password");
            System.out.println("2. Copy password to clipboard");
            System.out.println("3. Return to main menu");
            System.out.print("Enter your choice: ");

            String choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    System.out.println("Password: " + passwordManagerService.decryptPassword(entry.getEncryptedPassword()));
                    break;
                case "2":
                    String decryptedPassword = passwordManagerService.decryptPassword(entry.getEncryptedPassword());
                    StringSelection stringSelection = new StringSelection(decryptedPassword);
                    Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                    clipboard.setContents(stringSelection, null);
                    System.out.println("Password copied to clipboard!");
                    break;
                case "3":
                    return;
                default:
                    System.out.println("Invalid choice.");
            }
        } else {
            System.out.println("No entry found with title: " + title);
        }
    }

    private static void updatePassword(Scanner scanner, PasswordManagerService passwordManagerService,
                                       PasswordGeneratorService passwordGeneratorService) {
        System.out.println("\n=== Update Password ===");
        System.out.print("Enter title of the entry to update: ");
        String title = scanner.nextLine();

        PasswordEntry entry = passwordManagerService.findPasswordEntry(title);
        if (entry != null) {
            System.out.println("\nCurrent entry details:");
            System.out.println("Title: " + entry.getTitle());
            System.out.println("URL/Application: " + entry.getUrl());
            System.out.println("Notes: " + entry.getNotes());

            System.out.println("\nUpdate password options:");
            System.out.println("1. Enter a new password manually");
            System.out.println("2. Generate a new password");
            System.out.print("Enter your choice: ");

            String choice = scanner.nextLine();
            String newPassword = "";

            switch (choice) {
                case "1":
                    System.out.print("Enter new password: ");
                    newPassword = scanner.nextLine();
                    break;
                case "2":
                    newPassword = generatePassword(scanner, passwordGeneratorService);
                    break;
                default:
                    System.out.println("Invalid choice. Returning to main menu.");
                    return;
            }

            System.out.print("Update URL? (y/n): ");
            String updateUrl = scanner.nextLine();
            String newUrl = entry.getUrl();
            if (updateUrl.equalsIgnoreCase("y")) {
                System.out.print("Enter new URL: ");
                newUrl = scanner.nextLine();
            }

            System.out.print("Update notes? (y/n): ");
            String updateNotes = scanner.nextLine();
            String newNotes = entry.getNotes();
            if (updateNotes.equalsIgnoreCase("y")) {
                System.out.print("Enter new notes: ");
                newNotes = scanner.nextLine();
            }

            passwordManagerService.updatePasswordEntry(title, newPassword, newUrl, newNotes);
            System.out.println("Password entry updated successfully!");
        } else {
            System.out.println("No entry found with title: " + title);
        }
    }

    private static void deletePassword(Scanner scanner, PasswordManagerService passwordManagerService) {
        System.out.println("\n=== Delete Password ===");
        System.out.print("Enter title of the entry to delete: ");
        String title = scanner.nextLine();

        if (passwordManagerService.deletePasswordEntry(title)) {
            System.out.println("Password entry deleted successfully!");
        } else {
            System.out.println("No entry found with title: " + title);
        }
    }

    private static String generatePassword(Scanner scanner, PasswordGeneratorService passwordGeneratorService) {
        System.out.println("\n=== Password Generator ===");
        System.out.print("Enter password length (8-50): ");
        int length;
        try {
            length = Integer.parseInt(scanner.nextLine());
            if (length < 8 || length > 50) {
                System.out.println("Invalid length. Using default length of 16.");
                length = 16;
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid input. Using default length of 16.");
            length = 16;
        }

        System.out.print("Include uppercase letters? (y/n): ");
        boolean useUppercase = scanner.nextLine().equalsIgnoreCase("y");

        System.out.print("Include lowercase letters? (y/n): ");
        boolean useLowercase = scanner.nextLine().equalsIgnoreCase("y");

        System.out.print("Include numbers? (y/n): ");
        boolean useNumbers = scanner.nextLine().equalsIgnoreCase("y");

        System.out.print("Include special characters? (y/n): ");
        boolean useSpecial = scanner.nextLine().equalsIgnoreCase("y");

        String generatedPassword = passwordGeneratorService.generatePassword(length, useUppercase,
                useLowercase, useNumbers, useSpecial);
        System.out.println("Generated password: " + generatedPassword);

        System.out.print("Copy to clipboard? (y/n): ");
        if (scanner.nextLine().equalsIgnoreCase("y")) {
            StringSelection stringSelection = new StringSelection(generatedPassword);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
            System.out.println("Password copied to clipboard!");
        }

        return generatedPassword;
    }
}
