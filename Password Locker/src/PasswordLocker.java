import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import java.util.Set;

/**
 * Password Locker - Secure Password Management System
 * Features custom encryption, password generation, and secure storage
 */
public class PasswordLocker {

    private final PasswordRepository repository;
    private static final String APP_TITLE = "🔐 Password Locker";
    private static final int MAX_LOGIN_ATTEMPTS = 3;

    public PasswordLocker() {
        this.repository = new PasswordRepository();
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            // Use default look and feel
        }

        PasswordLocker locker = new PasswordLocker();
        locker.run();
    }

    public void run() {
        showWelcome();

        if (!repository.isMasterPasswordSet()) {
            if (!setupMasterPassword()) {
                return;
            }
        } else {
            if (!authenticate()) {
                return;
            }
        }

        mainMenu();
        showGoodbye();
    }

    private void showWelcome() {
        String message = "╔════════════════════════════════════════╗\n" +
                "║      🔐 PASSWORD LOCKER v1.0 🔐       ║\n" +
                "╚════════════════════════════════════════╝\n\n" +
                "Secure Password Management System\n" +
                "With Military-Grade Encryption\n\n" +
                "Features:\n" +
                "✓ Multi-layer Encryption\n" +
                "✓ Secure Password Generator\n" +
                "✓ Password Strength Analyzer\n" +
                "✓ Category Organization\n" +
                "✓ Encrypted File Storage";

        JOptionPane.showMessageDialog(null, message, APP_TITLE, JOptionPane.INFORMATION_MESSAGE);
    }

    private boolean setupMasterPassword() {
        String message = "╔════════════════════════════════════════╗\n" +
                "║         FIRST TIME SETUP               ║\n" +
                "╚════════════════════════════════════════╝\n\n" +
                "Create a strong master password.\n\n" +
                "Requirements:\n" +
                "• At least 8 characters long\n" +
                "• Mix of uppercase, lowercase, numbers\n" +
                "• Special characters recommended\n\n" +
                "⚠️  IMPORTANT: If you forget this password,\n" +
                "    your data CANNOT be recovered!";

        JOptionPane.showMessageDialog(null, message, APP_TITLE, JOptionPane.WARNING_MESSAGE);

        boolean validPassword = false;
        while (!validPassword) {
            JPasswordField passwordField = new JPasswordField();
            JPasswordField confirmField = new JPasswordField();

            Object[] fields = {
                    "Create Master Password:", passwordField,
                    "Confirm Password:", confirmField
            };

            int result = JOptionPane.showConfirmDialog(null, fields, "Setup Master Password",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE);

            if (result != JOptionPane.OK_OPTION) {
                return false;
            }

            String password = new String(passwordField.getPassword());
            String confirm = new String(confirmField.getPassword());

            try {
                if (!password.equals(confirm)) {
                    JOptionPane.showMessageDialog(null, "Passwords do not match!\n\nPlease try again.",
                            "Error", JOptionPane.ERROR_MESSAGE);
                    continue;
                }

                int strength = EncryptionService.calculatePasswordStrength(password);
                String strengthLabel = EncryptionService.getPasswordStrengthLabel(strength);

                if (strength < 50) {
                    int choice = JOptionPane.showConfirmDialog(null,
                            "Password Strength: " + strengthLabel + " (" + strength + "/100)\n\n" +
                                    "This password is weak. Continue anyway?",
                            "Weak Password Warning",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE);

                    if (choice != JOptionPane.YES_OPTION) {
                        continue;
                    }
                }

                repository.setupMasterPassword(password);

                JOptionPane.showMessageDialog(null,
                        "✓ Master password created successfully!\n\n" +
                                "Password Strength: " + strengthLabel + " (" + strength + "/100)\n\n" +
                                "Your vault is now ready to use.",
                        "Success", JOptionPane.INFORMATION_MESSAGE);

                validPassword = true;

            } catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(null, e.getMessage() + "\n\nPlease try again.",
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        return true;
    }

    private boolean authenticate() {
        int attempts = 0;

        while (attempts < MAX_LOGIN_ATTEMPTS) {
            JPasswordField passwordField = new JPasswordField();
            Object[] fields = {
                    "Enter Master Password:", passwordField
            };

            int result = JOptionPane.showConfirmDialog(null, fields, "Login - Attempt " + (attempts + 1) + "/" + MAX_LOGIN_ATTEMPTS,
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE);

            if (result != JOptionPane.OK_OPTION) {
                return false;
            }

            String password = new String(passwordField.getPassword());

            if (repository.verifyMasterPassword(password)) {
                JOptionPane.showMessageDialog(null, "✓ Login successful!\n\nWelcome back!",
                        "Success", JOptionPane.INFORMATION_MESSAGE);
                return true;
            } else {
                attempts++;
                int remaining = MAX_LOGIN_ATTEMPTS - attempts;

                if (remaining > 0) {
                    JOptionPane.showMessageDialog(null,
                            "✗ Incorrect password!\n\n" +
                                    "Attempts remaining: " + remaining,
                            "Authentication Failed", JOptionPane.ERROR_MESSAGE);
                }
            }
        }

        JOptionPane.showMessageDialog(null,
                "Maximum login attempts exceeded.\n\nApplication will now close.",
                "Access Denied", JOptionPane.ERROR_MESSAGE);

        return false;
    }

    private void mainMenu() {
        boolean running = true;

        while (running) {
            String choice = showMainMenu();

            if (choice == null) {
                running = confirmExit();
                continue;
            }

            try {
                switch (choice) {
                    case "1":
                        addPassword();
                        break;
                    case "2":
                        viewPasswords();
                        break;
                    case "3":
                        searchPassword();
                        break;
                    case "4":
                        updatePassword();
                        break;
                    case "5":
                        deletePassword();
                        break;
                    case "6":
                        generatePassword();
                        break;
                    case "7":
                        viewByCategory();
                        break;
                    case "8":
                        changeMasterPassword();
                        break;
                    case "9":
                        viewStatistics();
                        break;
                    case "10":
                        exportVault();
                        break;
                    case "11":
                        running = confirmExit();
                        break;
                    default:
                        JOptionPane.showMessageDialog(null, "Invalid choice. Please select 1-11.",
                                APP_TITLE, JOptionPane.WARNING_MESSAGE);
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(null, "Error: " + e.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String showMainMenu() {
        String menu = "╔════════════════════════════════════════╗\n" +
                "║         PASSWORD LOCKER MENU           ║\n" +
                "╚════════════════════════════════════════╝\n\n" +
                "1.  ➕ Add New Password\n" +
                "2.  📋 View All Passwords\n" +
                "3.  🔍 Search Password\n" +
                "4.  ✏️  Update Password\n" +
                "5.  🗑️  Delete Password\n" +
                "6.  🎲 Generate Strong Password\n" +
                "7.  📁 View by Category\n" +
                "8.  🔑 Change Master Password\n" +
                "9.  📊 View Statistics\n" +
                "10. 💾 Export Vault Backup\n" +
                "11. 🚪 Exit\n\n" +
                "Total Passwords: " + repository.getEntryCount();

        return JOptionPane.showInputDialog(null, menu, APP_TITLE, JOptionPane.PLAIN_MESSAGE);
    }

    private void addPassword() {
        JTextField websiteField = new JTextField();
        JTextField usernameField = new JTextField();
        JPasswordField passwordField = new JPasswordField();
        JTextField categoryField = new JTextField("General");
        JTextArea notesArea = new JTextArea(3, 20);
        notesArea.setLineWrap(true);
        JScrollPane notesScroll = new JScrollPane(notesArea);

        JButton generateBtn = new JButton("Generate Password");
        generateBtn.addActionListener(e -> {
            String generated = showPasswordGenerator();
            if (generated != null) {
                passwordField.setText(generated);
            }
        });

        Object[] fields = {
                "Website/App Name:", websiteField,
                "Username/Email:", usernameField,
                "Password:", passwordField,
                generateBtn,
                "Category:", categoryField,
                "Notes (Optional):", notesScroll
        };

        boolean validInput = false;
        while (!validInput) {
            int result = JOptionPane.showConfirmDialog(null, fields, "Add New Password",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE);

            if (result != JOptionPane.OK_OPTION) {
                return;
            }

            try {
                String website = websiteField.getText();
                String username = usernameField.getText();
                String password = new String(passwordField.getPassword());
                String category = categoryField.getText();
                String notes = notesArea.getText();

                if (password.isEmpty()) {
                    throw new IllegalArgumentException("Password cannot be empty");
                }

                int strength = EncryptionService.calculatePasswordStrength(password);
                String strengthLabel = EncryptionService.getPasswordStrengthLabel(strength);

                repository.addEntry(website, username, password, category, notes);

                JOptionPane.showMessageDialog(null,
                        "✓ Password saved successfully!\n\n" +
                                "Website: " + website + "\n" +
                                "Username: " + username + "\n" +
                                "Password Strength: " + strengthLabel + " (" + strength + "/100)\n" +
                                "Category: " + category,
                        "Success", JOptionPane.INFORMATION_MESSAGE);

                validInput = true;

            } catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(null, e.getMessage() + "\n\nPlease correct and try again.",
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void viewPasswords() {
        List<PasswordEntry> entries = repository.getSortedByWebsite();

        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(null, "No passwords saved yet.",
                    "Empty Vault", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String[] options = new String[entries.size()];
        for (int i = 0; i < entries.size(); i++) {
            options[i] = (i + 1) + ". " + entries.get(i).getCompactDisplay();
        }

        String selection = (String) JOptionPane.showInputDialog(null,
                "Select password to view details:\n\nTotal: " + entries.size() + " passwords",
                "All Passwords",
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]);

        if (selection != null) {
            int index = Integer.parseInt(selection.split("\\.")[0]) - 1;
            showPasswordDetails(entries.get(index));
        }
    }

    private void showPasswordDetails(PasswordEntry entry) {
        String decryptedPassword = repository.getDecryptedPassword(entry.getId());
        int strength = EncryptionService.calculatePasswordStrength(decryptedPassword);
        String strengthLabel = EncryptionService.getPasswordStrengthLabel(strength);

        String details = "═══════════════════════════════════════\n" +
                "         PASSWORD DETAILS\n" +
                "═══════════════════════════════════════\n\n" +
                entry.getDisplayInfo() + "\n\n" +
                "Password: " + maskPassword(decryptedPassword) + "\n" +
                "Password Strength: " + strengthLabel + " (" + strength + "/100)\n" +
                "\n═══════════════════════════════════════";

        String[] options = {"Show Password", "Copy to Clipboard", "Close"};
        int choice = JOptionPane.showOptionDialog(null, details, "Password Details",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                null, options, options[2]);

        if (choice == 0) {
            JOptionPane.showMessageDialog(null,
                    "Password: " + decryptedPassword + "\n\n⚠️ Make sure no one is watching!",
                    "Revealed Password", JOptionPane.INFORMATION_MESSAGE);
        } else if (choice == 1) {
            copyToClipboard(decryptedPassword);
            JOptionPane.showMessageDialog(null,
                    "✓ Password copied to clipboard!",
                    "Copied", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void searchPassword() {
        String query = JOptionPane.showInputDialog(null,
                "Enter search term (website, username, or category):",
                "Search Password",
                JOptionPane.QUESTION_MESSAGE);

        if (query != null && !query.trim().isEmpty()) {
            List<PasswordEntry> results = repository.searchEntries(query);

            if (results.isEmpty()) {
                JOptionPane.showMessageDialog(null,
                        "No passwords found matching: \"" + query + "\"",
                        "No Results", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            String[] options = new String[results.size()];
            for (int i = 0; i < results.size(); i++) {
                options[i] = (i + 1) + ". " + results.get(i).getCompactDisplay();
            }

            String selection = (String) JOptionPane.showInputDialog(null,
                    "Search Results for: \"" + query + "\"\n\nFound " + results.size() + " match(es):",
                    "Search Results",
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    options,
                    options[0]);

            if (selection != null) {
                int index = Integer.parseInt(selection.split("\\.")[0]) - 1;
                showPasswordDetails(results.get(index));
            }
        }
    }

    private void updatePassword() {
        List<PasswordEntry> entries = repository.getAllEntries();

        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(null, "No passwords to update.",
                    "Empty Vault", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String[] options = new String[entries.size()];
        for (int i = 0; i < entries.size(); i++) {
            options[i] = (i + 1) + ". " + entries.get(i).getCompactDisplay();
        }

        String selection = (String) JOptionPane.showInputDialog(null,
                "Select password to update:",
                "Update Password",
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]);

        if (selection == null) return;

        int index = Integer.parseInt(selection.split("\\.")[0]) - 1;
        PasswordEntry entry = entries.get(index);

        JTextField websiteField = new JTextField(entry.getWebsite());
        JTextField usernameField = new JTextField(entry.getUsername());
        JPasswordField passwordField = new JPasswordField();
        JTextField categoryField = new JTextField(entry.getCategory());
        JTextArea notesArea = new JTextArea(entry.getNotes(), 3, 20);
        notesArea.setLineWrap(true);
        JScrollPane notesScroll = new JScrollPane(notesArea);

        JButton generateBtn = new JButton("Generate New Password");
        generateBtn.addActionListener(e -> {
            String generated = showPasswordGenerator();
            if (generated != null) {
                passwordField.setText(generated);
            }
        });

        Object[] fields = {
                "Website/App Name:", websiteField,
                "Username/Email:", usernameField,
                "New Password (leave empty to keep current):", passwordField,
                generateBtn,
                "Category:", categoryField,
                "Notes:", notesScroll
        };

        boolean validInput = false;
        while (!validInput) {
            int result = JOptionPane.showConfirmDialog(null, fields, "Update Password",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE);

            if (result != JOptionPane.OK_OPTION) {
                return;
            }

            try {
                String website = websiteField.getText();
                String username = usernameField.getText();
                String password = new String(passwordField.getPassword());
                String category = categoryField.getText();
                String notes = notesArea.getText();

                repository.updateEntry(entry.getId(), website, username,
                        password.isEmpty() ? null : password, category, notes);

                JOptionPane.showMessageDialog(null, "✓ Password updated successfully!",
                        "Success", JOptionPane.INFORMATION_MESSAGE);
                validInput = true;

            } catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(null, e.getMessage() + "\n\nPlease correct and try again.",
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void deletePassword() {
        List<PasswordEntry> entries = repository.getAllEntries();

        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(null, "No passwords to delete.",
                    "Empty Vault", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String[] options = new String[entries.size()];
        for (int i = 0; i < entries.size(); i++) {
            options[i] = (i + 1) + ". " + entries.get(i).getCompactDisplay();
        }

        String selection = (String) JOptionPane.showInputDialog(null,
                "Select password to delete:",
                "Delete Password",
                JOptionPane.WARNING_MESSAGE,
                null,
                options,
                options[0]);

        if (selection == null) return;

        int index = Integer.parseInt(selection.split("\\.")[0]) - 1;
        PasswordEntry entry = entries.get(index);

        int confirm = JOptionPane.showConfirmDialog(null,
                "Are you sure you want to delete this password?\n\n" +
                        entry.getCompactDisplay() + "\n\n" +
                        "⚠️ This action cannot be undone!",
                "Confirm Deletion",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            repository.deleteEntry(entry.getId());
            JOptionPane.showMessageDialog(null, "✓ Password deleted successfully!",
                    "Success", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private String showPasswordGenerator() {
        JSpinner lengthSpinner = new JSpinner(new SpinnerNumberModel(16, 8, 64, 1));
        JCheckBox upperCase = new JCheckBox("Uppercase (A-Z)", true);
        JCheckBox lowerCase = new JCheckBox("Lowercase (a-z)", true);
        JCheckBox numbers = new JCheckBox("Numbers (0-9)", true);
        JCheckBox symbols = new JCheckBox("Symbols (!@#$%)", true);

        Object[] fields = {
                "Password Length:", lengthSpinner,
                upperCase,
                lowerCase,
                numbers,
                symbols
        };

        int result = JOptionPane.showConfirmDialog(null, fields, "Password Generator",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            try {
                int length = (int) lengthSpinner.getValue();
                String generated = EncryptionService.generatePassword(
                        length,
                        upperCase.isSelected(),
                        lowerCase.isSelected(),
                        numbers.isSelected(),
                        symbols.isSelected()
                );

                int strength = EncryptionService.calculatePasswordStrength(generated);
                String strengthLabel = EncryptionService.getPasswordStrengthLabel(strength);

                String message = "Generated Password:\n\n" + generated + "\n\n" +
                        "Strength: " + strengthLabel + " (" + strength + "/100)";

                String[] opts = {"Use This Password", "Generate Another", "Cancel"};
                int choice = JOptionPane.showOptionDialog(null, message, "Generated Password",
                        JOptionPane.DEFAULT_OPTION,
                        JOptionPane.INFORMATION_MESSAGE,
                        null, opts, opts[0]);

                if (choice == 0) {
                    return generated;
                } else if (choice == 1) {
                    return showPasswordGenerator();
                }

            } catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(null, e.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }

        return null;
    }

    private void generatePassword() {
        String generated = showPasswordGenerator();
        if (generated != null) {
            copyToClipboard(generated);
            JOptionPane.showMessageDialog(null,
                    "✓ Password generated and copied to clipboard!\n\n" +
                            "Password: " + generated,
                    "Success", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void viewByCategory() {
        Set<String> categories = repository.getAllCategories();

        if (categories.isEmpty()) {
            JOptionPane.showMessageDialog(null, "No categories available.",
                    "Empty Vault", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String[] options = categories.toArray(new String[0]);
        String selected = (String) JOptionPane.showInputDialog(null,
                "Select a category:",
                "View by Category",
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]);

        if (selected != null) {
            List<PasswordEntry> entries = repository.getEntriesByCategory(selected);

            String[] entryOptions = new String[entries.size()];
            for (int i = 0; i < entries.size(); i++) {
                entryOptions[i] = (i + 1) + ". " + entries.get(i).getCompactDisplay();
            }

            String selection = (String) JOptionPane.showInputDialog(null,
                    "Category: " + selected + "\n\nFound " + entries.size() + " password(s):",
                    "Category: " + selected,
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    entryOptions,
                    entryOptions[0]);

            if (selection != null) {
                int index = Integer.parseInt(selection.split("\\.")[0]) - 1;
                showPasswordDetails(entries.get(index));
            }
        }
    }

    private void changeMasterPassword() {
        JPasswordField oldPasswordField = new JPasswordField();
        JPasswordField newPasswordField = new JPasswordField();
        JPasswordField confirmField = new JPasswordField();

        Object[] fields = {
                "Current Master Password:", oldPasswordField,
                "New Master Password:", newPasswordField,
                "Confirm New Password:", confirmField
        };

        boolean validInput = false;
        while (!validInput) {
            int result = JOptionPane.showConfirmDialog(null, fields, "Change Master Password",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.WARNING_MESSAGE);

            if (result != JOptionPane.OK_OPTION) {
                return;
            }

            try {
                String oldPassword = new String(oldPasswordField.getPassword());
                String newPassword = new String(newPasswordField.getPassword());
                String confirm = new String(confirmField.getPassword());

                if (!newPassword.equals(confirm)) {
                    throw new IllegalArgumentException("New passwords do not match");
                }

                repository.changeMasterPassword(oldPassword, newPassword);

                JOptionPane.showMessageDialog(null,
                        "✓ Master password changed successfully!\n\n" +
                                "All passwords have been re-encrypted.",
                        "Success", JOptionPane.INFORMATION_MESSAGE);

                validInput = true;

            } catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(null, e.getMessage() + "\n\nPlease try again.",
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void viewStatistics() {
        var stats = repository.getStatistics();

        String message = "╔════════════════════════════════════════╗\n" +
                "║         VAULT STATISTICS               ║\n" +
                "╚════════════════════════════════════════╝\n\n" +
                "Total Passwords: " + stats.get("totalEntries") + "\n" +
                "Categories: " + stats.get("categories") + "\n" +
                "Last Backup: " + stats.get("lastBackup") + "\n\n" +
                "Encryption: Multi-Layer\n" +
                "File: vault.enc\n" +
                "Backup: vault_backup.enc";

        JOptionPane.showMessageDialog(null, message, "Statistics",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void exportVault() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Vault Backup");
        fileChooser.setSelectedFile(new java.io.File("vault_backup_" + System.currentTimeMillis() + ".enc"));

        int result = fileChooser.showSaveDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                repository.exportVault(fileChooser.getSelectedFile().getAbsolutePath());
                JOptionPane.showMessageDialog(null,
                        "✓ Vault exported successfully!\n\n" +
                                "Location: " + fileChooser.getSelectedFile().getAbsolutePath(),
                        "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(null, "Export failed: " + e.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String maskPassword(String password) {
        return "●".repeat(password.length());
    }

    private void copyToClipboard(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }

    private boolean confirmExit() {
        int confirm = JOptionPane.showConfirmDialog(null,
                "Are you sure you want to exit?\n\nAll passwords are safely encrypted.",
                "Confirm Exit",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        return confirm != JOptionPane.YES_OPTION;
    }

    private void showGoodbye() {
        JOptionPane.showMessageDialog(null,
                "Thank you for using Password Locker!\n\n" +
                        "Your passwords are safe and encrypted.\n" +
                        "Stay secure! 🔐",
                APP_TITLE,
                JOptionPane.INFORMATION_MESSAGE);
    }
}