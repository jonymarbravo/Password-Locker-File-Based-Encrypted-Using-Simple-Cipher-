import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Repository class for managing password data persistence
 * Handles encrypted file I/O operations
 */
public class PasswordRepository {

    private static final String VAULT_FILE = "vault.enc";
    private static final String BACKUP_FILE = "vault_backup.enc";
    private static final String MASTER_HASH_FILE = ".master.hash";
    private static final String CONFIG_FILE = ".config";

    private final Path vaultPath;
    private final Path backupPath;
    private final Path masterHashPath;
    private final Path configPath;

    private List<PasswordEntry> entries;
    private String masterPassword;

    public PasswordRepository() {
        this.vaultPath = Paths.get(VAULT_FILE);
        this.backupPath = Paths.get(BACKUP_FILE);
        this.masterHashPath = Paths.get(MASTER_HASH_FILE);
        this.configPath = Paths.get(CONFIG_FILE);
        this.entries = new ArrayList<>();
    }

    /**
     * Check if master password is set up
     */
    public boolean isMasterPasswordSet() {
        return Files.exists(masterHashPath);
    }

    /**
     * Set up initial master password
     */
    public boolean setupMasterPassword(String password) {
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Master password cannot be empty");
        }

        if (password.length() < 8) {
            throw new IllegalArgumentException("Master password must be at least 8 characters long");
        }

        try {
            String hashedPassword = EncryptionService.hashMasterPassword(password);
            Files.write(masterHashPath, hashedPassword.getBytes(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);

            // Set file as hidden
            try {
                Files.setAttribute(masterHashPath, "dos:hidden", true);
            } catch (Exception e) {
                // Ignore if not on Windows
            }

            this.masterPassword = password;

            // Create empty vault file
            saveVault();

            // Save initial config
            saveConfig();

            return true;
        } catch (IOException e) {
            throw new RuntimeException("Failed to save master password: " + e.getMessage(), e);
        }
    }

    /**
     * Verify master password
     */
    public boolean verifyMasterPassword(String password) {
        if (!Files.exists(masterHashPath)) {
            throw new IllegalStateException("Master password not set up");
        }

        try {
            String storedHash = new String(Files.readAllBytes(masterHashPath));
            String inputHash = EncryptionService.hashMasterPassword(password);

            if (storedHash.equals(inputHash)) {
                this.masterPassword = password;
                loadVault();
                return true;
            }
            return false;
        } catch (IOException e) {
            throw new RuntimeException("Failed to verify password: " + e.getMessage(), e);
        }
    }

    /**
     * Change master password
     */
    public boolean changeMasterPassword(String oldPassword, String newPassword) {
        if (!verifyMasterPassword(oldPassword)) {
            throw new IllegalArgumentException("Current password is incorrect");
        }

        if (newPassword == null || newPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("New password cannot be empty");
        }

        if (newPassword.length() < 8) {
            throw new IllegalArgumentException("New password must be at least 8 characters long");
        }

        try {
            // Re-encrypt all passwords with new master password
            List<PasswordEntry> decryptedEntries = new ArrayList<>();
            for (PasswordEntry entry : entries) {
                String decryptedPassword = EncryptionService.decrypt(entry.getEncryptedPassword(), masterPassword);
                String reencryptedPassword = EncryptionService.encrypt(decryptedPassword, newPassword);

                PasswordEntry newEntry = new PasswordEntry(
                        entry.getWebsite(),
                        entry.getUsername(),
                        reencryptedPassword,
                        entry.getCategory(),
                        entry.getNotes()
                );
                decryptedEntries.add(newEntry);
            }

            // Update master password
            this.masterPassword = newPassword;
            this.entries = decryptedEntries;

            // Save new hash
            String newHash = EncryptionService.hashMasterPassword(newPassword);
            Files.write(masterHashPath, newHash.getBytes(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);

            // Save re-encrypted vault
            saveVault();

            return true;
        } catch (Exception e) {
            throw new RuntimeException("Failed to change master password: " + e.getMessage(), e);
        }
    }

    /**
     * Load vault from encrypted file
     */
    private void loadVault() {
        if (!Files.exists(vaultPath)) {
            System.out.println("No vault file found. Starting with empty vault.");
            return;
        }

        try (BufferedReader reader = Files.newBufferedReader(vaultPath)) {
            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();

                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                try {
                    // Decrypt the line first
                    String decryptedLine = EncryptionService.decrypt(line, masterPassword);
                    PasswordEntry entry = PasswordEntry.fromFileFormat(decryptedLine);
                    entries.add(entry);
                } catch (Exception e) {
                    System.err.println("Error loading entry at line " + lineNumber + ": " + e.getMessage());
                }
            }

            System.out.println("Loaded " + entries.size() + " password entries.");
        } catch (IOException e) {
            throw new RuntimeException("Failed to load vault: " + e.getMessage(), e);
        }
    }

    /**
     * Save vault to encrypted file
     */
    private boolean saveVault() {
        try {
            // Create backup
            if (Files.exists(vaultPath)) {
                Files.copy(vaultPath, backupPath, StandardCopyOption.REPLACE_EXISTING);
            }

            // Write encrypted vault
            try (BufferedWriter writer = Files.newBufferedWriter(vaultPath,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {

                writer.write("# Password Vault - Encrypted\n");
                writer.write("# Last updated: " + new Date() + "\n");

                for (PasswordEntry entry : entries) {
                    // Encrypt the entire line
                    String line = entry.toFileFormat();
                    String encryptedLine = EncryptionService.encrypt(line, masterPassword);
                    writer.write(encryptedLine);
                    writer.newLine();
                }
            }

            return true;
        } catch (IOException e) {
            throw new RuntimeException("Failed to save vault: " + e.getMessage(), e);
        }
    }

    /**
     * Add a new password entry
     */
    public boolean addEntry(String website, String username, String plainPassword, String category, String notes) {
        if (masterPassword == null) {
            throw new IllegalStateException("Not authenticated");
        }

        // Check for duplicate
        boolean exists = entries.stream()
                .anyMatch(e -> e.getWebsite().equalsIgnoreCase(website) &&
                        e.getUsername().equalsIgnoreCase(username));

        if (exists) {
            throw new IllegalArgumentException("Entry already exists for " + website + " with username " + username);
        }

        // Encrypt password
        String encryptedPassword = EncryptionService.encrypt(plainPassword, masterPassword);

        // Create entry
        PasswordEntry entry = new PasswordEntry(website, username, encryptedPassword, category, notes);
        entries.add(entry);

        return saveVault();
    }

    /**
     * Update an existing entry
     */
    public boolean updateEntry(String id, String website, String username, String plainPassword,
                               String category, String notes) {
        if (masterPassword == null) {
            throw new IllegalStateException("Not authenticated");
        }

        PasswordEntry entry = findById(id);
        if (entry == null) {
            return false;
        }

        entry.setWebsite(website);
        entry.setUsername(username);

        if (plainPassword != null && !plainPassword.isEmpty()) {
            String encryptedPassword = EncryptionService.encrypt(plainPassword, masterPassword);
            entry.setEncryptedPassword(encryptedPassword);
        }

        entry.setCategory(category);
        entry.setNotes(notes);
        entry.updateLastModified();

        return saveVault();
    }

    /**
     * Delete an entry
     */
    public boolean deleteEntry(String id) {
        boolean removed = entries.removeIf(e -> e.getId().equals(id));
        if (removed) {
            saveVault();
        }
        return removed;
    }

    /**
     * Find entry by ID
     */
    public PasswordEntry findById(String id) {
        return entries.stream()
                .filter(e -> e.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    /**
     * Get decrypted password
     */
    public String getDecryptedPassword(String id) {
        if (masterPassword == null) {
            throw new IllegalStateException("Not authenticated");
        }

        PasswordEntry entry = findById(id);
        if (entry == null) {
            return null;
        }

        entry.updateLastAccessed();
        saveVault();

        return EncryptionService.decrypt(entry.getEncryptedPassword(), masterPassword);
    }

    /**
     * Search entries
     */
    public List<PasswordEntry> searchEntries(String query) {
        if (query == null || query.trim().isEmpty()) {
            return new ArrayList<>(entries);
        }

        String lowerQuery = query.toLowerCase();
        return entries.stream()
                .filter(e -> e.getWebsite().toLowerCase().contains(lowerQuery) ||
                        e.getUsername().toLowerCase().contains(lowerQuery) ||
                        e.getCategory().toLowerCase().contains(lowerQuery))
                .collect(Collectors.toList());
    }

    /**
     * Get all entries
     */
    public List<PasswordEntry> getAllEntries() {
        return new ArrayList<>(entries);
    }

    /**
     * Get entries sorted by website
     */
    public List<PasswordEntry> getSortedByWebsite() {
        List<PasswordEntry> sorted = new ArrayList<>(entries);
        Collections.sort(sorted);
        return sorted;
    }

    /**
     * Get entries by category
     */
    public List<PasswordEntry> getEntriesByCategory(String category) {
        return entries.stream()
                .filter(e -> e.getCategory().equalsIgnoreCase(category))
                .collect(Collectors.toList());
    }

    /**
     * Get all unique categories
     */
    public Set<String> getAllCategories() {
        return entries.stream()
                .map(PasswordEntry::getCategory)
                .collect(Collectors.toSet());
    }

    /**
     * Get vault statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalEntries", entries.size());
        stats.put("categories", getAllCategories().size());
        stats.put("lastBackup", Files.exists(backupPath) ? "Available" : "None");
        return stats;
    }

    /**
     * Save configuration
     */
    private void saveConfig() {
        try {
            Properties config = new Properties();
            config.setProperty("created", new Date().toString());
            config.setProperty("version", "1.0");

            try (FileOutputStream out = new FileOutputStream(configPath.toFile())) {
                config.store(out, "Password Locker Configuration");
            }

            // Hide config file
            try {
                Files.setAttribute(configPath, "dos:hidden", true);
            } catch (Exception e) {
                // Ignore if not on Windows
            }
        } catch (IOException e) {
            System.err.println("Warning: Could not save config: " + e.getMessage());
        }
    }

    /**
     * Export vault (for backup)
     */
    public boolean exportVault(String exportPath) {
        try {
            Files.copy(vaultPath, Paths.get(exportPath), StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException e) {
            throw new RuntimeException("Failed to export vault: " + e.getMessage(), e);
        }
    }

    /**
     * Get entry count
     */
    public int getEntryCount() {
        return entries.size();
    }
}