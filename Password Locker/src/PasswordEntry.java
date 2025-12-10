import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.UUID;

/**
 * PasswordEntry Model Class
 * Represents a single password entry with metadata
 */
public class PasswordEntry implements Serializable, Comparable<PasswordEntry> {
    private static final long serialVersionUID = 1L;

    private String id;
    private String website;
    private String username;
    private String encryptedPassword;
    private String category;
    private String notes;
    private LocalDateTime createdDate;
    private LocalDateTime lastModified;
    private LocalDateTime lastAccessed;

    /**
     * Constructor for new password entry
     */
    public PasswordEntry(String website, String username, String encryptedPassword, String category, String notes) {
        this.id = UUID.randomUUID().toString();
        this.createdDate = LocalDateTime.now();
        this.lastModified = LocalDateTime.now();
        this.lastAccessed = LocalDateTime.now();
        setWebsite(website);
        setUsername(username);
        setEncryptedPassword(encryptedPassword);
        setCategory(category);
        setNotes(notes);
    }

    /**
     * Constructor for loading from file
     */
    public PasswordEntry(String id, String website, String username, String encryptedPassword,
                         String category, String notes, String created, String modified, String accessed) {
        this.id = id;
        this.website = website;
        this.username = username;
        this.encryptedPassword = encryptedPassword;
        this.category = category;
        this.notes = notes;

        DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
        this.createdDate = LocalDateTime.parse(created, formatter);
        this.lastModified = LocalDateTime.parse(modified, formatter);
        this.lastAccessed = LocalDateTime.parse(accessed, formatter);
    }

    // Getters
    public String getId() {
        return id;
    }

    public String getWebsite() {
        return website;
    }

    public String getUsername() {
        return username;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public String getCategory() {
        return category;
    }

    public String getNotes() {
        return notes;
    }

    public LocalDateTime getCreatedDate() {
        return createdDate;
    }

    public LocalDateTime getLastModified() {
        return lastModified;
    }

    public LocalDateTime getLastAccessed() {
        return lastAccessed;
    }

    // Setters with validation
    public void setWebsite(String website) {
        if (website == null || website.trim().isEmpty()) {
            throw new IllegalArgumentException("Website name cannot be empty");
        }
        this.website = website.trim();
    }

    public void setUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        this.username = username.trim();
    }

    public void setEncryptedPassword(String encryptedPassword) {
        if (encryptedPassword == null || encryptedPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
        this.encryptedPassword = encryptedPassword;
    }

    public void setCategory(String category) {
        this.category = (category == null || category.trim().isEmpty()) ? "General" : category.trim();
    }

    public void setNotes(String notes) {
        this.notes = (notes == null) ? "" : notes.trim();
    }

    /**
     * Update last modified timestamp
     */
    public void updateLastModified() {
        this.lastModified = LocalDateTime.now();
    }

    /**
     * Update last accessed timestamp
     */
    public void updateLastAccessed() {
        this.lastAccessed = LocalDateTime.now();
    }

    /**
     * Convert to file format
     */
    public String toFileFormat() {
        DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
        return String.format("%s|%s|%s|%s|%s|%s|%s|%s|%s",
                id,
                website,
                username,
                encryptedPassword,
                category,
                notes.replace("|", "⎮"), // Replace pipe with similar character to avoid conflicts
                createdDate.format(formatter),
                lastModified.format(formatter),
                lastAccessed.format(formatter)
        );
    }

    /**
     * Create entry from file format
     */
    public static PasswordEntry fromFileFormat(String line) {
        if (line == null || line.trim().isEmpty()) {
            throw new IllegalArgumentException("Invalid file line");
        }

        String[] parts = line.split("\\|", -1); // -1 to keep empty strings
        if (parts.length != 9) {
            throw new IllegalArgumentException("Invalid file format - expected 9 fields, got " + parts.length);
        }

        return new PasswordEntry(
                parts[0], // id
                parts[1], // website
                parts[2], // username
                parts[3], // encryptedPassword
                parts[4], // category
                parts[5].replace("⎮", "|"), // notes
                parts[6], // created
                parts[7], // modified
                parts[8]  // accessed
        );
    }

    /**
     * Get display string without encrypted password
     */
    public String getDisplayInfo() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
        return String.format("Website: %s\nUsername: %s\nCategory: %s\nCreated: %s\nLast Modified: %s\nNotes: %s",
                website, username, category, createdDate.format(formatter), lastModified.format(formatter),
                notes.isEmpty() ? "None" : notes);
    }

    /**
     * Get compact display for lists
     */
    public String getCompactDisplay() {
        return String.format("%s - %s (%s)", website, username, category);
    }

    @Override
    public String toString() {
        return getCompactDisplay();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        PasswordEntry entry = (PasswordEntry) obj;
        return Objects.equals(id, entry.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public int compareTo(PasswordEntry other) {
        int websiteCompare = this.website.compareToIgnoreCase(other.website);
        if (websiteCompare != 0) {
            return websiteCompare;
        }
        return this.username.compareToIgnoreCase(other.username);
    }
}