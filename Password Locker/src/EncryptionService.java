import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Custom Encryption Service
 * Implements layered encryption: XOR + Caesar Cipher + Base64 + Key Derivation
 * Demonstrates understanding of encryption principles without external libraries
 */
public class EncryptionService {

    private static final int CAESAR_SHIFT = 13;
    private static final String SALT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final int SALT_LENGTH = 16;

    /**
     * Generate a cryptographic hash of the master password
     * Uses SHA-256 for secure password verification
     */
    public static String hashMasterPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Derive an encryption key from the master password
     * Creates a consistent key for encryption/decryption
     */
    public static byte[] deriveKey(String masterPassword) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(masterPassword.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Multi-layer encryption: XOR + Caesar + Substitution + Base64
     */
    public static String encrypt(String plaintext, String masterPassword) {
        if (plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("Cannot encrypt empty text");
        }
        if (masterPassword == null || masterPassword.isEmpty()) {
            throw new IllegalArgumentException("Master password required for encryption");
        }

        try {
            // Layer 1: XOR with derived key
            byte[] key = deriveKey(masterPassword);
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] xorResult = xorEncrypt(plaintextBytes, key);

            // Layer 2: Caesar cipher
            String caesarResult = caesarCipher(Base64.getEncoder().encodeToString(xorResult), CAESAR_SHIFT);

            // Layer 3: Character substitution
            String substituted = substituteEncrypt(caesarResult);

            // Layer 4: Base64 encoding for safe storage
            return Base64.getEncoder().encodeToString(substituted.getBytes(StandardCharsets.UTF_8));

        } catch (Exception e) {
            throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Multi-layer decryption: Base64 + Substitution + Caesar + XOR
     */
    public static String decrypt(String encrypted, String masterPassword) {
        if (encrypted == null || encrypted.isEmpty()) {
            throw new IllegalArgumentException("Cannot decrypt empty text");
        }
        if (masterPassword == null || masterPassword.isEmpty()) {
            throw new IllegalArgumentException("Master password required for decryption");
        }

        try {
            // Layer 4: Base64 decoding
            byte[] decodedBytes = Base64.getDecoder().decode(encrypted);
            String substituted = new String(decodedBytes, StandardCharsets.UTF_8);

            // Layer 3: Reverse character substitution
            String caesarResult = substituteDecrypt(substituted);

            // Layer 2: Reverse Caesar cipher
            String base64XorResult = caesarCipher(caesarResult, -CAESAR_SHIFT);

            // Layer 1: Reverse XOR
            byte[] key = deriveKey(masterPassword);
            byte[] xorEncrypted = Base64.getDecoder().decode(base64XorResult);
            byte[] plaintext = xorEncrypt(xorEncrypted, key); // XOR is reversible

            return new String(plaintext, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new RuntimeException("Decryption failed - password may be incorrect", e);
        }
    }

    /**
     * XOR encryption/decryption (reversible operation)
     */
    private static byte[] xorEncrypt(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    /**
     * Caesar cipher encryption (shift characters)
     */
    private static String caesarCipher(String text, int shift) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isUpperCase(c)) {
                result.append((char) ((c - 'A' + shift + 26) % 26 + 'A'));
            } else if (Character.isLowerCase(c)) {
                result.append((char) ((c - 'a' + shift + 26) % 26 + 'a'));
            } else if (Character.isDigit(c)) {
                result.append((char) ((c - '0' + shift + 10) % 10 + '0'));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Character substitution encryption
     */
    private static String substituteEncrypt(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            // Simple substitution: shift by position in extended ASCII
            int shifted = ((int) c + 7) % 256;
            result.append((char) shifted);
        }
        return result.toString();
    }

    /**
     * Character substitution decryption
     */
    private static String substituteDecrypt(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            // Reverse substitution
            int shifted = ((int) c - 7 + 256) % 256;
            result.append((char) shifted);
        }
        return result.toString();
    }

    /**
     * Generate a cryptographically secure random password
     */
    public static String generatePassword(int length, boolean includeUppercase, boolean includeLowercase,
                                          boolean includeNumbers, boolean includeSymbols) {
        if (length < 4) {
            throw new IllegalArgumentException("Password length must be at least 4 characters");
        }

        if (!includeUppercase && !includeLowercase && !includeNumbers && !includeSymbols) {
            throw new IllegalArgumentException("At least one character type must be selected");
        }

        StringBuilder charset = new StringBuilder();
        if (includeUppercase) charset.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        if (includeLowercase) charset.append("abcdefghijklmnopqrstuvwxyz");
        if (includeNumbers) charset.append("0123456789");
        if (includeSymbols) charset.append("!@#$%^&*()_+-=[]{}|;:,.<>?");

        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);

        // Ensure at least one character from each selected type
        if (includeUppercase) password.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ".charAt(random.nextInt(26)));
        if (includeLowercase) password.append("abcdefghijklmnopqrstuvwxyz".charAt(random.nextInt(26)));
        if (includeNumbers) password.append("0123456789".charAt(random.nextInt(10)));
        if (includeSymbols) password.append("!@#$%^&*()_+-=[]{}|;:,.<>?".charAt(random.nextInt(28)));

        // Fill remaining length with random characters
        while (password.length() < length) {
            int index = random.nextInt(charset.length());
            password.append(charset.charAt(index));
        }

        // Shuffle the password to avoid predictable patterns
        return shuffleString(password.toString(), random);
    }

    /**
     * Shuffle string characters randomly
     */
    private static String shuffleString(String str, SecureRandom random) {
        char[] chars = str.toCharArray();
        for (int i = chars.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char temp = chars[i];
            chars[i] = chars[j];
            chars[j] = temp;
        }
        return new String(chars);
    }

    /**
     * Generate a random salt for additional security
     */
    public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        StringBuilder salt = new StringBuilder(SALT_LENGTH);
        for (int i = 0; i < SALT_LENGTH; i++) {
            salt.append(SALT_CHARS.charAt(random.nextInt(SALT_CHARS.length())));
        }
        return salt.toString();
    }

    /**
     * Calculate password strength score (0-100)
     */
    public static int calculatePasswordStrength(String password) {
        if (password == null || password.isEmpty()) {
            return 0;
        }

        int score = 0;

        // Length score (max 30 points)
        score += Math.min(password.length() * 2, 30);

        // Complexity score
        boolean hasUpper = password.matches(".*[A-Z].*");
        boolean hasLower = password.matches(".*[a-z].*");
        boolean hasDigit = password.matches(".*\\d.*");
        boolean hasSymbol = password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{}|;:,.<>?].*");

        if (hasUpper) score += 15;
        if (hasLower) score += 15;
        if (hasDigit) score += 15;
        if (hasSymbol) score += 25;

        return Math.min(score, 100);
    }

    /**
     * Get password strength label
     */
    public static String getPasswordStrengthLabel(int strength) {
        if (strength < 30) return "Very Weak";
        if (strength < 50) return "Weak";
        if (strength < 70) return "Moderate";
        if (strength < 85) return "Strong";
        return "Very Strong";
    }
}