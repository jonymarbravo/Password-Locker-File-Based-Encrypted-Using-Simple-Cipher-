# 🔐 Password Locker

A secure, feature-rich password management system built with pure Java. Features custom multi-layer encryption, password generation, strength analysis, and encrypted file storage - all without external libraries.

## 📋 Table of Contents
- [Features](#features)
- [Security Architecture](#security-architecture)
- [Technologies Used](#technologies-used)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [Usage Guide](#usage-guide)
- [Project Structure](#project-structure)
- [Encryption Details](#encryption-details)
- [File Structure](#file-structure)
- [Contributing](#contributing)
- [Security Notice](#security-notice)
- [License](#license)

## ✨ Features

### Core Functionality
- 🔒 **Master Password Protection** - Single secure password protects all entries
- ➕ **Add Passwords** - Store credentials with website, username, password, category, and notes
- 👁️ **View Passwords** - Browse all passwords with masked display
- 🔍 **Search** - Find passwords by website, username, or category
- ✏️ **Update** - Modify existing password entries
- 🗑️ **Delete** - Remove entries with confirmation
- 📁 **Categories** - Organize passwords by category (Social, Banking, Email, etc.)

### Advanced Security Features
- 🔐 **Multi-Layer Encryption** - XOR + Caesar Cipher + Character Substitution + Base64
- 🎲 **Password Generator** - Create cryptographically secure random passwords (8-64 characters)
- 📊 **Password Strength Analyzer** - Real-time strength scoring (0-100)
- 🔑 **Master Password Change** - Re-encrypts all passwords with new master password
- 💾 **Automatic Backups** - Creates backup before every save operation
- 🔄 **Login Attempts Limit** - 3 failed attempts lock the application
- 📈 **Password Strength Requirements** - Enforces secure master password creation

### User Experience
- ✅ **Form Validation Loops** - Stay on form until input is correct
- 🎯 **Smart Error Messages** - Clear guidance on fixing validation errors
- 📋 **Copy to Clipboard** - One-click password copying
- 👁️‍🗨️ **Password Masking** - Secure display with reveal option
- 📊 **Statistics Dashboard** - View vault metrics
- 💾 **Export Functionality** - Backup vault to custom location
- 🕒 **Metadata Tracking** - Created, modified, and last accessed timestamps

## 🔒 Security Architecture

### Encryption Layers
The system implements a **4-layer encryption** approach:

1. **XOR Encryption** - Key derived from master password using SHA-256
2. **Caesar Cipher** - Character shifting with configurable offset
3. **Character Substitution** - Advanced substitution matrix
4. **Base64 Encoding** - Safe storage in text files

### Key Features
- **SHA-256 Hashing** - Master password never stored in plain text
- **Key Derivation** - Cryptographic key generation from master password
- **Salt Generation** - Random salts for additional security
- **Secure Random** - Cryptographically secure random number generation

## 🛠️ Technologies Used

- **Language**: Java (JDK 8 or higher)
- **GUI**: Java Swing (JOptionPane)
- **Encryption**: Custom implementation (no external libraries)
- **Security**: 
  - `java.security.MessageDigest` (SHA-256)
  - `java.security.SecureRandom` (Cryptographic RNG)
- **File I/O**: Java NIO (Path, Files)
- **Data Structures**: ArrayList, HashMap, Set
- **Architecture**: Repository Pattern with separation of concerns

## 💻 System Requirements

- **Java Development Kit (JDK)**: Version 8 or higher
- **IDE**: IntelliJ IDEA (recommended) or any Java IDE
- **Operating System**: Windows, macOS, or Linux
- **Memory**: Minimum 2GB RAM
- **Storage**: 10MB free space

## 📥 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/password-locker.git
   cd password-locker
   ```

2. **Open in IntelliJ IDEA**
   - Launch IntelliJ IDEA
   - Select `File > Open`
   - Navigate to the cloned project directory
   - Click `OK`

3. **Verify Project Structure**
   ```
   password-locker/
   ├── src/
   │   ├── PasswordEntry.java
   │   ├── EncryptionService.java
   │   ├── PasswordRepository.java
   │   └── PasswordLocker.java
   ├── vault.enc (auto-generated)
   ├── vault_backup.enc (auto-generated)
   ├── .master.hash (auto-generated, hidden)
   ├── .config (auto-generated, hidden)
   └── README.md
   ```

## 🚀 How to Run

### Using IntelliJ IDEA

1. Open the project in IntelliJ IDEA
2. Navigate to `src/PasswordLocker.java`
3. Right-click on the file and select `Run 'PasswordLocker.main()'`
4. Or click the green play button (▶️) next to the `main` method

### Using Command Line

```bash
# Navigate to src directory
cd src

# Compile all Java files
javac *.java

# Run the main class
java PasswordLocker
```

## 📖 Usage Guide

### First-Time Setup

1. **Create Master Password**
   - On first launch, you'll be prompted to create a master password
   - Requirements:
     - Minimum 8 characters
     - Mix of uppercase, lowercase, numbers recommended
     - Special characters encouraged
   - **IMPORTANT**: If you forget this password, your data CANNOT be recovered!

2. **Password Strength Check**
   - System shows strength score (0-100)
   - Warns if password is weak
   - Recommends improvements

### Adding a Password

1. Select option `1` from the main menu
2. Fill in the fields:
   - **Website/App Name**: e.g., "Gmail", "Facebook", "Banking"
   - **Username/Email**: Your login username or email
   - **Password**: Your password (or use generator)
   - **Category**: e.g., "Email", "Social", "Banking", "Work"
   - **Notes**: Optional additional information
3. Use "Generate Password" button for strong passwords
4. System shows password strength before saving

### Viewing Passwords

1. Select option `2` from the main menu
2. Select a password from the list
3. View masked password and details
4. Options:
   - **Show Password**: Reveals the actual password
   - **Copy to Clipboard**: Copies password for easy pasting
   - **Close**: Returns to list

### Searching

1. Select option `3` from the main menu
2. Enter search term (works for website, username, or category)
3. View matching results
4. Select entry to view details

### Updating a Password

1. Select option `4` from the main menu
2. Choose the password to update
3. Modify any fields (leave password empty to keep current)
4. Use generator for new strong password if needed
5. Changes are encrypted and saved immediately

### Deleting a Password

1. Select option `5` from the main menu
2. Choose the password to delete
3. Confirm deletion
4. **Warning**: This action cannot be undone!

### Password Generator

1. Select option `6` from main menu (or use button in Add/Update)
2. Configure options:
   - **Length**: 8-64 characters
   - **Uppercase**: A-Z
   - **Lowercase**: a-z
   - **Numbers**: 0-9
   - **Symbols**: !@#$%^&*()_+-=[]{}|;:,.<>?
3. View generated password with strength score
4. Options:
   - Use the password
   - Generate another
   - Cancel

### View by Category

1. Select option `7` from the main menu
2. Choose a category
3. View all passwords in that category
4. Select entry for full details

### Change Master Password

1. Select option `8` from the main menu
2. Enter current master password
3. Enter new master password
4. Confirm new password
5. **All passwords are automatically re-encrypted** with new master password

### Statistics

1. Select option `9` from the main menu
2. View:
   - Total number of passwords
   - Number of categories
   - Backup status
   - Encryption method

### Export Vault

1. Select option `10` from the main menu
2. Choose export location
3. Encrypted vault file is copied to chosen location
4. Use for backup or transfer to another machine

## 📁 Project Structure

### PasswordEntry.java
- **Purpose**: Model class representing a password entry
- **Responsibilities**:
  - Store password metadata (website, username, category, notes)
  - Track timestamps (created, modified, accessed)
  - Generate unique IDs
  - File format conversion
  - Sorting and comparison

### EncryptionService.java
- **Purpose**: Custom encryption engine
- **Responsibilities**:
  - Multi-layer encryption/decryption
  - Master password hashing (SHA-256)
  - Key derivation
  - Password generation
  - Password strength calculation
  - Secure random number generation

### PasswordRepository.java
- **Purpose**: Data persistence layer
- **Responsibilities**:
  - Master password management
  - Encrypted file I/O
  - CRUD operations (Create, Read, Update, Delete)
  - Search and filter
  - Automatic backups
  - Category management
  - Statistics generation

### PasswordLocker.java
- **Purpose**: Main application with user interface
- **Responsibilities**:
  - JOptionPane-based UI
  - Authentication flow
  - Menu navigation
  - Form validation loops
  - User interaction handling
  - Clipboard operations

## 🔐 Encryption Details

### Master Password Hashing
```java
SHA-256(masterPassword) → Stored in .master.hash
```
- Master password is NEVER stored in plain text
- Only cryptographic hash is stored
- Verification by comparing hashes

### Password Encryption Flow
```
PlainPassword 
  → XOR with derived key
  → Caesar cipher shift
  → Character substitution
  → Base64 encoding
  → Stored in vault.enc
```

### Key Derivation
```java
SHA-256(masterPassword) → 256-bit encryption key
```
- Consistent key generation from master password
- Used for XOR encryption layer
- Changes when master password changes

### Password Strength Algorithm
```
Score = Length Score (max 30)
      + Uppercase Bonus (15)
      + Lowercase Bonus (15)
      + Numbers Bonus (15)
      + Symbols Bonus (25)
= Total (max 100)
```

## 📂 File Structure

### vault.enc
- **Purpose**: Main encrypted password database
- **Format**: Encrypted lines, each containing one password entry
- **Encryption**: Each line is individually encrypted
- **Backup**: Automatically backed up before every save

### vault_backup.enc
- **Purpose**: Automatic backup of vault
- **Created**: Before every save operation
- **Use**: Recovery in case of corruption

### .master.hash (Hidden)
- **Purpose**: Stores SHA-256 hash of master password
- **Security**: Only hash stored, never plain password
- **Location**: Hidden file in application directory

### .config (Hidden)
- **Purpose**: Application configuration
- **Contains**: Creation date, version info
- **Location**: Hidden file in application directory

## 🎯 Why This Project Impresses Companies

### Demonstrates Security Knowledge
- ✅ Understanding of encryption principles
- ✅ Multi-layer security approach
- ✅ Proper password hashing (SHA-256)
- ✅ Secure random number generation
- ✅ Key derivation techniques

### Shows Programming Mastery
- ✅ Pure Java implementation (no external libraries)
- ✅ Clean architecture (Repository pattern)
- ✅ Proper exception handling
- ✅ Input validation
- ✅ File I/O management

### Professional Development Practices
- ✅ Comprehensive documentation
- ✅ Clear code organization
- ✅ User experience focus
- ✅ Error prevention
- ✅ Data backup strategies

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⚠️ Security Notice

**Important Notes:**
- This is an educational project demonstrating encryption principles
- For production use, consider established libraries like Bouncy Castle or Java Cryptography Extension (JCE)
- The multi-layer custom encryption provides good security for personal use
- Always use strong master passwords
- Keep backups of your vault file
- Never share your master password

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Jony Mar Barrete**
- GitHub: [@jonymarbravo](https://github.com/jonymarbravo)
- Email: jonymarbarrete88@gmail.com

## 🙏 Acknowledgments

- Built to demonstrate Java security principles
- Inspired by password managers like LastPass, 1Password, and Bitwarden
- Created for educational and portfolio purposes

## 📞 Support

For support, email jonymarbarrete88@gmail.com or open an issue in the GitHub repository.

---

⭐ **If you find this project helpful, please give it a star!** ⭐

## 🔒 Stay Secure!

Remember:
- Use unique passwords for each account
- Enable two-factor authentication when available
- Regularly update your passwords
- Never share your master password
- Keep your vault backed up

---

**Made with ❤️ and ☕ by [Jony Mar Barrete](https://github.com/jonymarbravo)**
