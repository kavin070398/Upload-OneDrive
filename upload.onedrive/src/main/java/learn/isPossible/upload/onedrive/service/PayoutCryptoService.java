package learn.isPossible.upload.onedrive.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Enhanced PayoutCryptoService with multiple operation modes
 * <p>
 * Supported Operations:
 * 1. Encrypt only (no compression)
 * 2. Encrypt with compression
 * 3. Decrypt only (no decompression)
 * 4. Decrypt with decompression
 * 5. Support multiple encryption keys
 * 6. Key generation and validation
 */
@Slf4j
//@Component
public class PayoutCryptoService {

        private static final ThreadLocal<Cipher> encCipher = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance(CryptoConstants.CIPHER_ALGORITHM);
        } catch (Exception e) {
            log.error("Failed to initialize encryption cipher", e);
            throw new RuntimeException("Failed to initialize encryption cipher", e);
        }
    });

    private static final ThreadLocal<Cipher> decCipher = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance(CryptoConstants.CIPHER_ALGORITHM);
        } catch (Exception e) {
            log.error("Failed to initialize decryption cipher", e);
            throw new RuntimeException("Failed to initialize decryption cipher", e);
        }
    });

    private static final SecureRandom secureRandom = new SecureRandom();

    // Primary encryption key (default)
    private final String primaryKey;

    // Secondary/backup keys for key rotation scenarios
    private final java.util.Map<String, String> keyRegistry;

    /**
     * Initialize with primary key only
     */
    public PayoutCryptoService(String primaryKey) {
        this(primaryKey, null);
        log.debug("Initializing PayoutCryptoService with primary key only");
    }

    /**
     * Initialize with primary key and additional keys (for key rotation)
     *
     * @param primaryKey     Base64-encoded primary encryption key
     * @param additionalKeys Map of keyId -> Base64-encoded key
     */
    public PayoutCryptoService(String primaryKey, java.util.Map<String, String> additionalKeys) {
        log.debug("Initializing PayoutCryptoService with primary key and additional keys");
        if (primaryKey == null || primaryKey.trim().isEmpty()) {
            log.error("Primary encryption key cannot be null or empty");
            throw new IllegalArgumentException("Primary encryption key cannot be null or empty");
        }

        validateKeyFormat(primaryKey);

        this.primaryKey = primaryKey;
        this.keyRegistry = new java.util.HashMap<>();

        if (additionalKeys != null && !additionalKeys.isEmpty()) {
            additionalKeys.forEach((keyId, key) -> {
                validateKeyFormat(key);
                this.keyRegistry.put(keyId, key);
            });
        }
    }

    // ** KEY GENERATION & MANAGEMENT **

    /**
     * Generate a new AES-256 encryption key
     * Run this ONCE during deployment setup
     * <p>
     * Output format: Base64-encoded 32-byte key
     * Store in secure vault: AWS Secrets Manager, HashiCorp Vault, etc.
     *
     * @return Base64-encoded encryption key
     * @throws Exception if key generation fails
     */
    public static String generateNewKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(CryptoConstants.KEY_ALGORITHM);
        keyGen.init(CryptoConstants.KEY_SIZE);
        SecretKey key = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Generate multiple keys for key rotation strategy
     *
     * @param count Number of keys to generate
     * @return Map of keyId -> Base64-encoded keys
     * @throws Exception if key generation fails
     */
    public static java.util.Map<String, String> generateMultipleKeys(int count) throws Exception {
        java.util.Map<String, String> keys = new java.util.LinkedHashMap<>();
        for (int i = 1; i <= count; i++) {
            String keyId = "KEY_" + System.currentTimeMillis() + "_" + i;
            keys.put(keyId, generateNewKey());
        }
        return keys;
    }

    /**
     * Validate key format and length
     *
     * @param key Base64-encoded key
     * @throws IllegalArgumentException if key is invalid
     */
    private static void validateKeyFormat(String key) {
        if (key == null || key.trim().isEmpty()) {
            log.error("Encryption key cannot be null or empty");
            throw new IllegalArgumentException("Encryption key cannot be null or empty");
        }

        try {
            byte[] decodedKey = Base64.getDecoder().decode(key);
            if (decodedKey.length != CryptoConstants.EXPECTED_KEY_BYTE_LENGTH) {
                throw new IllegalArgumentException(
                        String.format("Key must be %d bytes (256-bit), got: %d bytes",
                                CryptoConstants.EXPECTED_KEY_BYTE_LENGTH, decodedKey.length)
                );
            }
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid Base64 key format: " + e.getMessage());
        }
    }

    // ** COMPRESSION UTILITIES **

    /**
     * Fast compression using DEFLATE algorithm
     * Reduces payload size by 40-60% for typical JSON data
     */
    private static byte[] fastCompress(byte[] data) throws Exception {
        if (data == null || data.length == 0) {
            return new byte[0];
        }

        byte[] buffer = new byte[CryptoConstants.BUFFER_SIZE];
        ByteArrayOutputStream output = new ByteArrayOutputStream(data.length / 2);

        Deflater deflater = new Deflater(CryptoConstants.COMPRESSION_LEVEL);
        try {
            deflater.setInput(data);
            deflater.finish();

            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                if (count > 0) {
                    output.write(buffer, 0, count);
                }
            }
            return output.toByteArray();
        } finally {
            deflater.end();  // Manually release resources
        }
    }

    /**
     * Fast decompression using INFLATE algorithm
     */
    private static byte[] fastDecompress(byte[] data) throws Exception {
        if (data == null || data.length == 0) {
            return new byte[0];
        }

        byte[] buffer = new byte[CryptoConstants.BUFFER_SIZE];
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        // For decompression
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(data);

            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count > 0) {
                    output.write(buffer, 0, count);
                }
            }
            return output.toByteArray();
        } finally {
            inflater.end();  // Manually release resources
        }
    }

    // ** ENCRYPTION OPERATIONS **

    /**
     * MODE 1: Simple Encryption (no compression)
     * Best for: Already compressed data, small payloads, raw performance
     *
     * @param plainText Data to encrypt
     * @return Encrypted format: "BASE64_IV.BASE64_CIPHERTEXT"
     * @throws Exception on encryption failure
     */
    public String encrypt(String plainText) throws Exception {
        return encryptWithKey(plainText, primaryKey);
    }

    /**
     * MODE 1: Simple Encryption with specific key
     *
     * @param plainText Data to encrypt
     * @param keyId     Key identifier from key registry
     * @return Encrypted format: "BASE64_IV.BASE64_CIPHERTEXT"
     * @throws Exception on encryption failure
     */
    public String encryptWithKeyId(String plainText, String keyId) throws Exception {
        String key = keyRegistry.get(keyId);
        if (key == null) {
            throw new IllegalArgumentException("Key not found for keyId: " + keyId);
        }
        return encryptWithKey(plainText, key);
    }

    /**
     * MODE 1: Internal - Simple encryption with explicit key
     */
    private String encryptWithKey(String plainText, String key) throws Exception {
        if (plainText == null || plainText.isEmpty()) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty");
        }

        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

        // Generate random IV
        byte[] iv = new byte[CryptoConstants.IV_SIZE];
        secureRandom.nextBytes(iv);

        // Encrypt
        Cipher cipher = encCipher.get();
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, CryptoConstants.KEY_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(CryptoConstants.TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
        byte[] encrypted = cipher.doFinal(plainBytes);

        // Return compact format
        return Base64.getEncoder().encodeToString(iv) + CryptoConstants.DATA_SEPARATOR +
                Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * MODE 2: Encryption with Compression
     * Best for: Large JSON payloads, network optimization, bandwidth-sensitive scenarios
     * <p>
     * Typical compression: JSON 1KB → 400-600 bytes (40-60% reduction)
     *
     * @param plainText Data to compress and encrypt
     * @return Encrypted format: "BASE64_IV.BASE64_CIPHERTEXT" (of compressed data)
     * @throws Exception on compression/encryption failure
     */
    public String compressAndEncrypt(String plainText) throws Exception {
        return compressAndEncryptWithKey(plainText, primaryKey);
    }

    /**
     * MODE 2: Encryption with Compression and specific key
     *
     * @param plainText Data to compress and encrypt
     * @param keyId     Key identifier from key registry
     * @return Encrypted format: "BASE64_IV.BASE64_CIPHERTEXT"
     * @throws Exception on compression/encryption failure
     */
    public String compressAndEncryptWithKeyId(String plainText, String keyId) throws Exception {
        String key = keyRegistry.get(keyId);
        if (key == null) {
            throw new IllegalArgumentException("Key not found for keyId: " + keyId);
        }
        return compressAndEncryptWithKey(plainText, key);
    }

    /**
     * MODE 2: Internal - Compression + encryption with explicit key
     */
    public String compressAndEncryptWithKey(String plainText, String key) throws Exception {
        if (plainText == null || plainText.isEmpty()) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty");
        }

        byte[] keyBytes = Base64.getDecoder().decode(key);

        // Step 1: Compress
        byte[] compressed = fastCompress(plainText.getBytes(StandardCharsets.UTF_8));

        // Step 2: Generate random IV
        byte[] iv = new byte[CryptoConstants.IV_SIZE];
        secureRandom.nextBytes(iv);

        // Step 3: Encrypt compressed data
        Cipher cipher = encCipher.get();
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, CryptoConstants.KEY_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(CryptoConstants.TAG_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
        byte[] encrypted = cipher.doFinal(compressed);

        // Return compact format
        return Base64.getEncoder().encodeToString(iv) + CryptoConstants.DATA_SEPARATOR +
                Base64.getEncoder().encodeToString(encrypted);
    }

    // ** DECRYPTION OPERATIONS **

    /**
     * MODE 3: Simple Decryption (no decompression)
     * Best for: Already decompressed data, raw performance
     *
     * @param encrypted Encrypted format: "BASE64_IV.BASE64_CIPHERTEXT"
     * @return Decrypted plaintext
     * @throws Exception on decryption failure or tampering detection
     */
    public String decrypt(String encrypted) throws Exception {
        return decryptWithKey(encrypted, primaryKey);
    }

    /**
     * MODE 3: Simple Decryption with specific key
     *
     * @param encrypted Encrypted format: "BASE64_IV.BASE64_CIPHERTEXT"
     * @param keyId     Key identifier from key registry
     * @return Decrypted plaintext
     * @throws Exception on decryption failure
     */
    public String decryptWithKeyId(String encrypted, String keyId) throws Exception {
        String key = keyRegistry.get(keyId);
        if (key == null) {
            throw new IllegalArgumentException("Key not found for keyId: " + keyId);
        }
        return decryptWithKey(encrypted, key);
    }

    /**
     * MODE 3: Internal - Simple decryption with explicit key
     */
    private String decryptWithKey(String encrypted, String key) throws Exception {
        if (encrypted == null || encrypted.isEmpty()) {
            throw new IllegalArgumentException("Encrypted data cannot be null or empty");
        }

        String[] parts = encrypted.split("\\.", -1);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid encrypted format. Expected: IV.CIPHERTEXT");
        }

        try {
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] cipherBytes = Base64.getDecoder().decode(parts[1]);
            byte[] keyBytes = Base64.getDecoder().decode(key);

            // Decrypt
            Cipher cipher = decCipher.get();
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, CryptoConstants.KEY_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(CryptoConstants.TAG_LENGTH, iv);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
            byte[] plainBytes = cipher.doFinal(cipherBytes);

            return new String(plainBytes, StandardCharsets.UTF_8);

        } catch (javax.crypto.AEADBadTagException e) {
            throw new SecurityException("Authentication tag validation failed - data may be tampered", e);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Base64 decoding failed - invalid encrypted format", e);
        }
    }

    /**
     * MODE 4: Decryption with Decompression
     * Best for: Compressed encrypted payloads that need full recovery
     *
     * @param encrypted Encrypted format: "BASE64_IV.BASE64_CIPHERTEXT" (of compressed data)
     * @return Decrypted and decompressed plaintext
     * @throws Exception on decryption/decompression failure
     */
    public String decryptAndDecompress(String encrypted) throws Exception {
        return decryptAndDecompressWithKey(encrypted, primaryKey);
    }

    /**
     * MODE 4: Decryption with Decompression and specific key
     *
     * @param encrypted Encrypted format: "BASE64_IV.BASE64_CIPHERTEXT"
     * @param keyId     Key identifier from key registry
     * @return Decrypted and decompressed plaintext
     * @throws Exception on decryption/decompression failure
     */
    public String decryptAndDecompressWithKeyId(String encrypted, String keyId) throws Exception {
        String key = keyRegistry.get(keyId);
        if (key == null) {
            throw new IllegalArgumentException("Key not found for keyId: " + keyId);
        }
        return decryptAndDecompressWithKey(encrypted, key);
    }

    /**
     * MODE 4: Internal - Decryption + decompression with explicit key
     */
    public String decryptAndDecompressWithKey(String encrypted, String key) throws Exception {
        if (encrypted == null || encrypted.isEmpty()) {
            throw new IllegalArgumentException("Encrypted data cannot be null or empty");
        }

        String[] parts = encrypted.split("\\.", -1);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid encrypted format. Expected: IV.CIPHERTEXT");
        }

        try {
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] cipherBytes = Base64.getDecoder().decode(parts[1]);
            byte[] keyBytes = Base64.getDecoder().decode(key);

            // Decrypt
            Cipher cipher = decCipher.get();
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, CryptoConstants.KEY_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(CryptoConstants.TAG_LENGTH, iv);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
            byte[] compressedBytes = cipher.doFinal(cipherBytes);

            // Decompress
            byte[] plainBytes = fastDecompress(compressedBytes);

            return new String(plainBytes, StandardCharsets.UTF_8);

        } catch (javax.crypto.AEADBadTagException e) {
            throw new SecurityException("Authentication tag validation failed - data may be tampered", e);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Base64 decoding failed - invalid encrypted format", e);
        }
    }

    //** UTILITY METHODS **//

    /**
     * Extract IV from encrypted payload (for logging/audit purposes)
     */
    public static String extractIv(String encrypted) {
        String[] parts = encrypted.split("\\.", -1);
        return parts.length > 0 ? parts[0] : null;
    }

    /**
     * Check if payload is encrypted (has valid format)
     */
    public static boolean isValidEncryptedFormat(String data) {
        if (data == null || data.isEmpty()) return false;
        String[] parts = data.split("\\.", -1);
        return parts.length == 2 && !parts[0].isEmpty() && !parts[1].isEmpty();
    }
}