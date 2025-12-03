package learn.isPossible.upload.onedrive.service;

import java.util.Map;

class PayoutCryptoServiceExample {

    public static void main(String[] args) throws Exception {

        // ========== KEY GENERATION ==========
        System.out.println("1. KEY GENERATION");
        System.out.println("================\n");

        String primaryKey = PayoutCryptoService.generateNewKey();
        System.out.println("Primary Key (store in vault):\n" + primaryKey + "\n");

        // Generate multiple keys for rotation
        Map<String, String> additionalKeys = PayoutCryptoService.generateMultipleKeys(2);
        System.out.println("Additional Keys for rotation:");
        additionalKeys.forEach((id, key) -> System.out.println("  " + id + ": " + key.substring(0, 20) + "...\n"));

        // ========== INITIALIZE SERVICE ==========
        System.out.println("\n2. SERVICE INITIALIZATION");
        System.out.println("==========================\n");

        PayoutCryptoService crypto = new PayoutCryptoService(primaryKey, additionalKeys);

        String payoutJson = """
                {
                    "id": "payout_12345",
                    "amount": 1500.75,
                    "recipient": "user@example.com",
                    "status": "pending"
                }
                """;

        // ========== MODE 1: Simple Encryption ==========
        System.out.println("\n3. MODE 1: Simple Encryption (No Compression)");
        System.out.println("==============================================\n");

        String encrypted = crypto.encrypt(payoutJson);
        System.out.println("Encrypted (primary key):\n" + encrypted + "\n");
        System.out.println("IV: " + PayoutCryptoService.extractIv(encrypted) + "\n");

        String decrypted = crypto.decrypt(encrypted);
        System.out.println("Decrypted:\n" + decrypted + "\n");

        // ========== MODE 2: Compression + Encryption ==========
        System.out.println("\n4. MODE 2: Compression + Encryption");
        System.out.println("====================================\n");

        String compressedEncrypted = crypto.compressAndEncrypt(payoutJson);
        System.out.println("Compressed + Encrypted:\n" + compressedEncrypted + "\n");

        String decompressed = crypto.decryptAndDecompress(compressedEncrypted);
        System.out.println("Decrypted + Decompressed:\n" + decompressed + "\n");

        // ========== MODE 3: Using Specific Key ==========
        System.out.println("\n5. MODE 3: Encryption with Specific Key");
        System.out.println("========================================\n");

        String keyId = additionalKeys.keySet().iterator().next();
        String encryptedWithSpecificKey = crypto.compressAndEncryptWithKeyId(payoutJson, keyId);
        System.out.println("Encrypted with keyId [" + keyId + "]:\n" + encryptedWithSpecificKey + "\n");

        String decryptedWithSpecificKey = crypto.decryptAndDecompressWithKeyId(encryptedWithSpecificKey, keyId);
        System.out.println("Decrypted with keyId [" + keyId + "]:\n" + decryptedWithSpecificKey + "\n");

        // ========== VALIDATION ==========
        System.out.println("\n6. VALIDATION");
        System.out.println("=============\n");

        System.out.println("Is valid encrypted format: " + PayoutCryptoService.isValidEncryptedFormat(encrypted));
        System.out.println("Is valid encrypted format: " + PayoutCryptoService.isValidEncryptedFormat("invalid"));
    }
}