package learn.isPossible.upload.onedrive.service;

import java.util.zip.Deflater;

public class CryptoConstants {
    // Algorithm configurations
    public static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    public static final String KEY_ALGORITHM = "AES";

    // Key and IV sizes
    public static final int KEY_SIZE = 256;                    // 256-bit key
    public static final int IV_SIZE = 12;                      // 96-bit IV (GCM standard)
    public static final int TAG_LENGTH = 128;                  // 128-bit authentication tag

    // Compression settings
    public static final int BUFFER_SIZE = 8192;
    public static final int COMPRESSION_LEVEL = Deflater.BEST_SPEED;

    // Data format separator
    public static final String DATA_SEPARATOR = ".";

    // Expected key byte length (256-bit = 32 bytes)
    public static final int EXPECTED_KEY_BYTE_LENGTH = 32;
}