#include <stdio.h>
#include <stdlib.h> // For malloc and free
#include <string.h> // For strlen and strcpy

// Function to encrypt a plaintext string using the Caesar cipher
// Returns a dynamically allocated string containing the ciphertext.
// It's the caller's responsibility to free this memory.
char* encrypt_cesar(const char* plaintext, int shift) {
    // Ensure the shift is within a reasonable range [0, 25]
    // A negative shift behaves like a positive shift (e.g., -1 is like +25)
    shift = shift % 26;
    if (shift < 0) {
        shift += 26;
    }

    size_t len = strlen(plaintext);
    char* ciphertext = (char*)malloc((len + 1) * sizeof(char)); // +1 for null terminator
    if (ciphertext == NULL) {
        perror("Failed to allocate memory for ciphertext");
        return NULL;
    }
    strcpy(ciphertext, plaintext); // Copy plaintext to work on

    for (size_t i = 0; i < len; i++) {
        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            // Uppercase letters
            ciphertext[i] = ((ciphertext[i] - 'A' + shift) % 26) + 'A';
        } else if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            // Lowercase letters
            ciphertext[i] = ((ciphertext[i] - 'a' + shift) % 26) + 'a';
        }
        // Non-alphabetic characters are left unchanged
    }
    return ciphertext;
}

// Function to decrypt a ciphertext string using the Caesar cipher
// Returns a dynamically allocated string containing the plaintext.
// It's the caller's responsibility to free this memory.
char* decrypt_cesar(const char* ciphertext, int shift) {
    // Decrypting with a positive shift is equivalent to encrypting with a negative shift.
    // So, we can reuse the encrypt function with a negative shift.
    return encrypt_cesar(ciphertext, -shift);
}

int main() {
    char original_name[] = "BOUBACAR";
    int encryption_shift = 10;

    printf("Original Name: \"%s\"\n", original_name);
    printf("Shift: %d\n", encryption_shift);

    // Encryption
    char* encrypted_name = encrypt_cesar(original_name, encryption_shift);
    if (encrypted_name != NULL) {
        printf("Encrypted Name: \"%s\"\n", encrypted_name);

        // Decryption
        char* decrypted_name = decrypt_cesar(encrypted_name, encryption_shift);
        if (decrypted_name != NULL) {
            printf("Decrypted Name: \"%s\"\n", decrypted_name);
            free(decrypted_name); // Free memory allocated for decrypted_name
        }
        free(encrypted_name); // Free memory allocated for encrypted_name
    }

    return 0;
}