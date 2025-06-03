#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* encrypt_cesar(const char* plaintext, int shift) {
    shift = shift % 26;
    if (shift < 0) {
        shift += 26;
    }

    size_t len = strlen(plaintext);
    char* ciphertext = (char*)malloc((len + 1) * sizeof(char));
    if (ciphertext == NULL) {
        perror("Failed to allocate memory for ciphertext");
        return NULL;
    }
    strcpy(ciphertext, plaintext);

    for (size_t i = 0; i < len; i++) {
        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            ciphertext[i] = ((ciphertext[i] - 'A' + shift) % 26) + 'A';
        } else if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            ciphertext[i] = ((ciphertext[i] - 'a' + shift) % 26) + 'a';
        }
    }
    return ciphertext;
}

char* decrypt_cesar(const char* ciphertext, int shift) {
    return encrypt_cesar(ciphertext, -shift);
}

int main() {
    char original_name[] = "BOUBACAR";
    int encryption_shift = 3;

    printf("Original Name: \"%s\"\n", original_name);
    printf("Shift: %d\n", encryption_shift);

    char* encrypted_name = encrypt_cesar(original_name, encryption_shift);
    if (encrypted_name != NULL) {
        printf("Encrypted Name: \"%s\"\n", encrypted_name);

        char* decrypted_name = decrypt_cesar(encrypted_name, encryption_shift);
        if (decrypted_name != NULL) {
            printf("Decrypted Name: \"%s\"\n", decrypted_name);
            free(decrypted_name);
        }
        free(encrypted_name);
    }

    return 0;
}
