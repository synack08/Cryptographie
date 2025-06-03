#include <stdio.h>   // Fonctions d'entrée/sortie (printf)
#include <stdlib.h>  // Allocation mémoire (malloc, free)
#include <string.h>  // Manipulation de chaînes (strlen, strcpy)

/**
 * @brief Chiffre un texte en clair via le chiffrement de César.
 * @param plaintext Le texte à chiffrer.
 * @param shift Le décalage (clé de chiffrement).
 * @return La chaîne chiffrée allouée dynamiquement (à libérer par l'appelant).
 */
char* encrypt_cesar(const char* plaintext, int shift) {
    // Normalise le décalage entre 0 et 25.
    shift = shift % 26;
    if (shift < 0) {
        shift += 26;
    }

    size_t len = strlen(plaintext);
    // Alloue de la mémoire pour le texte chiffré.
    char* ciphertext = (char*)malloc((len + 1) * sizeof(char));
    if (ciphertext == NULL) {
        perror("Échec d'allocation mémoire");
        return NULL;
    }
    strcpy(ciphertext, plaintext); // Copie le texte pour le modifier.

    // Parcourt chaque caractère du texte.
    for (size_t i = 0; i < len; i++) {
        // Traite les majuscules.
        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            ciphertext[i] = ((ciphertext[i] - 'A' + shift) % 26) + 'A';
        } 
        // Traite les minuscules.
        else if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            ciphertext[i] = ((ciphertext[i] - 'a' + shift) % 26) + 'a';
        }
        // Les autres caractères sont laissés inchangés.
    }
    return ciphertext;
}

/**
 * @brief Déchiffre un texte chiffré de César.
 * @param ciphertext Le texte à déchiffrer.
 * @param shift Le décalage (clé de déchiffrement).
 * @return La chaîne déchiffrée allouée dynamiquement (à libérer par l'appelant).
 */
char* decrypt_cesar(const char* ciphertext, int shift) {
    // Le déchiffrement est un chiffrement avec un décalage négatif.
    return encrypt_cesar(ciphertext, -shift);
}

/**
 * @brief Point d'entrée principal du programme.
 * Démontre le chiffrement et le déchiffrement de César.
 */
int main() {
    char original_name[] = "BOUBACAR";
    int encryption_shift = 3;

    printf("Nom original: \"%s\"\n", original_name);
    printf("Décalage: %d\n", encryption_shift);

    // Chiffrement du nom.
    char* encrypted_name = encrypt_cesar(original_name, encryption_shift);
    if (encrypted_name != NULL) {
        printf("Nom chiffré: \"%s\"\n", encrypted_name);

        // Déchiffrement du nom.
        char* decrypted_name = decrypt_cesar(encrypted_name, encryption_shift);
        if (decrypted_name != NULL) {
            printf("Nom déchiffré: \"%s\"\n", decrypted_name);
            free(decrypted_name); // Libère la mémoire du texte déchiffré.
        }
        free(encrypted_name); // Libère la mémoire du texte chiffré.
    }

    return 0;
}
