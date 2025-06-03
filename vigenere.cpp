#include <stdio.h>   // Pour les fonctions d'entrée/sortie comme printf, fgets
#include <stdlib.h>  // Pour malloc et free (gestion de la mémoire dynamique)
#include <string.h>  // Pour strlen, strcpy, strcspn (manipulation de chaînes de caractères)
#include <ctype.h>   // Pour isalpha, isupper, toupper (vérification/conversion de caractères)

/**
 * @brief Chiffre un texte en clair en utilisant le chiffrement de Vigenère.
 *
 * Alloue dynamiquement de la mémoire pour le texte chiffré.
 * L'appelant est responsable de libérer cette mémoire avec free().
 *
 * @param plaintext Le texte en clair à chiffrer.
 * @param key La clé de chiffrement.
 * @return Un pointeur vers la chaîne de caractères chiffrée, ou NULL en cas d'erreur.
 */
char* encrypt_vigenere(const char* plaintext, const char* key) {
    size_t plain_len = strlen(plaintext);
    size_t key_len = strlen(key);

    // Alloue de la mémoire pour le texte chiffré (+1 pour le caractère nul de fin de chaîne)
    char* ciphertext = (char*)malloc((plain_len + 1) * sizeof(char));
    if (ciphertext == NULL) {
        perror("Échec de l'allocation mémoire pour le texte chiffré");
        return NULL;
    }

    int key_idx = 0; // Index pour parcourir la clé

    for (size_t i = 0; i < plain_len; i++) {
        char plain_char = plaintext[i];
        char encrypted_char;

        if (isalpha(plain_char)) { // Traite uniquement les caractères alphabétiques
            char base = isupper(plain_char) ? 'A' : 'a'; // Détermine la base ('A' ou 'a')
            
            // Cherche le prochain caractère alphabétique dans la clé
            // Boucle pour ignorer les non-alphabétiques dans la clé
            while (key_idx < key_len && !isalpha(key[key_idx])) {
                key_idx++;
            }
            // Si on a parcouru toute la clé, recommence au début
            if (key_idx == key_len) {
                key_idx = 0;
                // Assure qu'on ne boucle pas indéfiniment si la clé ne contient que des non-alphabétiques
                while (key_idx < key_len && !isalpha(key[key_idx])) {
                    key_idx++;
                }
                // Si la clé est vide ou ne contient que des non-alphabétiques, on ne peut pas chiffrer
                if (key_idx == key_len) { 
                    fprintf(stderr, "Erreur: La clé ne contient aucun caractère alphabétique valide.\n");
                    free(ciphertext);
                    return NULL;
                }
            }

            char key_char_for_shift = toupper(key[key_idx]); // Utilise la majuscule de la clé pour le décalage
            int shift = key_char_for_shift - 'A'; // Calcule la valeur de décalage (0-25)

            // Applique la formule de chiffrement de Vigenère
            encrypted_char = ((plain_char - base + shift) % 26) + base;
            
            key_idx++; // Passe au caractère suivant de la clé pour le prochain chiffrement
        } else {
            // Les caractères non alphabétiques sont laissés inchangés
            encrypted_char = plain_char;
        }
        ciphertext[i] = encrypted_char;
    }
    ciphertext[plain_len] = '\0'; // Termine la chaîne avec un caractère nul

    return ciphertext;
}

/**
 * @brief Déchiffre un texte chiffré en utilisant le chiffrement de Vigenère.
 *
 * Alloue dynamiquement de la mémoire pour le texte déchiffré.
 * L'appelant est responsable de libérer cette mémoire avec free().
 *
 * @param ciphertext Le texte chiffré à déchiffrer.
 * @param key La clé de déchiffrement (doit être la même que celle utilisée pour le chiffrement).
 * @return Un pointeur vers la chaîne de caractères déchiffrée, ou NULL en cas d'erreur.
 */
char* decrypt_vigenere(const char* ciphertext, const char* key) {
    size_t cipher_len = strlen(ciphertext);
    size_t key_len = strlen(key);

    // Alloue de la mémoire pour le texte clair (+1 pour le caractère nul de fin de chaîne)
    char* plaintext = (char*)malloc((cipher_len + 1) * sizeof(char));
    if (plaintext == NULL) {
        perror("Échec de l'allocation mémoire pour le texte clair");
        return NULL;
    }

    int key_idx = 0; // Index pour parcourir la clé

    for (size_t i = 0; i < cipher_len; i++) {
        char cipher_char = ciphertext[i];
        char decrypted_char;

        if (isalpha(cipher_char)) { // Traite uniquement les caractères alphabétiques
            char base = isupper(cipher_char) ? 'A' : 'a'; // Détermine la base ('A' ou 'a')

            // Cherche le prochain caractère alphabétique dans la clé
            while (key_idx < key_len && !isalpha(key[key_idx])) {
                key_idx++;
            }
            if (key_idx == key_len) {
                key_idx = 0;
                while (key_idx < key_len && !isalpha(key[key_idx])) {
                    key_idx++;
                }
                if (key_idx == key_len) {
                    fprintf(stderr, "Erreur: La clé ne contient aucun caractère alphabétique valide.\n");
                    free(plaintext);
                    return NULL;
                }
            }
            
            char key_char_for_shift = toupper(key[key_idx]); // Utilise la majuscule de la clé pour le décalage
            int shift = key_char_for_shift - 'A'; // Calcule la valeur de décalage (0-25)

            // Applique la formule de déchiffrement de Vigenère
            // Ajoute +26 avant le modulo pour gérer correctement les résultats négatifs en C
            decrypted_char = ((cipher_char - base - shift + 26) % 26) + base;
            
            key_idx++; // Passe au caractère suivant de la clé
        } else {
            // Les caractères non alphabétiques sont laissés inchangés
            decrypted_char = cipher_char;
        }
        plaintext[i] = decrypted_char;
    }
    plaintext[cipher_len] = '\0'; // Termine la chaîne avec un caractère nul

    return plaintext;
}

/**
 * @brief Fonction principale du programme.
 * Demande à l'utilisateur un message et une clé, puis chiffre et déchiffre le message.
 */
int main() {
    char message[1000]; // Tampon pour le message (taille maximale 999 caractères + null)
    char key[1000];     // Tampon pour la clé (taille maximale 999 caractères + null)

    printf("Entrez votre message : \n");
    // Utilise fgets pour une lecture sécurisée afin d'éviter les dépassements de tampon
    if (fgets(message, sizeof(message), stdin) == NULL) {
        perror("Erreur lors de la lecture du message");
        return 1; // Quitte avec un code d'erreur
    }
    // Supprime le caractère de nouvelle ligne ('\n') ajouté par fgets s'il est présent
    message[strcspn(message, "\n")] = 0;

    printf("Entrez votre clé : \n");
    if (fgets(key, sizeof(key), stdin) == NULL) {
        perror("Erreur lors de la lecture de la clé");
        return 1; // Quitte avec un code d'erreur
    }
    // Supprime le caractère de nouvelle ligne ('\n') de la clé
    key[strcspn(key, "\n")] = 0;

    printf("\n--- Test du Chiffrement de Vigenère ---\n");
    printf("Message original : \"%s\"\n", message);
    printf("Clé utilisée : \"%s\"\n", key);

    // --- Chiffrement ---
    char* encrypted_text = encrypt_vigenere(message, key);
    if (encrypted_text != NULL) { // Vérifie si le chiffrement a réussi (pas d'erreur d'allocation/clé vide)
        printf("Message chiffré : \"%s\"\n", encrypted_text);

        // --- Déchiffrement ---
        char* decrypted_text = decrypt_vigenere(encrypted_text, key);
        if (decrypted_text != NULL) { // Vérifie si le déchiffrement a réussi
            printf("Message déchiffré : \"%s\"\n", decrypted_text);
            free(decrypted_text); // Libère la mémoire allouée pour le texte déchiffré
        }
        free(encrypted_text); // Libère la mémoire allouée pour le texte chiffré
    } else {
        fprintf(stderr, "Le chiffrement a échoué. Vérifiez la clé.\n");
    }

    return 0; // Termine le programme avec succès
}