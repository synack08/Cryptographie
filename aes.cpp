#include <stdio.h>   // Fonctions d'entrée/sortie (printf, perror, fgets)
#include <stdlib.h>  // Gestion de la mémoire (malloc, free)
#include <string.h>  // Manipulation de chaînes (strlen, strcpy, strcspn)
#include <ctype.h>   // Vérification/conversion de caractères (isalpha, isupper, toupper)
#include <math.h>    // Fonctions mathématiques (log2)

// --- Définitions globales ---
#define ALPHABET_SIZE 26 // Taille de l'alphabet (A-Z)

// Structure pour une matrice 2x2, utilisée par le chiffrement de Hill
typedef struct {
    int mat[2][2];
} Matrix2x2;

// --- Fonctions Utilitaires Générales ---

/**
 * @brief Calcule l'inverse modulaire de 'a' sous le module 'm'.
 * Nécessaire pour le déchiffrement affine et Hill.
 * @param a Le nombre dont chercher l'inverse.
 * @param m Le module.
 * @return L'inverse modulaire si elle existe, -1 sinon.
 */
int modInverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return -1;
}

/**
 * @brief Calcule les fréquences de chaque lettre alphabétique dans un texte.
 * @param text La chaîne à analyser.
 * @param frequencies Tableau de ALPHABET_SIZE doubles pour stocker les fréquences.
 * @return Le nombre total de caractères alphabétiques traités.
 */
int calculate_frequencies(const char* text, double frequencies[ALPHABET_SIZE]) {
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        frequencies[i] = 0.0;
    }

    int total_alpha_chars = 0;
    size_t len = strlen(text);

    for (size_t i = 0; i < len; i++) {
        char c = toupper(text[i]); // Convertit en majuscule pour un traitement unifié
        if (c >= 'A' && c <= 'Z') {
            frequencies[c - 'A']++;
            total_alpha_chars++;
        }
    }

    if (total_alpha_chars > 0) {
        for (int i = 0; i < ALPHABET_SIZE; i++) {
            frequencies[i] /= total_alpha_chars;
        }
    }
    return total_alpha_chars;
}

// --- 2. Entropie, Redondance et Indice de Coïncidence ---

/**
 * @brief Calcule l'entropie d'un texte.
 * Mesure la quantité d'information ou d'incertitude.
 * @param text Le texte à analyser.
 * @return L'entropie en bits par caractère.
 */
double calculate_entropy(const char* text) {
    double frequencies[ALPHABET_SIZE];
    int total_alpha_chars = calculate_frequencies(text, frequencies);

    if (total_alpha_chars == 0) {
        return 0.0;
    }

    double entropy = 0.0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (frequencies[i] > 0) {
            entropy -= frequencies[i] * log2(frequencies[i]);
        }
    }
    return entropy;
}

/**
 * @brief Calcule la redondance d'un texte.
 * Mesure l'excès d'information ou la prévisibilité.
 * @param text Le texte à analyser.
 * @return La redondance en bits par caractère.
 */
double calculate_redundancy(const char* text) {
    double H = calculate_entropy(text);
    double H_max = log2(ALPHABET_SIZE); // Entropie maximale théorique
    return H_max - H;
}

/**
 * @brief Calcule l'incidence de coïncidence (IC) d'un texte.
 * Mesure la probabilité que deux lettres choisies au hasard soient identiques.
 * @param text Le texte à analyser.
 * @return La valeur de l'incidence de coïncidence.
 */
double calculate_ic(const char* text) {
    int counts[ALPHABET_SIZE] = {0};
    int total_alpha_chars = 0;
    size_t len = strlen(text);

    for (size_t i = 0; i < len; i++) {
        char c = toupper(text[i]);
        if (c >= 'A' && c <= 'Z') {
            counts[c - 'A']++;
            total_alpha_chars++;
        }
    }

    if (total_alpha_chars < 2) {
        return 0.0;
    }

    double ic = 0.0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        ic += (double)counts[i] * (counts[i] - 1);
    }
    ic /= ((double)total_alpha_chars * (total_alpha_chars - 1));

    return ic;
}

// --- 2.1 Le chiffrement de Lester Hill (matrice 2x2) ---

/**
 * @brief Chiffre un texte avec le chiffrement de Hill (matrice 2x2).
 * Le texte clair est complété avec 'X' si sa longueur alphabétique est impaire.
 * @param plaintext Le texte clair.
 * @param key La matrice clé 2x2.
 * @return Le texte chiffré alloué dynamiquement, ou NULL en cas d'erreur (clé non inversible).
 */
char* encrypt_hill(const char* plaintext, Matrix2x2 key) {
    int alpha_count = 0;
    for(size_t i = 0; i < strlen(plaintext); i++) {
        if (isalpha(plaintext[i])) alpha_count++;
    }

    // Gère le padding (complément)
    int padded_len = alpha_count;
    if (padded_len % 2 != 0) padded_len++;

    char* processed_plaintext = (char*)malloc((padded_len + 1) * sizeof(char));
    if (processed_plaintext == NULL) { perror("Échec d'allocation mémoire"); return NULL; }
    int current_char_idx = 0;
    for(size_t i = 0; i < strlen(plaintext); i++) {
        if (isalpha(plaintext[i])) processed_plaintext[current_char_idx++] = toupper(plaintext[i]);
    }
    if (current_char_idx < padded_len) processed_plaintext[current_char_idx++] = 'X';
    processed_plaintext[padded_len] = '\0';

    // Vérifie si la clé est inversible modulo 26
    int det = (key.mat[0][0] * key.mat[1][1] - key.mat[0][1] * key.mat[1][0]) % ALPHABET_SIZE;
    if (det < 0) det += ALPHABET_SIZE;
    if (det == 0 || (det % 2 == 0) || (det % 13 == 0)) {
        fprintf(stderr, "Erreur Hill: Déterminant de la clé (%d) non inversible modulo %d.\n", det, ALPHABET_SIZE);
        free(processed_plaintext);
        return NULL;
    }

    char* ciphertext = (char*)malloc((padded_len + 1) * sizeof(char));
    if (ciphertext == NULL) { perror("Échec d'allocation mémoire"); free(processed_plaintext); return NULL; }

    // Chiffre par blocs de 2
    for (int i = 0; i < padded_len; i += 2) {
        int p1 = processed_plaintext[i] - 'A';
        int p2 = processed_plaintext[i+1] - 'A';

        int c1 = (key.mat[0][0] * p1 + key.mat[0][1] * p2) % ALPHABET_SIZE;
        int c2 = (key.mat[1][0] * p1 + key.mat[1][1] * p2) % ALPHABET_SIZE;

        ciphertext[i] = c1 + 'A';
        ciphertext[i+1] = c2 + 'A';
    }
    ciphertext[padded_len] = '\0';

    free(processed_plaintext);
    return ciphertext;
}

/**
 * @brief Déchiffre un texte chiffré avec le chiffrement de Hill (matrice 2x2).
 * @param ciphertext Le texte chiffré.
 * @param key La matrice clé utilisée pour le chiffrement.
 * @return Le texte clair alloué dynamiquement, ou NULL en cas d'erreur.
 */
char* decrypt_hill(const char* ciphertext, Matrix2x2 key) {
    size_t cipher_len = strlen(ciphertext);
    if (cipher_len % 2 != 0) {
        fprintf(stderr, "Erreur Hill: Longueur du texte chiffré impaire.\n");
        return NULL;
    }

    // Calcule l'inverse de la matrice clé
    int det = (key.mat[0][0] * key.mat[1][1] - key.mat[0][1] * key.mat[1][0]) % ALPHABET_SIZE;
    if (det < 0) det += ALPHABET_SIZE;
    
    int det_inv = modInverse(det, ALPHABET_SIZE);
    if (det_inv == -1) {
        fprintf(stderr, "Erreur Hill: Inverse du déterminant non trouvé.\n");
        return NULL;
    }

    Matrix2x2 inv_key;
    inv_key.mat[0][0] = (key.mat[1][1] * det_inv) % ALPHABET_SIZE;
    inv_key.mat[0][1] = (-key.mat[0][1] * det_inv) % ALPHABET_SIZE;
    inv_key.mat[1][0] = (-key.mat[1][0] * det_inv) % ALPHABET_SIZE;
    inv_key.mat[1][1] = (key.mat[0][0] * det_inv) % ALPHABET_SIZE;

    // Assure que les éléments de la matrice inverse sont positifs
    for (int r = 0; r < 2; r++) {
        for (int c = 0; c < 2; c++) {
            if (inv_key.mat[r][c] < 0) {
                inv_key.mat[r][c] += ALPHABET_SIZE;
            }
        }
    }

    char* plaintext = (char*)malloc((cipher_len + 1) * sizeof(char));
    if (plaintext == NULL) { perror("Échec d'allocation mémoire"); return NULL; }

    // Déchiffre par blocs de 2
    for (size_t i = 0; i < cipher_len; i += 2) {
        int c1 = ciphertext[i] - 'A';
        int c2 = ciphertext[i+1] - 'A';

        int p1 = (inv_key.mat[0][0] * c1 + inv_key.mat[0][1] * c2) % ALPHABET_SIZE;
        int p2 = (inv_key.mat[1][0] * c1 + inv_key.mat[1][1] * c2) % ALPHABET_SIZE;

        plaintext[i] = p1 + 'A';
        plaintext[i+1] = p2 + 'A';
    }
    plaintext[cipher_len] = '\0';

    return plaintext;
}

// --- 2.2 Le chiffrement affine ---

/**
 * @brief Chiffre un texte clair avec le chiffrement affine.
 * @param plaintext Le texte clair.
 * @param a Clé multiplicative (doit être coprime avec 26).
 * @param b Clé additive.
 * @return Le texte chiffré alloué dynamiquement, ou NULL en cas d'erreur.
 */
char* encrypt_affine(const char* plaintext, int a, int b) {
    // Vérifie que 'a' est inversible modulo 26
    if (modInverse(a, ALPHABET_SIZE) == -1) {
        fprintf(stderr, "Erreur Affine: Clé 'a' (%d) non inversible modulo %d.\n", a, ALPHABET_SIZE);
        return NULL;
    }

    size_t len = strlen(plaintext);
    char* ciphertext = (char*)malloc((len + 1) * sizeof(char));
    if (ciphertext == NULL) { perror("Échec d'allocation mémoire"); return NULL; }

    // Parcourt et chiffre chaque caractère alphabétique.
    for (size_t i = 0; i < len; i++) {
        char current_char = plaintext[i];
        if (isalpha(current_char)) {
            char base = isupper(current_char) ? 'A' : 'a';
            int P = current_char - base;
            
            int C = (a * P + b) % ALPHABET_SIZE;
            if (C < 0) C += ALPHABET_SIZE; // Assure un résultat positif

            ciphertext[i] = C + base;
        } else {
            ciphertext[i] = current_char; // Non-alphabétiques inchangés
        }
    }
    ciphertext[len] = '\0';
    return ciphertext;
}

/**
 * @brief Déchiffre un texte chiffré avec le chiffrement affine.
 * @param ciphertext Le texte chiffré.
 * @param a Clé multiplicative.
 * @param b Clé additive.
 * @return Le texte clair alloué dynamiquement, ou NULL en cas d'erreur.
 */
char* decrypt_affine(const char* ciphertext, int a, int b) {
    int a_inv = modInverse(a, ALPHABET_SIZE);
    if (a_inv == -1) {
        fprintf(stderr, "Erreur Affine: Clé 'a' (%d) non inversible modulo %d.\n", a, ALPHABET_SIZE);
        return NULL;
    }

    size_t len = strlen(ciphertext);
    char* plaintext = (char*)malloc((len + 1) * sizeof(char));
    if (plaintext == NULL) { perror("Échec d'allocation mémoire"); return NULL; }

    // Parcourt et déchiffre chaque caractère alphabétique.
    for (size_t i = 0; i < len; i++) {
        char current_char = ciphertext[i];
        if (isalpha(current_char)) {
            char base = isupper(current_char) ? 'A' : 'a';
            int C = current_char - base;

            // Formule de déchiffrement: P = a_inv * (C - b) mod 26
            int P = (a_inv * (C - b));
            P = (P % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE; // Assure un résultat positif

            plaintext[i] = P + base;
        } else {
            plaintext[i] = current_char; // Non-alphabétiques inchangés
        }
    }
    plaintext[len] = '\0';
    return plaintext;
}


// --- Fonction main pour démontrer toutes les fonctionnalités ---
int main() {
    // --- Tests pour Entropie, Redondance, Incidence de Coïncidence ---
    const char* text_clair = "CECI EST UN TEST POUR LENTROPIE ET LA REDONDANCE ET LINCIDENCE DE COINCIDENCE";
    const char* text_chiffre_aleatoire = "ZQWXTJKLMNOIPQRSUVWXZYZABCDEFGH"; // Exemple de texte "aléatoire"
    const char* text_redondant = "AAAAAAAAAAAAAAAAAAAAAAAAAAAZZAAAAAAAAAAAAAAAAA";

    printf("--- Entropie, Redondance et Incidence de Coïncidence ---\n");
    printf("Texte: \"%s\"\n", text_clair);
    printf("  Entropie: %.4f bits/char\n", calculate_entropy(text_clair));
    printf("  Redondance: %.4f bits/char\n", calculate_redundancy(text_clair));
    printf("  Incidence de coïncidence: %.4f\n\n", calculate_ic(text_clair));

    printf("Texte: \"%s\"\n", text_chiffre_aleatoire);
    printf("  Entropie: %.4f bits/char\n", calculate_entropy(text_chiffre_aleatoire));
    printf("  Redondance: %.4f bits/char\n", calculate_redundancy(text_chiffre_aleatoire));
    printf("  Incidence de coïncidence: %.4f\n\n", calculate_ic(text_chiffre_aleatoire));

    printf("Texte: \"%s\"\n", text_redondant);
    printf("  Entropie: %.4f bits/char\n", calculate_entropy(text_redondant));
    printf("  Redondance: %.4f bits/char\n", calculate_redundancy(text_redondant));
    printf("  Incidence de coïncidence: %.4f\n\n", calculate_ic(text_redondant));


    // --- Tests pour Chiffrement de Lester Hill (matrice 2x2) ---
    Matrix2x2 hill_key = {{{11, 8}, {3, 7}}}; // Exemple de clé inversible mod 26
    const char* hill_message = "BONJOURLEMONDE"; // Longueur 14, sera complétée à 14 pour les lettres

    printf("\n--- Chiffrement de Lester Hill (Matrice 2x2) ---\n");
    printf("Message original : \"%s\"\n", hill_message);
    printf("Clé matrice :\n[%d %d]\n[%d %d]\n", hill_key.mat[0][0], hill_key.mat[0][1], hill_key.mat[1][0], hill_key.mat[1][1]);

    char* encrypted_hill = encrypt_hill(hill_message, hill_key);
    if (encrypted_hill != NULL) {
        printf("Message chiffré : \"%s\"\n", encrypted_hill);

        char* decrypted_hill = decrypt_hill(encrypted_hill, hill_key);
        if (decrypted_hill != NULL) {
            printf("Message déchiffré : \"%s\"\n", decrypted_hill);
            free(decrypted_hill);
        }
        free(encrypted_hill);
    }
    printf("\n");

    // --- Tests pour Chiffrement Affine ---
    const char* affine_message = "CRYPTOGRAPHIE EST AMUSANTE";
    int a_key = 5; // Doit être coprime avec 26 (ex: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)
    int b_key = 8; // Peut être n'importe quelle valeur

    printf("\n--- Chiffrement Affine ---\n");
    printf("Message original : \"%s\"\n", affine_message);
    printf("Clé a: %d, Clé b: %d\n", a_key, b_key);

    char* encrypted_affine = encrypt_affine(affine_message, a_key, b_key);
    if (encrypted_affine != NULL) {
        printf("Message chiffré : \"%s\"\n", encrypted_affine);

        char* decrypted_affine = decrypt_affine(encrypted_affine, a_key, b_key);
        if (decrypted_affine != NULL) {
            printf("Message déchiffré : \"%s\"\n", decrypted_affine);
            free(decrypted_affine);
        }
        free(encrypted_affine);
    }
    printf("\n");

    // --- Note sur AES et RSA ---
    printf("\n--- AES et RSA ---\n");


    return 0;
}