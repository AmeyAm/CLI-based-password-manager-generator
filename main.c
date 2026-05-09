#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <termios.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MIN_PASSWORD_LEN 12
#define MAX_PASSWORD_LEN 64
#define MIN_MASTER_PASSWORD_LEN 8
#define MAX_MASTER_PASSWORD_LEN 256
#ifndef DEFAULT_STORE_FILE
#define DEFAULT_STORE_FILE "passwords.txt"
#endif
#define PBKDF2_ITERATIONS 310000
#define KEY_LEN 32
#define SALT_LEN 16
#define IV_LEN 12
#define TAG_LEN 16
#define MAX_CIPHERTEXT_LEN (MAX_PASSWORD_LEN + EVP_MAX_BLOCK_LENGTH)

static int secure_random_bytes(unsigned char *buffer, size_t size) {
    if (size > INT_MAX) {
        return 0;
    }

    return RAND_priv_bytes(buffer, (int)size) == 1;
}

static int random_index(size_t upper_bound, size_t *out) {
    if (upper_bound == 0 || upper_bound > 256) {
        return 0;
    }

    const unsigned int limit = 256U - (256U % (unsigned int)upper_bound);
    unsigned char value = 0;

    do {
        if (!secure_random_bytes(&value, 1)) {
            return 0;
        }
    } while (value >= limit);

    *out = (size_t)(value % upper_bound);
    return 1;
}

static int choose_from_charset(const char *charset, char *out) {
    size_t index = 0;

    if (!random_index(strlen(charset), &index)) {
        return 0;
    }

    *out = charset[index];
    return 1;
}

static int generate_password(char *out, size_t length) {
    static const char lowercase[] = "abcdefghijklmnopqrstuvwxyz";
    static const char uppercase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const char digits[] = "0123456789";
    static const char symbols[] = "!@#$%^&*()-_=+[]{};:,.?/|~";
    static const char all_chars[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{};:,.?/|~";

    if (length < 4 || length > MAX_PASSWORD_LEN) {
        return 0;
    }

    if (!choose_from_charset(lowercase, &out[0]) ||
        !choose_from_charset(uppercase, &out[1]) ||
        !choose_from_charset(digits, &out[2]) ||
        !choose_from_charset(symbols, &out[3])) {
        return 0;
    }

    for (size_t i = 4; i < length; i++) {
        if (!choose_from_charset(all_chars, &out[i])) {
            return 0;
        }
    }

    for (size_t i = length - 1; i > 0; i--) {
        size_t swap_index = 0;
        char temp = '\0';

        if (!random_index(i + 1, &swap_index)) {
            return 0;
        }

        temp = out[i];
        out[i] = out[swap_index];
        out[swap_index] = temp;
    }

    out[length] = '\0';
    return 1;
}

static int read_hidden_line(const char *prompt, char *out, size_t size) {
    struct termios old_termios;
    struct termios new_termios;
    int hide_input = 0;

    printf("%s", prompt);
    fflush(stdout);

    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_termios) == 0) {
        new_termios = old_termios;
        new_termios.c_lflag &= (tcflag_t)~ECHO;
        hide_input = tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_termios) == 0;
    }

    if (fgets(out, (int)size, stdin) == NULL) {
        if (hide_input) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
            printf("\n");
        }
        return 0;
    }

    if (hide_input) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
        printf("\n");
    }

    out[strcspn(out, "\n")] = '\0';
    return 1;
}

static void bytes_to_hex(const unsigned char *bytes, size_t bytes_len, char *hex) {
    static const char hex_chars[] = "0123456789abcdef";

    for (size_t i = 0; i < bytes_len; i++) {
        hex[i * 2] = hex_chars[bytes[i] >> 4];
        hex[(i * 2) + 1] = hex_chars[bytes[i] & 0x0f];
    }

    hex[bytes_len * 2] = '\0';
}

static int encrypt_password(
    const char *master_password,
    const char *label,
    const char *password,
    unsigned char salt[SALT_LEN],
    unsigned char iv[IV_LEN],
    unsigned char tag[TAG_LEN],
    unsigned char *ciphertext,
    int *ciphertext_len
) {
    unsigned char key[KEY_LEN];
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ok = 0;

    if (!secure_random_bytes(salt, SALT_LEN) || !secure_random_bytes(iv, IV_LEN)) {
        return 0;
    }

    if (PKCS5_PBKDF2_HMAC(
            master_password,
            (int)strlen(master_password),
            salt,
            SALT_LEN,
            PBKDF2_ITERATIONS,
            EVP_sha256(),
            KEY_LEN,
            key) != 1) {
        OPENSSL_cleanse(key, sizeof(key));
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OPENSSL_cleanse(key, sizeof(key));
        return 0;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char *)label, (int)strlen(label)) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *)password, (int)strlen(password)) != 1) {
        goto cleanup;
    }

    *ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        goto cleanup;
    }

    *ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        goto cleanup;
    }

    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    return ok;
}

static int store_encrypted_password(
    const char *filename,
    const char *label,
    const unsigned char salt[SALT_LEN],
    const unsigned char iv[IV_LEN],
    const unsigned char tag[TAG_LEN],
    const unsigned char *ciphertext,
    int ciphertext_len
) {
    char salt_hex[(SALT_LEN * 2) + 1];
    char iv_hex[(IV_LEN * 2) + 1];
    char tag_hex[(TAG_LEN * 2) + 1];
    char ciphertext_hex[(MAX_CIPHERTEXT_LEN * 2) + 1];
    FILE *fp = fopen(filename, "a");

    if (fp == NULL) {
        return 0;
    }

    bytes_to_hex(salt, SALT_LEN, salt_hex);
    bytes_to_hex(iv, IV_LEN, iv_hex);
    bytes_to_hex(tag, TAG_LEN, tag_hex);
    bytes_to_hex(ciphertext, (size_t)ciphertext_len, ciphertext_hex);

    fprintf(
        fp,
        "v1:%s:%d:%s:%s:%s:%s\n",
        label,
        PBKDF2_ITERATIONS,
        salt_hex,
        iv_hex,
        tag_hex,
        ciphertext_hex);

    fclose(fp);
    return 1;
}

int main(){
    char label[128];
    char master_password[MAX_MASTER_PASSWORD_LEN];
    char master_password_confirm[MAX_MASTER_PASSWORD_LEN];
    char password[MAX_PASSWORD_LEN + 1] = {0};
    int length = 0;
    unsigned char salt[SALT_LEN];
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char ciphertext[MAX_CIPHERTEXT_LEN];
    int ciphertext_len = 0;
    int exit_code = 1;

    printf("Account/label: ");
    if (fgets(label, sizeof(label), stdin) == NULL) {
        fprintf(stderr, "Failed to read label.\n");
        goto cleanup;
    }

    label[strcspn(label, "\n")] = '\0';
    if (strlen(label) == 0) {
        fprintf(stderr, "Label cannot be empty.\n");
        goto cleanup;
    }

    if (strchr(label, ':') != NULL) {
        fprintf(stderr, "Label cannot contain ':'.\n");
        goto cleanup;
    }

    printf("Password length (%d-%d): ", MIN_PASSWORD_LEN, MAX_PASSWORD_LEN);
    if (scanf("%d", &length) != 1 || length < MIN_PASSWORD_LEN || length > MAX_PASSWORD_LEN) {
        fprintf(stderr, "Invalid length.\n");
        goto cleanup;
    }

    int ch = 0;
    while ((ch = getchar()) != '\n' && ch != EOF) {
    }

    if (!read_hidden_line("Master password for encryption: ", master_password, sizeof(master_password)) ||
        strlen(master_password) < MIN_MASTER_PASSWORD_LEN) {
        fprintf(stderr, "Master password must be at least %d characters.\n", MIN_MASTER_PASSWORD_LEN);
        goto cleanup;
    }

    if (!read_hidden_line("Confirm master password: ", master_password_confirm, sizeof(master_password_confirm)) ||
        strcmp(master_password, master_password_confirm) != 0) {
        fprintf(stderr, "Master passwords do not match.\n");
        goto cleanup;
    }

    if (!generate_password(password, (size_t)length)) {
        fprintf(stderr, "Failed to generate a secure password.\n");
        goto cleanup;
    }

    if (!encrypt_password(master_password, label, password, salt, iv, tag, ciphertext, &ciphertext_len)) {
        fprintf(stderr, "Failed to encrypt password.\n");
        goto cleanup;
    }

    if (!store_encrypted_password(DEFAULT_STORE_FILE, label, salt, iv, tag, ciphertext, ciphertext_len)) {
        fprintf(stderr, "Failed to store password in %s.\n", DEFAULT_STORE_FILE);
        goto cleanup;
    }

    printf("Generated password: %s\n", password);
    printf("Saved encrypted record to %s\n", DEFAULT_STORE_FILE);
    exit_code = 0;

cleanup:
    OPENSSL_cleanse(master_password, sizeof(master_password));
    OPENSSL_cleanse(master_password_confirm, sizeof(master_password_confirm));
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
    return exit_code;
}
