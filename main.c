#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MIN_PASSWORD_LEN 8
#define MAX_PASSWORD_LEN 64
#define DEFAULT_STORE_FILE "passwords.txt"

static int secure_random_bytes(unsigned char *buffer, size_t size) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp == NULL) {
        return 0;
    } //fp = file pointer

    size_t read_count = fread(buffer, 1, size, fp);
    fclose(fp);
    return read_count == size;
}

static void generate_password(char *out, size_t length) {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{};:,.?/|";
    const size_t charset_len = strlen(charset);

    for (size_t i = 0; i < length; i++) {
        unsigned char random_byte = 0;
        if (!secure_random_bytes(&random_byte, 1)) {
            /* Fallback for environments without /dev/urandom */
            random_byte = (unsigned char)(rand() % 256);
        }
        out[i] = charset[random_byte % charset_len];
    }
    out[length] = '\0';
}

static int store_password(const char *filename, const char *label, const char *password) {
    FILE *fp = fopen(filename, "a");
    if (fp == NULL) {
        return 0;
    }

    fprintf(fp, "%s:%s\n", label, password);
    fclose(fp);
    return 1;
}

int main(){
    char label[128];
    int length = 0;

    srand((unsigned int)time(NULL));

    printf("Account/label: ");
    if (fgets(label, sizeof(label), stdin) == NULL) {
        fprintf(stderr, "Failed to read label.\n");
        return 1;
    }

    label[strcspn(label, "\n")] = '\0';
    if (strlen(label) == 0) {
        fprintf(stderr, "Label cannot be empty.\n");
        return 1;
    }

    printf("Password length (%d-%d): ", MIN_PASSWORD_LEN, MAX_PASSWORD_LEN);
    if (scanf("%d", &length) != 1 || length < MIN_PASSWORD_LEN || length > MAX_PASSWORD_LEN) {
        fprintf(stderr, "Invalid length.\n");
        return 1;
    }

    char password[MAX_PASSWORD_LEN + 1];
    generate_password(password, (size_t)length);

    if (!store_password(DEFAULT_STORE_FILE, label, password)) {
        fprintf(stderr, "Failed to store password in %s.\n", DEFAULT_STORE_FILE);
        return 1;
    }

    printf("Generated password: %s\n", password);
    printf("Saved to %s\n", DEFAULT_STORE_FILE);
    return 0;
}
