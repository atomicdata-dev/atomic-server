#include <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Passwords cross stdin/stdout pipes only, never argv or a temporary file. */
int main(int argc, char **argv) {
    const char *service = "io.atomic.codex-bootstrap";
    if (argc != 3 || (strcmp(argv[1], "get") && strcmp(argv[1], "put"))) {
        fprintf(stderr, "Internal usage: keychain get|put <public-agent-id>\n");
        return 2;
    }
    UInt32 size = 0;
    void *password = NULL;
    SecKeychainItemRef item = NULL;
    OSStatus status = SecKeychainFindGenericPassword(NULL, (UInt32)strlen(service), service,
        (UInt32)strlen(argv[2]), argv[2], &size, &password, &item);
    if (!strcmp(argv[1], "get")) {
        if (status == errSecSuccess) {
            size_t written = fwrite(password, 1, size, stdout);
            memset(password, 0, size);
            SecKeychainItemFreeContent(NULL, password);
            CFRelease(item);
            return written == size ? 0 : 1;
        }
    } else {
        unsigned char input[8192];
        size_t length = fread(input, 1, sizeof(input), stdin);
        if (ferror(stdin) || !length || length == sizeof(input)) {
            fprintf(stderr, "Invalid credential input.\n");
            memset(input, 0, sizeof(input));
            return 2;
        }
        if (status == errSecSuccess) {
            memset(password, 0, size);
            SecKeychainItemFreeContent(NULL, password);
            status = SecKeychainItemModifyAttributesAndData(item, NULL, (UInt32)length, input);
            CFRelease(item);
        } else if (status == errSecItemNotFound) {
            status = SecKeychainAddGenericPassword(NULL, (UInt32)strlen(service), service,
                (UInt32)strlen(argv[2]), argv[2], (UInt32)length, input, NULL);
        }
        memset(input, 0, sizeof(input));
        if (status == errSecSuccess) return 0;
    }
    fprintf(stderr, "Keychain operation failed (OSStatus %d). Unlock your login keychain or allow this helper in Keychain Access.\n", (int)status);
    return 1;
}
