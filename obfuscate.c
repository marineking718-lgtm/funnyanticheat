#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* This source is a user-mode (ring 3) helper.  It must not be compiled into
 * the kernel-mode driver, where the C runtime and heap APIs are unavailable. */
#if defined(_KERNEL_MODE) || defined(_NTDDK_) || defined(_WDM_INCLUDED_)
#error "obfuscate.c must be built as a ring-3 user-mode component"
#endif

static void xor_decode(unsigned char *buffer, size_t length, unsigned char key) {
    if (buffer == NULL) {
        return;
    }

    for (size_t i = 0; i < length; ++i) {
        buffer[i] = (unsigned char)(buffer[i] ^ (key + (unsigned char)i + 0x11u));
    }
}

static char *decode_literal(const unsigned char *encoded, size_t length, unsigned char key) {
    if ((encoded == NULL && length != 0u) || length > SIZE_MAX - 1u) {
        return NULL;
    }

    unsigned char *buffer = malloc(length + 1u);
    if (!buffer) {
        return NULL;
    }

    if (length != 0u) {
        memcpy(buffer, encoded, length);
    }
    buffer[length] = '\0';
    xor_decode(buffer, length, key);

    return (char *)buffer;
}

static int run_driver(void) {
    const unsigned char encoded[] = {
        0x4B, 0x5D, 0x4F, 0x41, 0x4A, 0x53, 0x5D, 0x4D,
        0x41, 0x47, 0x4D, 0x4F, 0x5A, 0x49, 0x4B, 0x48,
        0x3A, 0x2F, 0x30, 0x2B, 0x2A, 0x35, 0x2B, 0x39,
        0x2E, 0x31, 0x25, 0x30, 0x2B, 0x3F, 0x24, 0x1D
    };

    const unsigned char key = 0x5Au;
    char *driver_name = decode_literal(encoded, sizeof(encoded), key);
    if (!driver_name) {
        return 1;
    }

    if (puts(driver_name) == EOF) {
        free(driver_name);
        return 1;
    }
    free(driver_name);

    return 0;
}

int main(void) {
    return run_driver();
}
