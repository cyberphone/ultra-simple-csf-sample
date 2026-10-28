// https://github.com/cyberphone/ultra-simple-csf-sample/blob/main/src/demo.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include "../lib/hmac_sha256.h"

/*
    Decode and verify the integrity of this minimal sample using 
    CBOR Signature Format (CSF).

    Sample expressed in diagnostic notation:

        {
          1: "data",
          2: "more data",
          simple(99): {
            1: 5,
            6: h'237e674c7be1818ddd7eaacf40ca80415b9ad816880751d2136c45385207420c'
          }
        }

*/

uint8_t buffer[] = {  // The CBOR binary
    0xa3, 0x01, 0x64, 0x64, 0x61, 0x74, 0x61, 0x02, 0x69, 0x6d, 0x6f, 0x72, 
    0x65, 0x20, 0x64, 0x61, 0x74, 0x61, 0xf8, 0x63, 0xa2, 0x01, 0x05, 0x06,
    0x58, 0x20, 0x23, 0x7e, 0x67, 0x4c, 0x7b, 0xe1, 0x81, 0x8d, 0xdd, 0x7e,
    0xaa, 0xcf, 0x40, 0xca, 0x80, 0x41, 0x5b, 0x9a, 0xd8, 0x16, 0x88, 0x07,
    0x51, 0xd2, 0x13, 0x6c, 0x45, 0x38, 0x52, 0x07, 0x42, 0x0c };

const uint8_t HMAC_KEY[] = {
    0x7f, 0xdd, 0x85, 0x1a, 0x3b, 0x9d, 0x2d, 0xaf, 0xc5, 0xf0, 0xd0, 0x00,
    0x30, 0xe2, 0x2b, 0x93, 0x43, 0x90, 0x0c, 0xd4, 0x2e, 0xde, 0x49, 0x48,
    0x56, 0x8a, 0x4a, 0x2e, 0xe6, 0x55, 0x29, 0x1a };

#define COSE_HS256_ALG 5
#define COSE_HS256_LEN 32

int bufferPosition;

void failedOperation(char *message, ...) {
    va_list args;
    printf("\n*** ");
    va_start(args, message);
    vprintf(message, args);
    va_end(args);
    printf(" (bufferPosition = %d)\n\n", bufferPosition);
    exit(1);
}

void initiate() {
    bufferPosition = 0;
}

void terminate() {
    if (bufferPosition < sizeof(buffer)) {
        failedOperation("Unread buffer data");
    }
}

uint8_t _getByte() {
    if (bufferPosition >= sizeof(buffer)) {
        failedOperation("Buffer overflow");
    }
    return buffer[bufferPosition++];
}

int32_t _getLength(uint8_t header) {
    int32_t length = header & 0x1f;
    if (length >= 24) switch (length) {
        default:
            failedOperation("Unsupported or invalid length: 0x%02x", length);
        case 24:
        case 25:
        case 26:
            {
                int32_t q = 1 << (length - 24);
                int32_t leadingZeroMask = 0xffff << (q * 4);
                length = 0;
                while (q--) {
                    length <<= 8;
                    length += _getByte();
                }
                if (length & 0x80000000) {
                    failedOperation("Int32 value out of range");
                }
                if ((length & leadingZeroMask) == 0 || length < 24) {
                    failedOperation("Non-deterministically encoded integer");
                }
            }
    }
    return length;
}

int32_t getInt32() {
    uint8_t header = _getByte();
    int32_t value = _getLength(header);
    if ((header &= 0xe0) == 0x00) {
        return value;
    }
    if (header == 0x20) {
        return ~value;
    }
    failedOperation("Expected integer");
    return 0;
}

void getSimple(uint8_t value) {
    if (_getByte() != 0xf8 || _getByte() != value) {
        failedOperation("Expected simple(%d)", value);
    }
}

void getKey(int32_t key) {
    if (key != getInt32()) {
        failedOperation("Expected key: %d", key);
    }
}

int32_t getMap(int32_t elements) {
    int32_t savePos = bufferPosition;
    uint8_t header = _getByte();
    if ((header & 0xe0) != 0xa0 || elements != _getLength(header)) {
        failedOperation("Expected map with %d elements", elements);
    }
    return savePos; 
}

typedef struct {
    int length;
    uint8_t* bytes;
} STRING;

void _getString(uint8_t majorType, STRING* string) {
    uint8_t header = _getByte();
    if ((header & 0xe0) != majorType) {
        failedOperation("Expected string type");
    }
    int32_t length = _getLength(header);
    string->length = length;
    string->bytes = &buffer[bufferPosition];
    while (length--) {
        _getByte();  // Scan away, but check for overrun!
    }
}

void getTstr(STRING* string) {
    _getString(0x60, string);
}

void getBstr(STRING* string) {
    _getString(0x40, string);
}

void printIt(STRING* data, bool hex, char* description) {
    printf("%s: ", description);
    for (int i = 0; i < data->length; ) {
        printf(hex ? "%02x" : "%c", data->bytes[i++]);
    }
    printf("\n");
}

int main(int argc, char **args) {
    initiate();
    getMap(3);
    
        getKey(1);
        STRING firstArgument;
        getTstr(&firstArgument);

        getKey(2);
        STRING secondArgument;
        getTstr(&secondArgument);

        getSimple(99);  // CSF object label

            // Read and verify the size of the CSF map.  Then decrement
            // CSF map size (signatureValue is not a part of signedData).
            buffer[getMap(2)]--;

                getKey(1);  // CSF algorithm label
                int32_t algorithm = getInt32();

                // The signed data constitute of the preceding bytes.
                STRING signedData;
                signedData.length = bufferPosition;
                signedData.bytes = buffer;

                getKey(6); // CSF signatue value label
                STRING signatureValue;
                getBstr(&signatureValue);

    terminate();

    // Everything is format-wise correct.
    printIt(&firstArgument, false, "First argument");
    printIt(&secondArgument, false, "Second argument");
    printIt(&signedData, true, "Signed data");
    printf("Algorithm: %d (COSE HS256)\n", algorithm);
    printIt(&signatureValue, true, "Signature value");

    if (algorithm != COSE_HS256_ALG || signatureValue.length != COSE_HS256_LEN) {
        failedOperation("Error in algorithm or signatureValue.length");
    }
    uint8_t out[COSE_HS256_LEN];
    size_t hmac = hmac_sha256(HMAC_KEY, sizeof(HMAC_KEY), 
                              signedData.bytes, signedData.length, 
                              out, COSE_HS256_LEN);
    if (hmac != COSE_HS256_LEN || memcmp(out, signatureValue.bytes, COSE_HS256_LEN)) {
        failedOperation("Signature validation failed");
    }
    printf("\nSample validated!!!\n");
}