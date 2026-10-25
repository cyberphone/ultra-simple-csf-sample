// https://github.com/cyberphone/ultra-simple-csf-sample/blob/main/src/demo.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
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

void initiate() {
    bufferPosition = 0;
}

void terminate() {
    if (bufferPosition < sizeof(buffer)) {
        printf("Unread buffer data");
        exit(1);
    }
}

uint8_t getByte() {
    if (bufferPosition >= sizeof(buffer)) {
        printf("Buffer overflow");
        exit(1);
    }
    return buffer[bufferPosition++];
}

typedef struct {
    int len;
    uint8_t* bytes;
} STRING;

const uint8_t _OUTER_MAP[] = {0xa3}; 
#define OUTER_MAP sizeof(_OUTER_MAP), _OUTER_MAP

const uint8_t _CSF_MAP[] = {0xa2}; 
#define CSF_MAP sizeof(_CSF_MAP), _CSF_MAP

const uint8_t _SIMPLE_99[] = {0xf8, 0x63};
#define SIMPLE_99 sizeof(_SIMPLE_99), _SIMPLE_99

void badItem() {
    printf("Unexpected item");
    exit(1);
}

void getItem(int len, const uint8_t* bytes) {
    while (len--) {
        if (getByte() != *bytes++) {
            badItem();
        }
    }
}

void getKey(uint8_t key) {
    getItem(1, &key);
}

int32_t _getLen(uint8_t header) {
    int32_t len = header & 0x1f;
    if (len >= 24) switch (len) {
        case 24:
            if ((len = getByte()) >= 24) { 
                break;
            }
        default:
            badItem();
        case 25:
        case 26:
            {
                int32_t q = 1 << (len - 24);
                int32_t mask = 0xffff << (q / 2) * 8;
                len = 0;
                while (q--) {
                    len <<= 8;
                    len += getByte();
                }
                if ((len & mask) == 0) {
                    badItem();
                }
            }
    }
    return len;
}

void getVariableItem(uint8_t majorType, STRING* string) {
    uint8_t header = getByte();
    if ((header & 0xe0) != majorType) {
        badItem();
    }
    int32_t len = _getLen(header);
    string->len = len;
    string->bytes = &buffer[bufferPosition];
    while (len--) {
        getByte();  // Scan away!
    }
}

int32_t getInt32() {
    uint8_t header = getByte();
    int32_t value = _getLen(header);
    if ((header &= 0xe0) == 0x00) {
        return value;
    }
    if (header == 0x20) {
        return ~value;
    }
    badItem();
    return 0;
}

void getTstr(STRING* string) {
    getVariableItem(0x60, string);
}

void getBstr(STRING* string) {
    getVariableItem(0x40, string);
}

void printIt(STRING* data, bool hex, char* description) {
    printf("%s: ", description);
    for (int i = 0; i < data->len; ) {
        printf(hex ? "%02x" : "%c", data->bytes[i++]);
    }
    printf("\n");
}

int main(int argc, char **args) {
    initiate();
    getItem(OUTER_MAP);
    
        getKey(1);
        STRING firstArgument;
        getTstr(&firstArgument);

        getKey(2);
        STRING secondArgument;
        getTstr(&secondArgument);

        getItem(SIMPLE_99);

            int csfMap = bufferPosition;
            getItem(CSF_MAP);

                getKey(1);
                int32_t algorithm = getInt32();

                // We have read all but the signature value.
                // The signed data are the preceding bytes.

                // Decrement CSF map size (signatureValue is not a part of signedData).
                buffer[csfMap]--;
                STRING signedData;
                signedData.len = bufferPosition;
                signedData.bytes = buffer;

                getKey(6);
                STRING signatureValue;
                getBstr(&signatureValue);

    terminate();

    // Everything is format-wise correct.
    printIt(&firstArgument, false, "First argument");
    printIt(&secondArgument, false, "Second argument");
    printIt(&signedData, true, "Signed data");
    printf("Algorithm: %d (COSE HS256)\n", algorithm);
    printIt(&signatureValue, true, "Signature value");

    if (algorithm != COSE_HS256_ALG || signatureValue.len != COSE_HS256_LEN) {
        printf("Error in algorithm or signatureValue.len");
        exit(1);
    }
    uint8_t out[COSE_HS256_LEN];
    size_t hmac = hmac_sha256(HMAC_KEY, sizeof(HMAC_KEY), 
                              signedData.bytes, signedData.len, 
                              out, COSE_HS256_LEN);
    if (hmac != COSE_HS256_LEN || memcmp(out, signatureValue.bytes, COSE_HS256_LEN)) {
        printf("Signature validation failed");
        exit(1);
    }
    printf("\nSample validated!!!\n");
}