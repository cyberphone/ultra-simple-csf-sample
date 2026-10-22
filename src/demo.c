#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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

u_int8_t buffer[] = {  // The CBOR binary
    0xa3, 0x01, 0x64, 0x64, 0x61, 0x74, 0x61, 0x02, 0x69, 0x6d, 0x6f, 0x72, 
    0x65, 0x20, 0x64, 0x61, 0x74, 0x61, 0xf8, 0x63, 0xa2, 0x01, 0x05, 0x06,
    0x58, 0x20, 0x23, 0x7e, 0x67, 0x4c, 0x7b, 0xe1, 0x81, 0x8d, 0xdd, 0x7e,
    0xaa, 0xcf, 0x40, 0xca, 0x80, 0x41, 0x5b, 0x9a, 0xd8, 0x16, 0x88, 0x07,
    0x51, 0xd2, 0x13, 0x6c, 0x45, 0x38, 0x52, 0x07, 0x42, 0x0c };

const u_int8_t SECRET_KEY[] = {
    0x7f, 0xdd, 0x85, 0x1a, 0x3b, 0x9d, 0x2d, 0xaf, 0xc5, 0xf0, 0xd0, 0x00,
    0x30, 0xe2, 0x2b, 0x93, 0x43, 0x90, 0x0c, 0xd4, 0x2e, 0xde, 0x49, 0x48,
    0x56, 0x8a, 0x4a, 0x2e, 0xe6, 0x55, 0x29, 0x1a };

const int HMAC_256_ALG = 5;
const int HMAC_256_LEN = 32;

int buflen;

void initiate() {
    buflen = 0;
}

void terminate() {
    if (buflen < sizeof(buffer)) {
        printf("Unread buffer data");
        exit(1);
    }
}

u_int8_t getByte() {
    if (buflen >= sizeof(buffer)) {
        printf("Buffer overflow");
        exit(1);
    }
    return buffer[buflen++];
}

typedef struct {
    int len;
    u_int8_t* bytes;
} STRING;

const u_int8_t _OUTER_MAP[] = {0xa3}; 
#define OUTER_MAP sizeof(_OUTER_MAP), _OUTER_MAP

const u_int8_t _CSF_MAP[] = {0xa2}; 
#define CSF_MAP sizeof(_CSF_MAP), _CSF_MAP

const u_int8_t _SIMPLE_99[] = {0xf8, 0x63};
#define SIMPLE_99 sizeof(_SIMPLE_99), _SIMPLE_99

void badItem() {
    printf("Unexpected item");
    exit(1);
}

void getItem(int len, u_int8_t* bytes) {
    while (len--) {
        if (getByte() != *bytes++) {
            badItem();
        }
    }
}

void getKey(u_int8_t key) {
    getItem(1, &key);
}

int32_t _getLen(u_int8_t header) {
    int32_t len = header & 0x1f;
    if (len > 23) {
        if (len == 24) {
            len = getByte();
        } else {
            badItem();   
        }
    }
    return len;
}

void getVariableItem(u_int8_t majorType, STRING* string) {
    u_int8_t header = getByte();
    if ((header & 0xe0) != majorType) {
        badItem();
    }
    int32_t len = _getLen(header);
    string->len = len;
    string->bytes = &buffer[buflen];
    while (len--) {
        getByte();  // Scan away!
    }
}

int32_t getInt32() {
    u_int8_t header = getByte();
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
        STRING arg1;
        getTstr(&arg1);

        getKey(2);
        STRING arg2;
        getTstr(&arg2);

        getItem(SIMPLE_99);

            int csfMap = buflen;
            getItem(CSF_MAP);

                getKey(1);
                int32_t alg = getInt32();

                // We have read all but the signature value.
                // The signed data are the preceding bytes.

                // Decrement CSF map size (SigVal is not a part of signedData).
                buffer[csfMap]--;
                STRING signedData;
                signedData.len = buflen;
                signedData.bytes = buffer;

                getKey(6);
                STRING sigVal;
                getBstr(&sigVal);

    terminate();

    // Everything is format-wise correct.
    printIt(&arg1, false, "First argument");
    printIt(&arg2, false, "Second argument");
    printIt(&signedData, true, "Signed data");
    printf("Algorithm: %d\n", alg);
    printIt(&sigVal, true, "Signature value");

    if (alg != HMAC_256_ALG || sigVal.len != HMAC_256_LEN) {
        printf("Error in alg or sigVal.len");
        exit(1);
    }
    u_int8_t out[HMAC_256_LEN] = {0};
    size_t hmac = hmac_sha256(SECRET_KEY, sizeof(SECRET_KEY), 
                              signedData.bytes, signedData.len, 
                              out, HMAC_256_LEN);
    if (hmac != HMAC_256_LEN || memcmp(out, sigVal.bytes, HMAC_256_LEN)) {
        printf("Signature validation failed");
        exit(1);
    }
    printf("\nSample validated!!!\n");
}