#include <strings.h>
#include <stdlib.h>
#include <stdio.h>

#include "hashing_algo.h"
#include "file.h"
#include "sph_md5.h"

void freeHashAlgo(HashAlgorithm *algo) {
    free(algo->ctx);
    free(algo);
}

static HashAlgorithm* createMD5SPH() {
    HashAlgorithm *md5 = (HashAlgorithm*) malloc(sizeof (HashAlgorithm));
    sph_md5_context *md5_context = (sph_md5_context*) malloc(sizeof (sph_md5_context));
    md5->hashType = MD5;
    md5->ctx = (void*) md5_context;
    md5->hashSize = MD5_SIZE;
    md5->toString = md5_toString;
    md5->equals = md5_equal_sph;
    md5->init = md5_init_sph;
    md5->update = md5_update_sph;
    md5->final = md5_final_sph;
    return md5;
}

HashAlgorithm* createHashAlgorithm(char *hashAlgorithm) {
    if (!strcmp("MD5", hashAlgorithm)) {
        return createMD5SPH();
    }
    else {
        return NULL;
    }
}

static void updateHash(void *buffer, unsigned int bytesRead, void *ctx) {
    HashAlgorithm *algo = (HashAlgorithm*) ctx;
    algo->update(algo->ctx, (uchar*) buffer, bytesRead);
}

void getHashFromFile(HashAlgorithm *algo, char *filename, uchar *hash) {
    algo->init(algo->ctx);
    readFile(filename, updateHash, algo);
    algo->final(algo->ctx, hash);
}

void getHashFromStringIter(HashAlgorithm *algo, char *string, uchar *hash, int numIterations) {
    int i = 0;
    algo->init(algo->ctx);
    for (i = 0; i < numIterations; i++) {
        algo->update(algo->ctx, (uchar*) string, strlen(string));
    }
    algo->final(algo->ctx, hash);
}

void getHashFromString(HashAlgorithm *algo, char *string, uchar *hash) {
    getHashFromStringIter(algo, string, hash, 1);
}

static uchar hexCharToBin(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else {
        return 0;
    }
}

static uchar hexToBin(char c1, char c2) {
    uchar temp = 0;
    temp = hexCharToBin(c2);
    temp |= hexCharToBin(c1) << 4;
    return temp;
}

uchar* convertHashStringToBinary(HashAlgorithm *algo, char *hashString) {
   unsigned int i, j;
    uchar *hashBinary = (uchar*) malloc(sizeof (uchar) * algo->hashSize);
    for (i = 0, j = 0; i < algo->hashSize; i++, j += 2) {
        hashBinary[i] = hexToBin(hashString[j], hashString[j + 1]);
    }
    return hashBinary;
}
