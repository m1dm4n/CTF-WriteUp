#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// /algorithms is not challenge relevant
#include "algorithms/Blake2b/blake2b.h"
#include "algorithms/sha256/sha256.h"

typedef unsigned char byte;



struct Bytearray
{
    int sz;
    byte *data;
};

void hash1(struct Bytearray *input)
{
    SHA256_CTX ctx;
    byte outbuf[32];

    sha256_init(&ctx);
    sha256_update(&ctx, input->data, input->sz);
    sha256_final(&ctx, outbuf);
    memcpy(input->data, outbuf, 16);
}

void hash2(struct Bytearray *input)
{
    for (int i = 0; i < 50; i++)
    {
        blake2b(input->data, 16, input->data, input->sz, 0, 0);
    }
}

int countbits(byte b)
{
    int count = 0;
    while (b)
    {
        count += b & 1;
        b >>= 1;
    }
    return count;
}

char *to_hexstring(const struct Bytearray *ba)
{
    char *outstr = malloc(ba->sz * 2);

    for (int i = 0; i < ba->sz; i++)
    {
        char hexrep[3];

        snprintf(hexrep, 3, "%02x", ba->data[i]);

        outstr[i * 2] = hexrep[0];
        outstr[i * 2 + 1] = hexrep[1];
    }
    return outstr;
}

struct Bytearray *from_hexstring(char *hstring)
{
    int num_bytes = strlen(hstring) / 2;

    struct Bytearray *ret = malloc(sizeof(struct Bytearray));
    ret->sz = num_bytes;
    ret->data = malloc(num_bytes);

    for (int i = 0; i < num_bytes; i++)
    {
        unsigned char byt;
        int chars_processed;
        int error = 0;

        if (sscanf(&hstring[i * 2], "%2hhx%n", &byt, &chars_processed) != 1)
        {
            error = 1;
        }
        else if (chars_processed != 2)
        {
            error = 1;
        }
        ret->data[i] = byt;
    }
    return ret;
}

void hmac(byte *key, struct Bytearray *plain)
{
    struct Bytearray *state = from_hexstring("0000000000000000ffffffffffffffff");

    int original_size = plain->sz;

    int num_blocks = plain->sz / 16;

    for (int blocknum = 0; blocknum < num_blocks; blocknum++)
    {

        for (int i = 0; i < 16; i++)
        {
            int offset = blocknum * 16 + i;

            byte kbyte = key[i];
            byte pbyte = plain->data[offset];
            byte res = kbyte ^ pbyte;

            state->data[i] = state->data[i] ^ key[i];

            if (countbits(res) >= 4)
            {
                hash1(state);
            }
            else
            {
                hash2(state);
            }
        }
    }
    printf("%s\n", to_hexstring(state));
}


int main(int argc, char **argv)
{
    if (argc < 3)
    {
        printf("using: ./enc key data\n");
        exit(1);
    }
    struct Bytearray *sesskey = from_hexstring((char *)argv[1]);
    struct Bytearray *plain = from_hexstring((char *)argv[2]);

    hmac(sesskey->data, plain);
    
    return 0;
}
