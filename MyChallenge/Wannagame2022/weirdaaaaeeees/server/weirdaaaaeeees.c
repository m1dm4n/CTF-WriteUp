/*

 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
const int NR = 3;
#define BLOCK_SIZE (16)

const uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

const uint8_t rcon[10] = {1, 2, 4, 8, 16, 32, 64, 128, 27, 54};
/* Initial Permutation Table */
static char IP[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7};

/* Inverse Initial Permutation Table */
static char PI[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25};

/*Expansion table */
static char E[] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1};

/* Post S-Box permutation */
static char P[] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25};

/* The S-Box tables */
static char S[8][64] = {{/* S1 */
                         14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
                        {/* S2 */
                         15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
                        {/* S3 */
                         10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
                        {/* S4 */
                         7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
                        {/* S5 */
                         2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
                        {/* S6 */
                         12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
                        {/* S7 */
                         4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
                        {/* S8 */
                         13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

/* Permuted Choice 1 Table */
static char PC1[] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4};

/* Permuted Choice 2 Table */
static char PC2[] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32};

/* Iteration Shift Array */
static char iteration_shift[] = {
    /* 1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16 */
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

/*
 * The DES function
 * input: 64 bit message
 * key: 64 bit key for encryption
 */
uint64_t bytes_to_dword(const uint8_t a[8])
{
    uint64_t b = 0;
    b |= ((uint64_t)a[0] << 56);
    b |= ((uint64_t)a[0] << 48);
    b |= ((uint64_t)a[0] << 40);
    b |= ((uint64_t)a[0] << 32);
    b |= ((uint64_t)a[0] << 24);
    b |= ((uint64_t)a[0] << 16);
    b |= ((uint64_t)a[0] << 8);
    b |= ((uint64_t)a[0]);
    return b;
}

void dword_to_bytes(const uint64_t a, uint8_t b[8])
{
    b[0] = (uint8_t)((a >> 56) & 0xff);
    b[1] = (uint8_t)((a >> 48) & 0xff);
    b[2] = (uint8_t)((a >> 40) & 0xff);
    b[3] = (uint8_t)((a >> 32) & 0xff);
    b[4] = (uint8_t)((a >> 24) & 0xff);
    b[5] = (uint8_t)((a >> 16) & 0xff);
    b[6] = (uint8_t)((a >> 8) & 0xff);
    b[7] = (uint8_t)(a & 0xff);
}
uint64_t enc1(uint64_t input, uint64_t key)
{

    int i, j;

    /* 8 bits */
    char row, column;

    /* 28 bits */
    uint32_t C = 0;
    uint32_t D = 0;

    /* 32 bits */
    uint32_t L = 0;
    uint32_t R = 0;
    uint32_t s_output = 0;
    uint32_t f_function_res = 0;
    uint32_t temp = 0;

    /* 48 bits */
    uint64_t sub_key[16] = {0};
    uint64_t s_input = 0;

    /* 56 bits */
    uint64_t permuted_choice_1 = 0;
    uint64_t permuted_choice_2 = 0;

    /* 64 bits */
    uint64_t init_perm_res = 0;
    uint64_t inv_init_perm_res = 0;
    uint64_t pre_output = 0;

    /* initial permutation */
    for (i = 0; i < 64; i++)
    {

        init_perm_res <<= 1;
        init_perm_res |= (input >> (64 - IP[i])) & 0x0000000000000001ul;
    }

    L = (uint32_t)(init_perm_res >> 32) & 0x00000000fffffffful;
    R = (uint32_t)init_perm_res & 0x00000000fffffffful;

    /* initial key schedule calculation */
    for (i = 0; i < 56; i++)
    {

        permuted_choice_1 <<= 1;
        permuted_choice_1 |= (key >> (64 - PC1[i])) & 0x0000000000000001ul;
    }

    C = (uint32_t)((permuted_choice_1 >> 28) & 0x000000000fffffff);
    D = (uint32_t)(permuted_choice_1 & 0x000000000fffffff);

    /* Calculation of the 16 keys */
    for (i = 0; i < 16; i++)
    {

        /* key schedule */
        // shifting Ci and Di
        for (j = 0; j < iteration_shift[i]; j++)
        {

            C = (0x0fffffff & (C << 1)) | (0x00000001 & (C >> 27));
            D = (0x0fffffff & (D << 1)) | (0x00000001 & (D >> 27));
        }

        permuted_choice_2 = 0;
        permuted_choice_2 = (((uint64_t)C) << 28) | (uint64_t)D;

        sub_key[i] = 0;

        for (j = 0; j < 48; j++)
        {

            sub_key[i] <<= 1;
            sub_key[i] |= (permuted_choice_2 >> (56 - PC2[j])) & 0x0000000000000001ul;
        }
    }

    for (i = 0; i < 16; i++)
    {

        /* f(R,k) function */
        s_input = 0;

        for (j = 0; j < 48; j++)
        {

            s_input <<= 1;
            s_input |= (uint64_t)((R >> (32 - E[j])) & 0x00000001ul);
        }

        // encryption
        s_input = s_input ^ sub_key[i];
        /* S-Box Tables */
        for (j = 0; j < 8; j++)
        {
            // 00 00 RCCC CR00 00 00 00 00 00 s_input
            // 00 00 1000 0100 00 00 00 00 00 row mask
            // 00 00 0111 1000 00 00 00 00 00 column mask
            row = (char)((s_input & (0x0000840000000000 >> 6 * j)) >> (42 - 6 * j));
            row = (row >> 4) | (row & 0x01);

            column = (char)((s_input & (0x0000780000000000 >> 6 * j)) >> (43 - 6 * j));

            s_output <<= 4;
            s_output |= (uint32_t)(S[j][16 * row + column] & 0x0f);
        }

        f_function_res = 0;

        for (j = 0; j < 32; j++)
        {

            f_function_res <<= 1;
            f_function_res |= (s_output >> (32 - P[j])) & 0x00000001ul;
        }

        temp = R;
        R = L ^ f_function_res;
        L = temp;
    }

    pre_output = (((uint64_t)R) << 32) | (uint64_t)L;

    /* inverse initial permutation */
    for (i = 0; i < 64; i++)
    {

        inv_init_perm_res <<= 1;
        inv_init_perm_res |= (pre_output >> (64 - PI[i])) & 0x0000000000000001ul;
    }

    return inv_init_perm_res;
}
void encencenc(const uint8_t input[BLOCK_SIZE / 2], uint8_t output[BLOCK_SIZE / 2], const uint64_t key1[3])
{
    uint64_t state = bytes_to_dword(input);
    state = enc1(state, key1[0]);
    state = enc1(state, key1[1]);
    state = enc1(state, key1[2]);
    dword_to_bytes(state, output);
}

uint8_t helper1(uint8_t b)
{
    return ((b) << 1) ^ (((b) >> 7) * 0x1b);
}

void helper2(uint8_t state[BLOCK_SIZE])
{
    int i;
    for (i = 0; i < BLOCK_SIZE; i++)
    {
        state[i] = sbox[state[i]];
    }
}

void helper3(uint8_t state[BLOCK_SIZE])
{
    uint8_t tmp1, tmp2;

    tmp1 = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp1;

    tmp1 = state[2];
    tmp2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = tmp1;
    state[14] = tmp2;

    tmp1 = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp1;
}

void mixColumn(uint8_t a[4])
{
    uint8_t t, u, v;

    t = a[0] ^ a[1] ^ a[2] ^ a[3];
    u = a[0];

    v = a[0] ^ a[1];
    v = helper1(v);
    a[0] = a[0] ^ v ^ t;

    v = a[1] ^ a[2];
    v = helper1(v);
    a[1] = a[1] ^ v ^ t;

    v = a[2] ^ a[3];
    v = helper1(v);
    a[2] = a[2] ^ v ^ t;

    v = a[3] ^ u;
    v = helper1(v);
    a[3] = a[3] ^ v ^ t;
}

void helper4(uint8_t state[BLOCK_SIZE])
{
    int i;
    for (i = 0; i < BLOCK_SIZE; i += 4)
    {
        mixColumn(&state[i]);
    }
}

void extend_key(const uint8_t masterkey[BLOCK_SIZE], uint8_t subkeys[176])
{
    int i;

    for (i = 0; i < BLOCK_SIZE; i++)
    {
        subkeys[i] = masterkey[i];
    }

    for (i = 16; i < 176; i += 4)
    {
        if (i % 16 == 0)
        {
            subkeys[i] = sbox[subkeys[i - 3]] ^ rcon[(i >> 4) - 1] ^ subkeys[i - 16];
            subkeys[i + 1] = sbox[subkeys[i - 2]] ^ subkeys[i - 15];
            subkeys[i + 2] = sbox[subkeys[i - 1]] ^ subkeys[i - 14];
            subkeys[i + 3] = sbox[subkeys[i - 4]] ^ subkeys[i - 13];
        }
        else
        {
            subkeys[i] = subkeys[i - 16] ^ subkeys[i - 4];
            subkeys[i + 1] = subkeys[i - 15] ^ subkeys[i - 3];
            subkeys[i + 2] = subkeys[i - 14] ^ subkeys[i - 2];
            subkeys[i + 3] = subkeys[i - 13] ^ subkeys[i - 1];
        }
    }
}

void enc2(const uint8_t input[BLOCK_SIZE], uint8_t output[BLOCK_SIZE], const uint8_t masterkey[BLOCK_SIZE])
{
    int i, round;
    uint8_t state[BLOCK_SIZE];
    uint8_t subkeys[176];
    extend_key(masterkey, subkeys);
    memcpy(state, input, BLOCK_SIZE);

    /* add the first round key */
    for (i = 0; i < BLOCK_SIZE; i++)
    {
        state[i] ^= subkeys[i];
    }

    /* rounds 1 to 9 */
    for (round = 1; round <= NR; round++)
    {
        helper2(state);
        helper3(state);
        helper4(state);
        for (i = 0; i < BLOCK_SIZE; i++)
        {
            state[i] ^= subkeys[round * BLOCK_SIZE + i];
        }
    }

    /* last round */
    helper2(state);
    helper3(state);
    for (i = 0; i < BLOCK_SIZE; i++)
    {
        state[i] ^= subkeys[round * BLOCK_SIZE + i];
    }

    memcpy(output, state, BLOCK_SIZE);
}

void encrypt(const uint8_t input[BLOCK_SIZE], const uint64_t key1[3], const uint8_t key2[16], uint8_t output[BLOCK_SIZE])
{
    encencenc(input, output, key1);
    encencenc(input + 8, output + 8, key1);
    enc2(input, output, key2);
}
void readfirstkey(uint64_t key1[3])
{
    char inp[17];
    for (int i = 0; i < 3; ++i)
    {
        fgets(inp, 17, stdin);
        sscanf(inp, "%lx", key1 + i);
    }
    scanf("%*c");
}
int checkKey(const uint64_t key1, const uint64_t key2, const uint64_t key3)
{
    uint64_t a, b, c;
    a = key1 ^ key2;
    b = key1 ^ key3;
    c = key2 ^ key3;
    if (a == 0 || a == 0xfffffffffffffffful)
        return 0;
    if (b == 0 || b == 0xfffffffffffffffful)
        return 0;
    if (c == 0 || c == 0xfffffffffffffffful)
        return 0;
    return 1;
}
void exit_with_error()
{
    puts("[!] Something went wrong!");
    exit(EXIT_FAILURE);
}
void fill_random(uint8_t *buf, size_t sz)
{
    FILE *fd = fopen("/dev/urandom", "rb");
    if (!fd)
        exit_with_error();
    size_t result = fread(buf, 1, sz, fd);
    if (result != sz)
        exit_with_error();
    fclose(fd);
}
void shuffle(uint8_t *buff, size_t sz) {
    uint32_t i;
    uint32_t *j = malloc(sizeof(uint32_t));
    uint8_t tmp;
    for (i = ((uint32_t)sz) - 1; i >= 1; --i)
    {
        fill_random((uint8_t *)j, sizeof(j));
        *j =  (*j) % (i + 1);
        tmp = buff[*j];
        buff[*j] = buff[i];
        buff[i] = tmp;
    }
    free(j);
}
void PrintBytearray(uint8_t *arr, size_t sz) {
    int i;
    for (i = 0; i < sz; i++)
        printf("%02x", arr[i]);
    putchar(10);
}
int TesingGame(uint8_t pt[BLOCK_SIZE], uint64_t key1[3], uint8_t key2[16])
{
    int i, count = 0, guess;
    uint8_t state[256];
    uint8_t output[BLOCK_SIZE];
    char line[10];
    puts("[-] Initializing my state....");
    for (i = 0; i < 256; ++i)
        state[i] = (uint8_t)i;
    shuffle(state, 256);
    sleep(2);
    // PrintBytearray(state, 256);
    puts("[+] Done. The last number of each plaintext will be the number i'm think about. Try guessing all the number!\n");
    for (i = 0; i < sizeof state; ++i) {
        memset(line, 0, 10);
        guess = 0;
        pt[15] = state[i];
        // puts("Here is your plain test:");
        // PrintBytearray(pt, BLOCK_SIZE);
        encrypt(pt, key1, key2, output);
        puts("Here is your cipher test:");
        PrintBytearray(output, BLOCK_SIZE);
        puts("Your guess:");
        fgets(line, 10, stdin);
        sscanf(line, "%x%*c", &guess);
        // printf("%02x - %02x\n", guess, state[i]);
        if (guess == state[i])
            count += 1;
    }
    return (count == sizeof state);
}
void printEncryptedFlag(const uint64_t key1[3], const uint8_t key2[BLOCK_SIZE])
{
    puts("[+] You have proved yourself that you are very skilled at cryptanalysis. HERE IS YOUR SECRET:");
    size_t sz = 64, i;
    uint8_t FLAG[sz];
    FILE *fd = fopen("flag.txt", "rb");
    if (!fd)
        exit_with_error();
    size_t result = fread(FLAG, 1, sz, fd);
    if (result != sz)
        exit_with_error();
    fclose(fd);
    uint8_t ENCRYPTED_FLAG[sz];
    for (i = 0; i < sz; i += BLOCK_SIZE)
        encrypt(FLAG + i, key1, key2, ENCRYPTED_FLAG + i);
    PrintBytearray(ENCRYPTED_FLAG, sz);
    putchar(10);
}
int main()
{
    // uint64_t input = 0x12e55ad3aa2841aa;
    // uint64_t key1 = 0x3132333435363738;
    // uint64_t key2 = 0xE0FEE0FEF1FEF1FE;
    // uint64_t key3 = 0xFEE0FEE0FEF1FEF1;
    // uint64_t result = input;
    // result = enc1(result, key1);
    // printf ("E: %016lx\n", result);
    // result = enc1(result, key2);
    // printf("E: %016lx\n", result);
    // result = enc1(result, key3);
    // printf("E: %016lx\n", result);

    uint64_t HintKeys[3];
    uint8_t SecretKey[BLOCK_SIZE];
    puts("Since i'm a good guy, i will let you choose key for my first cipher (24 bytes in hexadecimal format)\n[-] Key: ");
    readfirstkey(HintKeys);
    // int i
    // for (int i = 0; i < 3; ++i) {
    //     printf("%016lx\n", HintKeys[i]);
    // }
    //     putchar(10);
    if (!checkKey(HintKeys[0], HintKeys[1], HintKeys[2]))
    {
        puts("[!] I don't like your keys. Bye!");
        exit_with_error();
    }
    puts("Look good!\n");
    puts("You need to prove that you could understand what i'm saying. Now let's the game begin.");
    puts("[-] Initializing my key....");
    fill_random(SecretKey, BLOCK_SIZE);
    sleep(2);
    puts("[+] Done!\n");
    // for (i = 0; i < 16; i++)
    // {
    //     printf("%02x", SecretKey[i]);
    // }
    // putchar(10);
    // printEncryptedFlag(HintKeys, SecretKey);

    uint8_t pt[BLOCK_SIZE];
    int counter = 2;
    while (counter)
    {
        printf("[-] You have %d chance left\n", counter);
        fill_random(pt, 15);
        int check = TesingGame(pt, HintKeys, SecretKey);
        if (check)
        {
            printEncryptedFlag(HintKeys, SecretKey);
            break;
        }
        puts("[!] This is not enough to get my trust. Try again plz!");
        counter -= 1;
    }
    if (counter == 0)
    {
        puts("[!] So dissapointed at you! I will never talk with you again :(((((");
    }
    puts("Bye bye!");
    return 0;
}