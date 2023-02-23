// https://www.davidwong.fr/blockbreakers/square_4_attack5rounds.html
// https://eprint.iacr.org/2012/280.pdf
#pragma GCC optimize("O3")
#pragma GCC optimize("unroll-loops")
#include <stdio.h>
#include <stdint.h>
#include <fstream>
#include <thread>
#include <vector>
#include <set>
#include "./add_table.inc"
#include "./sub_table.inc"
#include "./mul_table.inc"
using std::set;
using std::thread;
using std::vector;
using BYTE = uint8_t;

const BYTE MAX_GF = 243;
const BYTE MOD = 3;
const BYTE NDIGIT = 5;
const BYTE SBOX[MAX_GF] = {23, 21, 22, 183, 206, 227, 103, 116, 137, 237, 80, 74, 54, 97, 193, 64, 126, 153, 130, 53, 47, 33, 214, 241, 43, 147, 162, 228, 82, 30, 12, 78, 239, 13, 238, 73, 179, 49, 113, 128, 17, 154, 142, 160, 156, 90, 99, 165, 194, 96, 11, 203, 222, 195, 112, 67, 177, 3, 51, 129, 4, 131, 46, 169, 94, 187, 140, 145, 118, 149, 8, 163, 83, 230, 75, 198, 211, 207, 242, 213, 2, 225, 205, 20, 132, 172, 176, 168, 39, 95, 180, 173, 134, 175, 181, 133, 68, 111, 48, 100, 92, 57, 148, 42, 6, 93, 41, 188, 72, 79, 14, 85, 107, 88, 35, 0, 215, 31, 81, 77, 18, 204, 185, 120, 191, 217, 125, 110, 150, 122, 231, 189, 201, 197, 61, 209, 28, 199, 212, 200, 27, 240, 1, 34, 62, 196, 224, 208, 210, 29, 19, 184, 226, 56, 9, 98, 232, 121, 216, 223, 202, 60, 115, 26, 135, 91, 167, 58, 235, 86, 87, 186, 40, 170, 166, 101, 59, 192, 10, 55, 106, 236, 89, 32, 76, 229, 84, 234, 105, 161, 141, 69, 127, 63, 15, 158, 70, 143, 44, 164, 7, 117, 37, 138, 108, 124, 219, 38, 119, 144, 24, 114, 102, 159, 71, 157, 52, 5, 45, 65, 155, 16, 174, 171, 182, 218, 190, 233, 139, 36, 146, 221, 151, 109, 66, 50, 178, 220, 123, 152, 25, 104, 136};
const BYTE INV_SBOX[MAX_GF] = {115, 142, 80, 57, 60, 217, 104, 200, 70, 154, 178, 50, 30, 33, 110, 194, 221, 40, 120, 150, 83, 1, 2, 0, 210, 240, 163, 140, 136, 149, 29, 117, 183, 21, 143, 114, 229, 202, 207, 88, 172, 106, 103, 24, 198, 218, 62, 20, 98, 37, 235, 58, 216, 19, 12, 179, 153, 101, 167, 176, 161, 134, 144, 193, 15, 219, 234, 55, 96, 191, 196, 214, 108, 35, 11, 74, 184, 119, 31, 109, 10, 118, 28, 72, 186, 111, 169, 170, 113, 182, 45, 165, 100, 105, 64, 89, 49, 13, 155, 46, 99, 175, 212, 6, 241, 188, 180, 112, 204, 233, 127, 97, 54, 38, 211, 162, 7, 201, 68, 208, 123, 157, 129, 238, 205, 126, 16, 192, 39, 59, 18, 61, 84, 95, 92, 164, 242, 8, 203, 228, 66, 190, 42, 197, 209, 67, 230, 25, 102, 69, 128, 232, 239, 17, 41, 220, 44, 215, 195, 213, 43, 189, 26, 71, 199, 47, 174, 166, 87, 63, 173, 223, 85, 91, 222, 93, 86, 56, 236, 36, 90, 94, 224, 3, 151, 122, 171, 65, 107, 131, 226, 124, 177, 14, 48, 53, 145, 133, 75, 137, 139, 132, 160, 51, 121, 82, 4, 77, 147, 135, 148, 76, 138, 79, 22, 116, 158, 125, 225, 206, 237, 231, 52, 159, 146, 81, 152, 5, 27, 185, 73, 130, 156, 227, 187, 168, 181, 9, 34, 32, 141, 23, 78};
const BYTE COLUMN_IDX[3][3] = {{0, 3, 6}, {1, 4, 7}, {2, 5, 8}};
const BYTE COLUMN_SHIFT_IDX[3][3] = {{0, 5, 7}, {1, 3, 8}, {2, 4, 6}};
vector<vector<BYTE *>> ciphertexts(5, vector<BYTE *>(MAX_GF));
vector<BYTE> ans(9);

struct GF
{
public:
    BYTE v;
    GF() : v(0) {}
    GF(const BYTE &value)
    {
        this->v = value;
    }
    GF(const GF &value)
    {
        this->v = value.v;
    }
    BYTE add(const BYTE &a, const BYTE &b)
    {
        return ADD_TABLE[a * MAX_GF + b];
    }
    BYTE sub(const BYTE &a, const BYTE &b)
    {
        return SUB_TABLE[a * MAX_GF + b];
    }
    BYTE mul(const BYTE &a, const BYTE &b)
    {
        return MUL_TABLE[a * MAX_GF + b];
    }
    GF operator+(GF &other)
    {
        return GF(add(this->v, other.v));
    }
    GF operator+(const GF &other)
    {
        return GF(add(this->v, other.v));
    }
    GF operator-(GF &other)
    {
        return GF(sub(this->v, other.v));
    }
    GF operator-(const GF &other)
    {
        return GF(sub(this->v, other.v));
    }
    GF operator*(GF &other)
    {
        return GF(mul(this->v, other.v));
    }
    GF operator*(const GF &other)
    {
        return GF(mul(this->v, other.v));
    }
};
struct column
{
    GF a, b, c;
    column() : a(0), b(0), c(0) {}
    column(const BYTE &_a, const BYTE &_b, const BYTE &_c) : a(_a), b(_b), c(_c) {}
    column(const GF &_a, const GF &_b, const GF &_c)
    {
        a.v = _a.v;
        b.v = _b.v;
        c.v = _c.v;
    }
    column operator+(column &other)
    {
        return column(other.a + this->a, other.b + this->b, other.c + this->c);
    }
    column operator-(column &other)
    {
        return column(this->a - other.a, this->b - other.b, this->c - other.c);
    }
    // void print()
    // {
    //     printf("%hu %hu %hu\n", a.v, b.v, c.v);
    // }
};
inline void inv_mix(column &col)
{
    GF x, y, z;
    const BYTE a1 = 86, a2 = 222, a3 = 148;
    x = GF(a1) * col.a + GF(a2) * col.b + GF(a3) * col.c;
    y = GF(a2) * col.a + GF(a3) * col.b + GF(a1) * col.c;
    z = GF(a3) * col.a + GF(a1) * col.b + GF(a2) * col.c;
    col.a = x;
    col.b = y;
    col.c = z;
}
inline void inv_sub(column &col)
{
    col.a.v = INV_SBOX[col.a.v];
    col.b.v = INV_SBOX[col.b.v];
    col.c.v = INV_SBOX[col.c.v];
}
inline GF backup(GF &a, BYTE &b)
{
    return GF(INV_SBOX[(a - GF(b)).v]);
}
bool findPossibleColumnRoundKey(column &rk_guess, const BYTE &ncolumn)
{
    BYTE i, id1 = COLUMN_SHIFT_IDX[ncolumn][0], id2 = COLUMN_SHIFT_IDX[ncolumn][1], id3 = COLUMN_SHIFT_IDX[ncolumn][2];
    column cur_work;
    for (BYTE mix_guess = 0; mix_guess < 243; ++mix_guess)
    {
        bool is_good = true;
        for (BYTE ct_idx = 0; ct_idx < 5; ++ct_idx)
        {
            if (!is_good)
                break;
            GF sum(0);
            for (i = 0; i < MAX_GF; ++i)
            {
                cur_work.a.v = ciphertexts[ct_idx][i][id1];
                cur_work.b.v = ciphertexts[ct_idx][i][id2];
                cur_work.c.v = ciphertexts[ct_idx][i][id3];
                cur_work = cur_work - rk_guess;
                inv_sub(cur_work);
                inv_mix(cur_work);
                sum = sum + backup(cur_work.a, mix_guess);
            }
            if (sum.v != 0)
                is_good = false;
        }
        if (is_good)
            return true;
    }
    return false;
}
void attack(int i)
{
    column state;
    for (int a = 0; a < MAX_GF; ++a)
    {
        state.a = GF(a);
        for (int b = 0; b < MAX_GF; ++b)
        {
            state.b = GF(b);
            for (int c = 0; c < MAX_GF; ++c)
            {
                state.c = GF(c);
                if (findPossibleColumnRoundKey(state, i))
                {
                    ans[COLUMN_SHIFT_IDX[i][0]] = a;
                    ans[COLUMN_SHIFT_IDX[i][1]] = b;
                    ans[COLUMN_SHIFT_IDX[i][2]] = c;
                    // for (int j = 0; j < 3; ++j)
                    // {
                    //     printf("Possible key at index %d: %hu\n", COLUMN_SHIFT_IDX[i][j], ans[COLUMN_SHIFT_IDX[i][j]]);
                    // }
                    return;
                }
            }
        }
    }
}
void fill()
{
    int tmp;
    std::ifstream myfile("input.txt");
    for (int k = 0; k < 5; ++k)
    {
        for (int i = 0; i < MAX_GF; ++i)
        {
            ciphertexts[k][i] = new BYTE[9];
            for (int j = 0; j < 9; ++j)
            {
                myfile >> tmp;
                ciphertexts[k][i][j] = BYTE(tmp);
            }
        }
    }
    myfile.close();
    // for (auto i : ciphertexts) {
    //     for (BYTE a = 0; a < 9; ++a)
    //         cout << (int)i[a] << ' ';
    //     cout << '\n';
    // }
}
int main()
{
    fill();
    // local debug key: [GF(35), GF(112), GF(130), GF(138), GF(229), GF(173), GF(213), GF(152), GF(152)]
    auto t0 = thread(&attack, 0);
    auto t1 = thread(&attack, 1);
    auto t2 = thread(&attack, 2);
    t0.join();
    t1.join();
    t2.join();
    for (const BYTE &i : ans)
        printf("%hu ", i);
    putchar(10);
    return 0;
}