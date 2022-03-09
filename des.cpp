#include<iostream>
#include<cstdio>
#include<cstring>
#include<algorithm>
#include<climits>
#include<cmath>
#include<queue>

#include "des.h"

int main() {
    char ClearWord[] = "明文";
    char ClearText[10];           // 8字节字符明文
    bool ClearText_B[64];         // 64位明文
    
    char CipherWord[] = "密文";
    char CipherText[10];          // 8字节字符密文
    bool CipherText_B[64];        // 64位密文
    
    char ClearWord2[] = "解密";
    char ClearText2[10];          // 8字节字符解密
    bool ClearText2_B[64];        // 64位解密
    
    char KeyWord[] = "密钥";
    char KEY_C[10];               // 8字节字符密钥
    bool KEY_B[64];               // 64位密钥
    bool SUBKEY[16][48];         // 存放16轮48位子密钥
    
    puts("请输入长度为 8 个字符的明文：");
    scanf("%s", ClearText);
    puts("请指定长度为 8 个字符的密钥：");
    scanf("%s", KEY_C);

    puts("\n初始信息：\n");
    ByteToBit(ClearText_B, ClearText, 8);
    print_result(ClearWord, ClearText, ClearText_B);
    
    SETKEY(KEY_C, KEY_B);

    puts("\n开始设置子密钥：\n");
    Set_SubKey(SUBKEY, KEY_B);
    puts("\n子密钥设置完毕：\n");
    print_result(KeyWord, KEY_C, KEY_B);
    
    puts("\n开始加密：\n");
    DES(CipherText, ClearText, SUBKEY, true);
    
    puts("\n加密结果：\n");
    ByteToBit(CipherText_B, CipherText, 8);
    print_result(CipherWord, CipherText, CipherText_B);
    
    puts("\n开始解密：\n");
    DES(ClearText2, CipherText, SUBKEY, false);

    puts("\n解密结果：\n");
    ByteToBit(ClearText2_B, ClearText2, 8);
    print_result(ClearWord2, ClearText2, ClearText2_B);
    
    return 0;
}

void print_result(char* word, char* text, bool* bits)
{
    printf("%s：%s\n", word, text);
    printf("%s：", word);
    for (int i=0; i<8; i++) {
        int val = 0;
        for (int j=0; j<8; j++) {
            val = (val<<1) | bits[i*8+j];
        }
        printf("0x%x ", val);
        // printf("%c ", val);
    }
    printf("\n");
    printf("%s：", word);
    for (int i=0; i<64; i++) {
        printf("%d", bits[i]);
    }
    printf("\n");
}

bool flag = true;

void print_bool(char* s, const bool *out, int len){
    printf("%s: ", s);
    for (int i=0; i<len; i++) {
        printf("%d", out[i]);
    }
    printf("\n");
}

void show(char name[10], const bool * arr, int len) {
    printf("%s:\n", name);
    for (int i = 0; i < len; ++i) {
        printf("%d", arr[i]);
    }
    putchar('\n');
}

void SETKEY(const char Key_C[8], bool Key_B[64])
{
    for (int i = 0; i < 8; ++i) {
        int t = Key_C[i];
        for (int j = 7; j >= 0; --j, t >>= 1) {
            Key_B[i*8+j] = t&1;
        }
    }
}

void ByteToBit(bool *Outs, const char *In, int bits)
{
    for (int i = 0; i < 8; ++i) {
        int t = In[i];
        for (int j = bits-1; j >= 0; --j, t >>= 1) {
            Outs[i*bits+j] = t&1;
        }
    }
}

void BitToByte(char *Outs, const bool *In, int bits)
{
    for (int i = 0; i < 8; ++i) {
        int t = 0;
        for (int j = 0; j < bits; ++j) {
            t = (t<<1) | In[i*bits+j];
        }
        Outs[i] = (char)t;
    }
    Outs[8] = '\0';
}


void CYCLELEFT(bool *In, int len, int loop)                         // 循环左移函数
{
    bool temp[len];
    for (int i = 0; i < len; ++i) {
        temp[i] = In[i];
    }
    for (int i = 0, j = loop; j < len; ++i, ++j) {
        In[i] = temp[j];
    }
    for (int i = len-loop, j = 0; i < len; ++i, ++j) {
        In[i] = temp[j];
    }
}

void Set_SubKey(bool subKey[16][48], bool Key[64])                  // 设置子密钥
{
    bool key[56];
    show("密钥置换前", Key, 64);
    for (int i = 0; i < 56; ++i) {
        key[i] = Key[TRANS_64to56[i]-1];
    }
    show("密钥置换后", key, 64);
    bool * C = key, * D = key + 28;
    show("\n循环移动开始\n初始状态", key, 56);
    for (int k = 0; k < 16; ++k) {
        CYCLELEFT(C, 28, SHIFT_TAB[k]);
        CYCLELEFT(D, 28, SHIFT_TAB[k]);
        printf("第 %d ", k + 1);
        show("循环移动后，压缩置换前", key, 56);
        for (int i = 0; i < 48; ++i) {
            subKey[k][i] = key[TRANS_56to48[i]-1];
        }
        show("压缩置换后", subKey[k], 48);
    }
}

void XOR(bool *InA, const bool *InB, int len)                       // 异或函数
{
    for (int i = 0; i < len; ++i) {
        InA[i] ^= InB[i];
    }
}

void S_BOXF(bool Out[32], const bool In[48])// S-盒代替函数
{
    for (int k = 0, rank = 0, n = 0; k < 48; k += 6) {
        int i = 2*In[k] + In[k+5];
        int j = 8*In[k+1] + 4*In[k+2] + 2*In[k+3] + In[k+4];
        int t = S_BOX[n++][i][j];
        for (int m = 3; m >= 0; --m) {
            Out[rank++] = (t>>m)&1;
        }
    }
}

void F_FUNCTION(bool In[32], const bool Ki[48]) // f 函数完成扩展置换、S-盒代替和P盒置换
{
    // 第一步：扩展置换，32 -> 48
    bool E[48];
    show("扩展置换前", In, 32);
    for (int i = 0; i < 48; ++i) {
        E[i] = In[EXPAND_32to48[i]-1];
    }
    XOR(E, Ki, 48);
    show("扩展置换后", Ki, 48);
    bool S[32];
    show("S 盒代替前", S, 32);
    S_BOXF(S, E);
    for (int i = 0; i < 32; ++i) {   // give back P
        In[i] = S[TRANS_32to32[i]-1];
    }
    show("S 盒代替后", S, 32);
}

void DES(char Out[8], char In[8], const bool subKey[16][48], bool Type)  // 标准DES Type: True加密/False解密
{
    bool M[64], IP[64];
    ByteToBit(M, In, 8);
    show("初始置换前", M, 64);
    for (int i = 0; i < 64; ++i) {
        IP[i] = M[TRANS_INIT[i]-1];
    }
    show("初始置换后", IP, 64);
    bool * L = IP, * R = IP + 32;   // 使用指针进行 16 轮迭代
    bool Rt[32];
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 32; ++j) {
            Rt[j] = R[j];
        }
        F_FUNCTION(Rt, subKey[Type ? i : 15-i]);
        XOR(L, Rt, 32);
    }
    bool ans[64];
    show("结尾置换前", ans, 64);
    for (int i = 0; i < 64; ++i) {
        ans[i] = IP[TRANS_END[i]-1];
    }
    show("结尾置换后", ans, 64);
    BitToByte(Out, ans, 8);
}