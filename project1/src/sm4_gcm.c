#include <stdint.h>
#include <string.h>
#include <stdio.h>

// SM4算法基础实现（无任何优化）
static const uint8_t Sbox[256] = {
    0xD6,0x90,0xE9,0xFE,0xCC,0xE1,0x3D,0xB7,0x16,0xB6,0x14,0xC2,0x28,0xFB,0x2C,0x05,
    0x2B,0x67,0x9A,0x76,0x2A,0xBE,0x04,0xC3,0xAA,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9C,0x42,0x50,0xF4,0x91,0xEF,0x98,0x7A,0x33,0x54,0x0B,0x43,0xED,0xCF,0xAC,0x62,
    0xE4,0xB3,0x1C,0xA9,0xC9,0x08,0xE8,0x95,0x80,0xDF,0x94,0xFA,0x75,0x8F,0x3F,0xA6,
    0x47,0x07,0xA7,0xFC,0xF3,0x73,0x17,0xBA,0x83,0x59,0x3C,0x19,0xE6,0x85,0x4F,0xA8,
    0x68,0x6B,0x81,0xB2,0x71,0x64,0xDA,0x8B,0xF8,0xEB,0x0F,0x4B,0x70,0x56,0x9D,0x35,
    0x1E,0x24,0x0E,0x5E,0x63,0x58,0xD1,0xA2,0x25,0x22,0x7C,0x3B,0x01,0x21,0x78,0x87,
    0xD4,0x00,0x46,0x57,0x9F,0xD3,0x27,0x52,0x4C,0x36,0x02,0xE7,0xA0,0xC4,0xC8,0x9E,
    0xEA,0xBF,0x8A,0xD2,0x40,0xC7,0x31,0xB1,0x12,0x10,0x59,0x29,0x72,0xC0,0x3B,0xEE,
    0x7B,0xFB,0x7E,0x03,0x1B,0x11,0x0C,0x55,0x6D,0x8D,0x74,0x1F,0x4D,0x2D,0x8E,0x4E,
    0x09,0xCF,0x2F,0x5B,0x66,0xC1,0x1A,0x79,0x6D,0xCD,0x8C,0x9A,0x6E,0x73,0x6F,0xAC,
    0xAA,0xD8,0x32,0x64,0x81,0x90,0x41,0x58,0x28,0x92,0xDA,0x3A,0x0A,0x49,0x06,0x24,
    0x13,0x26,0x49,0x86,0x06,0x99,0x9C,0x42,0x50,0xF4,0x91,0xEF,0x98,0x7A,0x33,0x54,
    0x0B,0x43,0xED,0xCF,0xAC,0x62,0xE4,0xB3,0x1C,0xA9,0xC9,0x08,0xE8,0x95,0x80,0xDF,
    0x94,0xFA,0x75,0x8F,0x3F,0xA6,0x47,0x07,0xA7,0xFC,0xF3,0x73,0x17,0xBA,0x83,0x59,
    0x3C,0x19,0xE6,0x85,0x4F,0xA8,0x68,0x6B,0x81,0xB2,0x71,0x64,0xDA,0x8B,0xF8,0xEB
};

static const uint32_t FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

static const uint32_t CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// 字节替换函数
static uint8_t sm4_sbox(uint8_t x) {
    return Sbox[x];
}

// 线性变换L
static uint32_t sm4_L(uint32_t x) {
    return x ^ ((x << 2) | (x >> 30)) ^ ((x << 10) | (x >> 22)) ^ 
           ((x << 18) | (x >> 14)) ^ ((x << 24) | (x >> 8));
}

// T函数 (S盒 + L变换)
static uint32_t sm4_T(uint32_t x) {
    uint8_t *bytes = (uint8_t *)&x;
    // 对每个字节应用S盒
    bytes[0] = sm4_sbox(bytes[0]);
    bytes[1] = sm4_sbox(bytes[1]);
    bytes[2] = sm4_sbox(bytes[2]);
    bytes[3] = sm4_sbox(bytes[3]);
    // 应用线性变换L
    return sm4_L(x);
}

// 密钥扩展函数
static void sm4_key_extension(const uint8_t *key, uint32_t *rk) {
    uint32_t MK[4];
    uint32_t K[36];
    int i;
    
    memcpy(MK, key, 16);
    
    K[0] = MK[0] ^ FK[0];
    K[1] = MK[1] ^ FK[1];
    K[2] = MK[2] ^ FK[2];
    K[3] = MK[3] ^ FK[3];
    
    for (i = 0; i < 32; i++) {
        uint32_t t = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i];
        // 对t应用S盒
        uint8_t *t_bytes = (uint8_t *)&t;
        t_bytes[0] = sm4_sbox(t_bytes[0]);
        t_bytes[1] = sm4_sbox(t_bytes[1]);
        t_bytes[2] = sm4_sbox(t_bytes[2]);
        t_bytes[3] = sm4_sbox(t_bytes[3]);
        // 轮密钥生成
        K[i+4] = K[i] ^ (t ^ ((t << 13) | (t >> 19)) ^ ((t << 23) | (t >> 9)));
        rk[i] = K[i+4];
    }
}

// SM4单块加密（无优化）
static void sm4_encrypt_block(const uint8_t *key, const uint8_t *input, uint8_t *output, uint32_t *rk) {
    uint32_t X[36];
    int i;
    
    memcpy(X, input, 16);
    
    for (i = 0; i < 32; i++) {
        X[i+4] = X[i] ^ sm4_T(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]);
    }
    
    // 反序输出
    ((uint32_t*)output)[0] = X[35];
    ((uint32_t*)output)[1] = X[34];
    ((uint32_t*)output)[2] = X[33];
    ((uint32_t*)output)[3] = X[32];
}

// ========================== GCM模式实现 =========================

// 128位异或操作
static void xor_128(const uint8_t *a, const uint8_t *b, uint8_t *out) {
    for (int i = 0; i < 16; i++) {
        out[i] = a[i] ^ b[i];
    }
}

// 计数器加1
static void increment_counter(uint8_t *counter) {
    for (int i = 15; i >= 0; i--) {
        if (++counter[i] != 0) break;
    }
}

// GF(2^128)域乘法
static void gf_mult(const uint8_t *a, const uint8_t *b, uint8_t *out) {
    uint8_t p[16] = {0};
    uint8_t tmp[16];
    
    memcpy(tmp, a, 16);
    
    for (int i = 0; i < 128; i++) {
        int bit_pos = 127 - i;
        uint8_t b_bit = (b[bit_pos / 8] >> (7 - (bit_pos % 8))) & 1;
        
        if (b_bit) {
            xor_128(p, tmp, p);
        }
        
        // 左移一位
        uint8_t carry = 0;
        for (int j = 15; j >= 0; j--) {
            uint8_t new_carry = (tmp[j] >> 7) & 1;
            tmp[j] = (tmp[j] << 1) | carry;
            carry = new_carry;
        }
        
        // 若有进位，与不可约多项式异或
        if (carry) {
            tmp[15] ^= 0x87; // x^128 + x^7 + x^2 + x + 1
        }
    }
    
    memcpy(out, p, 16);
}

// GHASH计算
static void ghash(const uint8_t *H, const uint8_t *aad, size_t aad_len,
                 const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *hash) {
    uint8_t state[16] = {0};
    uint8_t block[16] = {0};
    size_t i, len;
    
    // 处理AAD
    for (i = 0; i < (aad_len + 15) / 16; i++) {
        len = (i == (aad_len + 15) / 16 - 1) ? (aad_len % 16) : 16;
        if (len == 0) len = 16;
        
        memcpy(block, aad + i * 16, len);
        if (len < 16) memset(block + len, 0, 16 - len);
        
        xor_128(state, block, state);
        gf_mult(state, H, state);
    }
    
    // 处理密文
    for (i = 0; i < (ciphertext_len + 15) / 16; i++) {
        len = (i == (ciphertext_len + 15) / 16 - 1) ? (ciphertext_len % 16) : 16;
        if (len == 0) len = 16;
        
        memcpy(block, ciphertext + i * 16, len);
        if (len < 16) memset(block + len, 0, 16 - len);
        
        xor_128(state, block, state);
        gf_mult(state, H, state);
    }
    
    // 处理长度块
    uint8_t len_block[16] = {0};
    for (i = 0; i < 8; i++) {
        len_block[i] = (aad_len * 8) >> (56 - i * 8);
        len_block[i + 8] = (ciphertext_len * 8) >> (56 - i * 8);
    }
    
    xor_128(state, len_block, state);
    gf_mult(state, H, state);
    
    memcpy(hash, state, 16);
}

// SM4-GCM加密
int sm4_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *plaintext, size_t plaintext_len,
                   uint8_t *ciphertext, uint8_t *tag, size_t tag_len) {
    if (!key || !iv || !plaintext || !ciphertext || !tag) return -1;
    if (tag_len == 0 || tag_len > 16) return -1;
    if (iv_len != 12) return -1; // 推荐IV长度为12字节
    
    uint32_t rk[32];
    sm4_key_extension(key, rk);
    
    // 生成H = SM4_encrypt(key, 0^128)
    uint8_t H[16] = {0};
    uint8_t zero_block[16] = {0};
    sm4_encrypt_block(key, zero_block, H, rk);
    
    // 生成初始计数器 (IV || 0x00000001)
    uint8_t counter[16];
    memcpy(counter, iv, 12);
    counter[12] = 0x00;
    counter[13] = 0x00;
    counter[14] = 0x00;
    counter[15] = 0x01;
    
    // 生成J0 = SM4_encrypt(key, counter)
    uint8_t J0[16];
    sm4_encrypt_block(key, counter, J0, rk);
    
    // 加密明文
    size_t num_blocks = (plaintext_len + 15) / 16;
    uint8_t keystream[16];
    
    for (size_t i = 0; i < num_blocks; i++) {
        increment_counter(counter);
        sm4_encrypt_block(key, counter, keystream, rk);
        
        size_t len = (i == num_blocks - 1) ? (plaintext_len % 16) : 16;
        if (len == 0) len = 16;
        
        for (size_t j = 0; j < len; j++) {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ keystream[j];
        }
    }
    
    // 计算标签
    uint8_t hash[16];
    ghash(H, aad, aad_len, ciphertext, plaintext_len, hash);
    for (size_t i = 0; i < tag_len; i++) {
        tag[i] = hash[i] ^ J0[i];
    }
    
    return 0;
}

// SM4-GCM解密
int sm4_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *tag, size_t tag_len,
                   uint8_t *plaintext) {
    if (!key || !iv || !ciphertext || !tag || !plaintext) return -1;
    if (tag_len == 0 || tag_len > 16) return -1;
    if (iv_len != 12) return -1;
    
    uint32_t rk[32];
    sm4_key_extension(key, rk);
    
    // 生成H
    uint8_t H[16] = {0};
    uint8_t zero_block[16] = {0};
    sm4_encrypt_block(key, zero_block, H, rk);
    
    // 生成初始计数器和J0
    uint8_t counter[16];
    memcpy(counter, iv, 12);
    counter[12] = 0x00;
    counter[13] = 0x00;
    counter[14] = 0x00;
    counter[15] = 0x01;
    
    uint8_t J0[16];
    sm4_encrypt_block(key, counter, J0, rk);
    
    // 验证标签
    uint8_t hash[16];
    ghash(H, aad, aad_len, ciphertext, ciphertext_len, hash);
    
    uint8_t computed_tag[16];
    for (size_t i = 0; i < 16; i++) {
        computed_tag[i] = hash[i] ^ J0[i];
    }
    
    if (memcmp(computed_tag, tag, tag_len) != 0) {
        return -1; // 标签验证失败
    }
    
    // 解密密文
    size_t num_blocks = (ciphertext_len + 15) / 16;
    uint8_t keystream[16];
    
    for (size_t i = 0; i < num_blocks; i++) {
        increment_counter(counter);
        sm4_encrypt_block(key, counter, keystream, rk);
        
        size_t len = (i == num_blocks - 1) ? (ciphertext_len % 16) : 16;
        if (len == 0) len = 16;
        
        for (size_t j = 0; j < len; j++) {
            plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ keystream[j];
        }
    }
    
    return 0;
}

// 示例使用
int main() {
    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t iv[12] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b};
    uint8_t aad[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    uint8_t plaintext[32] = "sm4-gcmtestandhowareyou";
    uint8_t ciphertext[32];
    uint8_t tag[16];
    uint8_t decrypted[32];
    
    // 加密
    if (sm4_gcm_encrypt(key, iv, 12, aad, 8, plaintext, 32, ciphertext, tag, 16) != 0) {
        printf("加密失败\n");
        return 1;
    }
    
    // 解密
    if (sm4_gcm_decrypt(key, iv, 12, aad, 8, ciphertext, 32, tag, 16, decrypted) != 0) {
        printf("解密失败，标签验证不通过\n");
        return 1;
    }
    
    printf("解密结果: %s\n", decrypted);
    return 0;
}
    