#include <stdint.h>
#include <string.h>
#include "sm4_advanced.h"  // 包含优化后的SM4实现

// GCM模式的上下文结构
typedef struct {
    uint8_t key[16];        // 加密密钥
    uint8_t H[16];          // 哈希子密钥
    uint8_t J0[16];         // 初始计数器
    uint8_t counter[16];    // 当前计数器
    uint8_t tag[16];        // 认证标签
    uint8_t buf[16];        // 缓冲区
    size_t buf_len;         // 缓冲区长度
    size_t auth_len;        // 已认证数据长度
    size_t cipher_len;      // 已加密数据长度
} sm4_gcm_ctx;

// 伽罗瓦域乘法 (GF(2^128))
static void gcm_mult(const uint8_t x[16], const uint8_t y[16], uint8_t res[16]) {
    uint64_t xh, xl, yh, yl;
    uint64_t zh = 0, zl = 0;
    uint8_t v[16];
    int i, j;
    
    // 加载输入到64位变量
    xh = ((uint64_t)x[0] << 56) | ((uint64_t)x[1] << 48) |
         ((uint64_t)x[2] << 40) | ((uint64_t)x[3] << 32) |
         ((uint64_t)x[4] << 24) | ((uint64_t)x[5] << 16) |
         ((uint64_t)x[6] << 8) | x[7];
    xl = ((uint64_t)x[8] << 56) | ((uint64_t)x[9] << 48) |
         ((uint64_t)x[10] << 40) | ((uint64_t)x[11] << 32) |
         ((uint64_t)x[12] << 24) | ((uint64_t)x[13] << 16) |
         ((uint64_t)x[14] << 8) | x[15];
         
    yh = ((uint64_t)y[0] << 56) | ((uint64_t)y[1] << 48) |
         ((uint64_t)y[2] << 40) | ((uint64_t)y[3] << 32) |
         ((uint64_t)y[4] << 24) | ((uint64_t)y[5] << 16) |
         ((uint64_t)y[6] << 8) | y[7];
    yl = ((uint64_t)y[8] << 56) | ((uint64_t)y[9] << 48) |
         ((uint64_t)y[10] << 40) | ((uint64_t)y[11] << 32) |
         ((uint64_t)y[12] << 24) | ((uint64_t)y[13] << 16) |
         ((uint64_t)y[14] << 8) | y[15];
         
    // 伽罗瓦域乘法实现
    for (i = 0; i < 64; i++) {
        if (yl & 1) {
            zh ^= xh;
            zl ^= xl;
        }
        
        int carry = (xl & 1) ? 1 : 0;
        xl >>= 1;
        xl |= (xh & 1) << 63;
        xh >>= 1;
        
        if (carry) {
            xh ^= 0xE100000000000000ULL;  // GCM的不可约多项式
        }
        
        yl >>= 1;
        yl |= (yh & 1) << 63;
        yh >>= 1;
    }
    
    // 存储结果
    for (i = 0; i < 8; i++) {
        v[i] = (zh >> (56 - i * 8)) & 0xFF;
        v[i + 8] = (zl >> (56 - i * 8)) & 0xFF;
    }
    
    memcpy(res, v, 16);
}

// 初始化GCM上下文
int sm4_gcm_init(sm4_gcm_ctx *ctx, const uint8_t *key, size_t key_len,
                 const uint8_t *iv, size_t iv_len,
                 const uint8_t *aad, size_t aad_len) {
    if (key_len != 16) return -1;  // SM4密钥必须是16字节
    
    // 初始化密钥
    memcpy(ctx->key, key, 16);
    
    // 计算哈希子密钥H = SM4_encrypt(0)
    uint8_t zero[16] = {0};
    sm4_encrypt_advanced(key, zero, ctx->H);
    
    // 处理IV，生成初始计数器J0
    if (iv_len == 12) {
        // IV长度为12字节时的特殊处理
        memcpy(ctx->J0, iv, 12);
        ctx->J0[12] = 0x00;
        ctx->J0[13] = 0x00;
        ctx->J0[14] = 0x00;
        ctx->J0[15] = 0x01;
    } else {
        // 通用情况：Hash(IV) || 0^32 || len(IV)
        // 实现省略...
    }
    
    // 初始化当前计数器
    memcpy(ctx->counter, ctx->J0, 16);
    
    // 初始化标签
    memset(ctx->tag, 0, 16);
    
    // 处理附加认证数据(AAD)
    ctx->buf_len = 0;
    ctx->auth_len = 0;
    ctx->cipher_len = 0;
    
    if (aad_len > 0) {
        sm4_gcm_update_aad(ctx, aad, aad_len);
    }
    
    return 0;
}

// 处理附加认证数据
void sm4_gcm_update_aad(sm4_gcm_ctx *ctx, const uint8_t *aad, size_t len) {
    size_t i;
    
    // 处理缓冲区中的剩余数据
    if (ctx->buf_len > 0) {
        size_t fill = 16 - ctx->buf_len;
        if (fill > len) fill = len;
        memcpy(ctx->buf + ctx->buf_len, aad, fill);
        ctx->buf_len += fill;
        aad += fill;
        len -= fill;
        
        if (ctx->buf_len == 16) {
            // 缓冲区满，进行伽罗瓦乘法更新标签
            for (i = 0; i < 16; i++) {
                ctx->tag[i] ^= ctx->buf[i];
            }
            gcm_mult(ctx->tag, ctx->H, ctx->tag);
            ctx->buf_len = 0;
        }
    }
    
    // 处理完整的16字节块
    while (len >= 16) {
        for (i = 0; i < 16; i++) {
            ctx->tag[i] ^= aad[i];
        }
        gcm_mult(ctx->tag, ctx->H, ctx->tag);
        aad += 16;
        len -= 16;
        ctx->auth_len += 16;
    }
    
    // 剩余数据存入缓冲区
    if (len > 0) {
        memcpy(ctx->buf, aad, len);
        ctx->buf_len = len;
        ctx->auth_len += len;
    }
}

// 加密数据
void sm4_gcm_encrypt(sm4_gcm_ctx *ctx, const uint8_t *plaintext, 
                    uint8_t *ciphertext, size_t len) {
    uint8_t keystream[16];
    size_t i;
    
    while (len > 0) {
        // 生成密钥流块
        sm4_encrypt_advanced(ctx->key, ctx->counter, keystream);
        
        // 递增计数器
        for (i = 15; i >= 0; i--) {
            if (++ctx->counter[i] != 0) break;
        }
        
        // 处理数据
        size_t block_len = (len < 16) ? len : 16;
        for (i = 0; i < block_len; i++) {
            ciphertext[i] = plaintext[i] ^ keystream[i];
        }
        
        // 将密文块用于认证
        uint8_t temp[16];
        memset(temp, 0, 16);
        memcpy(temp, ciphertext, block_len);
        
        for (i = 0; i < 16; i++) {
            ctx->tag[i] ^= temp[i];
        }
        gcm_mult(ctx->tag, ctx->H, ctx->tag);
        
        plaintext += block_len;
        ciphertext += block_len;
        len -= block_len;
        ctx->cipher_len += block_len;
    }
}

// 解密数据
void sm4_gcm_decrypt(sm4_gcm_ctx *ctx, const uint8_t *ciphertext, 
                    uint8_t *plaintext, size_t len) {
    uint8_t keystream[16];
    size_t i;
    
    while (len > 0) {
        // 生成密钥流块
        sm4_encrypt_advanced(ctx->key, ctx->counter, keystream);
        
        // 递增计数器
        for (i = 15; i >= 0; i--) {
            if (++ctx->counter[i] != 0) break;
        }
        
        // 先将密文用于认证
        uint8_t temp[16];
        memset(temp, 0, 16);
        size_t block_len = (len < 16) ? len : 16;
        memcpy(temp, ciphertext, block_len);
        
        for (i = 0; i < 16; i++) {
            ctx->tag[i] ^= temp[i];
        }
        gcm_mult(ctx->tag, ctx->H, ctx->tag);
        
        // 解密数据
        for (i = 0; i < block_len; i++) {
            plaintext[i] = ciphertext[i] ^ keystream[i];
        }
        
        ciphertext += block_len;
        plaintext += block_len;
        len -= block_len;
        ctx->cipher_len += block_len;
    }
}

// 完成GCM处理，生成认证标签
void sm4_gcm_final(sm4_gcm_ctx *ctx, uint8_t *tag, size_t tag_len) {
    size_t i;
    
    // 处理缓冲区中剩余的AAD数据
    if (ctx->buf_len > 0) {
        for (i = ctx->buf_len; i < 16; i++) {
            ctx->buf[i] = 0;
        }
        for (i = 0; i < 16; i++) {
            ctx->tag[i] ^= ctx->buf[i];
        }
        gcm_mult(ctx->tag, ctx->H, ctx->tag);
    }
    
    // 处理长度信息
    uint8_t len_block[16];
    memset(len_block, 0, 16);
    
    // 将AAD长度和密文长度编码到len_block
    uint64_t auth_bits = (uint64_t)ctx->auth_len * 8;
    uint64_t cipher_bits = (uint64_t)ctx->cipher_len * 8;
    
    for (i = 0; i < 8; i++) {
        len_block[i] = (auth_bits >> (56 - i * 8)) & 0xFF;
        len_block[i + 8] = (cipher_bits >> (56 - i * 8)) & 0xFF;
    }
    
    // 处理长度块
    for (i = 0; i < 16; i++) {
        ctx->tag[i] ^= len_block[i];
    }
    gcm_mult(ctx->tag, ctx->H, ctx->tag);
    
    // 计算最终标签：tag = tag ^ Encrypt(J0)
    uint8_t j0_encrypted[16];
    sm4_encrypt_advanced(ctx->key, ctx->J0, j0_encrypted);
    
    for (i = 0; i < 16; i++) {
        ctx->tag[i] ^= j0_encrypted[i];
    }
    
    // 输出标签（截断到所需长度）
    if (tag_len > 16) tag_len = 16;
    memcpy(tag, ctx->tag, tag_len);
}
