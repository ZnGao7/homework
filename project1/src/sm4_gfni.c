#include <stdint.h>
#include <string.h>
#include <immintrin.h>  // 包含GFNI和VPROLD等指令

// SM4常量 (与前面实现相同)
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

// S盒用于GFNI操作
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
    0xAA,0xD8,0x32,0x64,0x81,0x90,0x41,0x58,0x28,0x92,0xDA,0x3A,0x0A,0x49,0x06,0x24
};

// 使用GFNI指令进行S盒替换
static __m128i sm4_sbox_gfni(__m128i x) {
    // 使用GF2P8AFFINEQB指令执行仿射变换
    __m128i mask = _mm_set1_epi8(0x80); // 仿射变换的掩码
    return _mm_gf2p8affineqb_epi64_epi8(x, _mm_loadu_si128((const __m128i*)Sbox), mask);
}

// 使用VPROLD指令优化的线性变换L
static __m128i sm4_L_gfni(__m128i x) {
    // 使用VPROLD进行循环左移
    __m128i x2 = _mm_rol_epi32(x, 2);    // 左移2位
    __m128i x10 = _mm_rol_epi32(x, 10);  // 左移10位
    __m128i x18 = _mm_rol_epi32(x, 18);  // 左移18位
    __m128i x24 = _mm_rol_epi32(x, 24);  // 左移24位
    
    // 组合所有结果
    __m128i result = _mm_xor_si128(x, x2);
    result = _mm_xor_si128(result, x10);
    result = _mm_xor_si128(result, x18);
    result = _mm_xor_si128(result, x24);
    
    return result;
}

// 密钥扩展函数的GFNI优化实现
static void sm4_key_extension_gfni(const uint8_t *key, __m128i rk[32]) {
    __m128i MK = _mm_loadu_si128((const __m128i*)key);
    __m128i FK_ni = _mm_setr_epi32(FK[0], FK[1], FK[2], FK[3]);
    
    // 初始化密钥
    __m128i K[36];
    K[0] = _mm_xor_si128(_mm_shuffle_epi32(MK, _MM_SHUFFLE(0,0,0,0)), 
                        _mm_shuffle_epi32(FK_ni, _MM_SHUFFLE(0,0,0,0)));
    K[1] = _mm_xor_si128(_mm_shuffle_epi32(MK, _MM_SHUFFLE(1,1,1,1)), 
                        _mm_shuffle_epi32(FK_ni, _MM_SHUFFLE(1,1,1,1)));
    K[2] = _mm_xor_si128(_mm_shuffle_epi32(MK, _MM_SHUFFLE(2,2,2,2)), 
                        _mm_shuffle_epi32(FK_ni, _MM_SHUFFLE(2,2,2,2)));
    K[3] = _mm_xor_si128(_mm_shuffle_epi32(MK, _MM_SHUFFLE(3,3,3,3)), 
                        _mm_shuffle_epi32(FK_ni, _MM_SHUFFLE(3,3,3,3)));
    
    // 生成轮密钥
    for (int i = 0; i < 32; i++) {
        __m128i t = _mm_xor_si128(_mm_xor_si128(K[i+1], K[i+2]), K[i+3]);
        t = _mm_xor_si128(t, _mm_set1_epi32(CK[i]));
        
        // 使用GFNI进行S盒替换
        t = sm4_sbox_gfni(t);
        
        // 使用VPROLD进行循环移位
        __m128i t13 = _mm_rol_epi32(t, 13);
        __m128i t23 = _mm_rol_epi32(t, 23);
        
        __m128i temp = _mm_xor_si128(t, _mm_xor_si128(t13, t23));
        
        K[i+4] = _mm_xor_si128(K[i], temp);
        rk[i] = K[i+4];
    }
}

// 使用GFNI和VPROLD优化的SM4加密函数
void sm4_encrypt_gfni(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    __m128i X[36];
    __m128i rk[32];
    int i;
    
    // 密钥扩展
    sm4_key_extension_gfni(key, rk);
    
    // 加载输入
    X[0] = _mm_cvtsi32_si128(((const uint32_t*)input)[0]);
    X[1] = _mm_cvtsi32_si128(((const uint32_t*)input)[1]);
    X[2] = _mm_cvtsi32_si128(((const uint32_t*)input)[2]);
    X[3] = _mm_cvtsi32_si128(((const uint32_t*)input)[3]);
    
    // 32轮迭代
    for (i = 0; i < 32; i++) {
        __m128i t = _mm_xor_si128(_mm_xor_si128(X[i+1], X[i+2]), _mm_xor_si128(X[i+3], rk[i]));
        
        // 使用GFNI进行S盒替换
        t = sm4_sbox_gfni(t);
        
        // 使用VPROLD进行线性变换L
        t = sm4_L_gfni(t);
        
        // 轮函数输出
        X[i+4] = _mm_xor_si128(X[i], t);
    }
    
    // 存储输出
    ((uint32_t*)output)[0] = _mm_cvtsi128_si32(X[35]);
    ((uint32_t*)output)[1] = _mm_cvtsi128_si32(X[34]);
    ((uint32_t*)output)[2] = _mm_cvtsi128_si32(X[33]);
    ((uint32_t*)output)[3] = _mm_cvtsi128_si32(X[32]);
}

// 使用GFNI和VPROLD优化的SM4解密函数
void sm4_decrypt_gfni(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    __m128i X[36];
    __m128i rk[32];
    int i;
    
    // 密钥扩展
    sm4_key_extension_gfni(key, rk);
    
    // 加载输入
    X[0] = _mm_cvtsi32_si128(((const uint32_t*)input)[0]);
    X[1] = _mm_cvtsi32_si128(((const uint32_t*)input)[1]);
    X[2] = _mm_cvtsi32_si128(((const uint32_t*)input)[2]);
    X[3] = _mm_cvtsi32_si128(((const uint32_t*)input)[3]);
    
    // 32轮迭代，使用逆序的轮密钥
    for (i = 0; i < 32; i++) {
        __m128i t = _mm_xor_si128(_mm_xor_si128(X[i+1], X[i+2]), _mm_xor_si128(X[i+3], rk[31-i]));
        
        // 使用GFNI进行S盒替换
        t = sm4_sbox_gfni(t);
        
        // 使用VPROLD进行线性变换L
        t = sm4_L_gfni(t);
        
        // 轮函数输出
        X[i+4] = _mm_xor_si128(X[i], t);
    }
    
    // 存储输出
    ((uint32_t*)output)[0] = _mm_cvtsi128_si32(X[35]);
    ((uint32_t*)output)[1] = _mm_cvtsi128_si32(X[34]);
    ((uint32_t*)output)[2] = _mm_cvtsi128_si32(X[33]);
    ((uint32_t*)output)[3] = _mm_cvtsi128_si32(X[32]);
}
