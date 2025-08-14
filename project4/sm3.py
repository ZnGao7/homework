import sys
import struct
from typing import List, Tuple, Union

# SM3常量定义
T = [0x79cc4519] * 16 + [0x7a879d8a] * 48

# 初始化向量
IV = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
]

def rotl(x: int, n: int) -> int:
    """循环左移"""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def ff_j(x: int, y: int, z: int, j: int) -> int:
    """布尔函数FF_j"""
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | (x & z) | (y & z)

def gg_j(x: int, y: int, z: int, j: int) -> int:
    """布尔函数GG_j"""
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | ((~x) & z)

def p0(x: int) -> int:
    """置换函数P0"""
    return x ^ rotl(x, 9) ^ rotl(x, 17)

def p1(x: int) -> int:
    """置换函数P1"""
    return x ^ rotl(x, 15) ^ rotl(x, 23)

def padding(message: bytes) -> bytes:
    """消息填充"""
    length = len(message) * 8  # 消息长度(bit)
    message += b'\x80'  # 填充10000000
    
    # 填充0直到满足长度 ≡ 448 mod 512
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    
    # 附加64bit长度信息
    message += struct.pack('>Q', length)
    return message

def message_extension(B: bytes) -> Tuple[List[int], List[int]]:
    """消息扩展"""
    # 将512bit分组转换为16个32bit字
    W = list(struct.unpack('>16I', B))
    
    # 扩展生成W[16..67]
    for j in range(16, 68):
        val = p1(W[j-16] ^ W[j-9] ^ rotl(W[j-3], 15)) ^ rotl(W[j-13], 7) ^ W[j-6]
        W.append(val & 0xFFFFFFFF)
    
    # 生成W'[0..63]
    W_prime = []
    for j in range(64):
        W_prime.append(W[j] ^ W[j+4])
    
    return W, W_prime

def compress_function(V: List[int], B: bytes) -> List[int]:
    """压缩函数"""
    A, B, C, D, E, F, G, H = V
    W, W_prime = message_extension(B)
    
    for j in range(64):
        # 优化：减少临时变量，直接计算
        SS1 = rotl((rotl(A, 12) + E + rotl(T[j], j % 32)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ rotl(A, 12)
        TT1 = (ff_j(A, B, C, j) + D + SS2 + W_prime[j]) & 0xFFFFFFFF
        TT2 = (gg_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = rotl(B, 9)
        B = A
        A = TT1
        H = G
        G = rotl(F, 19)
        F = E
        E = p0(TT2)
    
    # 与初始值异或
    return [
        (A ^ V[0]) & 0xFFFFFFFF,
        (B ^ V[1]) & 0xFFFFFFFF,
        (C ^ V[2]) & 0xFFFFFFFF,
        (D ^ V[3]) & 0xFFFFFFFF,
        (E ^ V[4]) & 0xFFFFFFFF,
        (F ^ V[5]) & 0xFFFFFFFF,
        (G ^ V[6]) & 0xFFFFFFFF,
        (H ^ V[7]) & 0xFFFFFFFF
    ]

def sm3_hash(message: Union[str, bytes], initial_vector: List[int] = None) -> str:
    """计算SM3哈希值，支持自定义初始向量（用于长度扩展攻击）"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # 初始化向量
    V = initial_vector.copy() if initial_vector else IV.copy()
    
    # 消息填充
    padded = padding(message)
    
    # 按512bit分组处理
    for i in range(0, len(padded), 64):
        B = padded[i:i+64]
        V = compress_function(V, B)
    
    # 拼接结果
    return ''.join(f'{x:08x}' for x in V)

# 优化版本：使用预计算和循环展开提升性能
def sm3_hash_optimized(message: Union[str, bytes], initial_vector: List[int] = None) -> str:
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    V = initial_vector.copy() if initial_vector else IV.copy()
    padded = padding(message)
    
    # 循环展开处理分组（每2组处理一次）
    for i in range(0, len(padded), 128):
        # 处理第一组
        if i < len(padded):
            B = padded[i:i+64]
            V = compress_function(V, B)
        
        # 处理第二组
        if i + 64 < len(padded):
            B = padded[i+64:i+128]
            V = compress_function(V, B)
    
    return ''.join(f'{x:08x}' for x in V)
