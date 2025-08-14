from typing import Tuple, Optional

# === SM2 椭圆曲线参数 (sm2p256v1, GM/T 0003.1-2012) ===
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5AEF1353E9DA3113B5F0B8C00A60B1CE1D7E819D7A431
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# === 最小化 SM3 实现 (大端模式) ===
def _rotl32(x, r): return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF
def _P0(x): return x ^ _rotl32(x, 9) ^ _rotl32(x, 17)
def _P1(x): return x ^ _rotl32(x, 15) ^ _rotl32(x, 23)

def sm3(data: bytes) -> bytes:
    # 初始向量
    IV = [0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E]
    msg = bytearray(data)
    bit_len = (8 * len(msg)) & ((1 << 64) - 1)
    # 填充 0x80
    msg.append(0x80)
    while (len(msg) + 8) % 64 != 0:
        msg.append(0)
    msg += bit_len.to_bytes(8, 'big')
    V = IV[:]
    # 分组处理
    for i in range(0, len(msg), 64):
        B = msg[i:i+64]
        W = [int.from_bytes(B[j:j+4], 'big') for j in range(0, 64, 4)]
        for j in range(16, 68):
            W.append(_P1(W[j-16] ^ W[j-9] ^ _rotl32(W[j-3], 15)) ^ _rotl32(W[j-13], 7) ^ W[j-6])
        Wp = [(W[j] ^ W[j+4]) & 0xFFFFFFFF for j in range(64)]
        A,Bc,C,D,E,F,G,H = V
        for j in range(64):
            Tj = 0x79CC4519 if j < 16 else 0x7A879D8A
            FF = (A ^ Bc ^ C) if j < 16 else ((A & Bc) | (A & C) | (Bc & C))
            GG = (E ^ F ^ G) if j < 16 else ((E & F) | ((~E) & G))
            SS1 = _rotl32((_rotl32(A,12) + E + _rotl32(Tj, j % 32)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ _rotl32(A,12)
            TT1 = (FF + D + SS2 + Wp[j]) & 0xFFFFFFFF
            TT2 = (GG + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = _rotl32(Bc,9)
            Bc= A
            A = TT1
            H = G
            G = _rotl32(F,19)
            F = E
            E = _P0(TT2)
        V = [(x ^ y) & 0xFFFFFFFF for x,y in zip(V, [A,Bc,C,D,E,F,G,H])]
    return b''.join(v.to_bytes(4,'big') for v in V)

# === 有限域运算 mod p ===
def inv_mod(x: int, m: int=p) -> int:
    # 费马小定理求逆元（p 是素数）
    return pow(x, m-2, m)

# === Jacobian 坐标系点运算 ===
O = (0, 1, 0)  # 无穷远点 (X:Y:Z)，Z=0 表示无穷远

def to_jac(P: Tuple[int,int]) -> Tuple[int,int,int]:
    if P is None: return O
    x,y = P
    return (x % p, y % p, 1)

def from_jac(PJ: Tuple[int,int,int]) -> Optional[Tuple[int,int]]:
    X,Y,Z = PJ
    if Z == 0: return None
    Zi = inv_mod(Z)
    Zi2 = (Zi*Zi) % p
    x = (X*Zi2) % p
    y = (Y*Zi2*Zi) % p
    return (x, y)

def j_add(P: Tuple[int,int,int], Q: Tuple[int,int,int]) -> Tuple[int,int,int]:
    # Jacobian 坐标点加法
    if P[2]==0: return Q
    if Q[2]==0: return P
    X1,Y1,Z1 = P; X2,Y2,Z2 = Q
    Z1Z1 = (Z1*Z1)%p; Z2Z2 = (Z2*Z2)%p
    U1 = (X1*Z2Z2)%p; U2 = (X2*Z1Z1)%p
    S1 = (Y1*Z2*Z2Z2)%p; S2 = (Y2*Z1*Z1Z1)%p
    if U1 == U2:
        if S1 != S2: return O
        return j_double(P)
    H = (U2-U1)%p
    I = ((2*H)%p)**2 % p
    J = (H*I)%p
    r = (2*(S2-S1))%p
    V = (U1*I)%p
    X3 = (r*r - J - 2*V) % p
    Y3 = (r*(V - X3) - 2*S1*J) % p
    Z3 = ((Z1+Z2)**2 - Z1Z1 - Z2Z2) % p
    Z3 = (Z3*H) % p
    return (X3,Y3,Z3)

def j_double(P: Tuple[int,int,int]) -> Tuple[int,int,int]:
    # Jacobian 坐标点倍加
    X,Y,Z = P
    if Z==0 or Y==0: return O
    A_ = (X*X) % p
    B_ = (Y*Y) % p
    C_ = (B_*B_) % p
    D_ = (2*((X+B_)**2 - A_ - C_)) % p
    E_ = (3*A_ + a*(Z*Z % p * Z*Z % p)) % p
    X3 = (E_*E_ - 2*D_) % p
    Y3 = (E_*(D_ - X3) - 8*C_) % p
    Z3 = (2*Y*Z) % p
    return (X3,Y3,Z3)

# === wNAF 标量乘，G 为固定基点预计算 ===
def naf(k: int, w: int=5):
    # 将 k 表示为 NAF 形式，数字范围 [-2^{w-1}+1, ..., 2^{w-1}-1]
    digits = []
    while k > 0:
        if k & 1:
            di = k & ((1<<w)-1)
            if di >= 1<<(w-1): di -= 1<<w
            k -= di
        else:
            di = 0
        digits.append(di)
        k >>= 1
    return digits

def precompute_G(w: int=5):
    # 预计算奇数倍 G: G, 3G, 5G, ...
    GJ = to_jac((Gx,Gy))
    table = []
    P = GJ
    table.append(P)
    dbl = j_double(GJ)
    for _ in range(1, (1<<(w-1))):
        P = j_add(P, dbl)
        table.append(P)
    return table

_G_TABLE = precompute_G()

def scalar_mul_G(k: int) -> Tuple[int,int]:
    if k % n == 0: return None
    w = 5
    digits = naf(k, w)
    R = O
    for di in reversed(digits):
        R = j_double(R)
        if di != 0:
            idx = (abs(di)//2)
            PJ = _G_TABLE[idx]
            R = j_add(R, PJ if di>0 else (PJ[0], (-PJ[1])%p, PJ[2]))
    return from_jac(R)

def scalar_mul(P: Tuple[int,int], k: int) -> Optional[Tuple[int,int]]:
    if P is None or k % n == 0: return None
    w = 5
    PJ = to_jac(P)
    # 针对任意基点的动态表
    table = [PJ]
    dbl = j_double(PJ)
    for _ in range(1, (1<<(w-1))):
        table.append(j_add(table[-1], dbl))
    digits = naf(k, w)
    R = O
    for di in reversed(digits):
        R = j_double(R)
        if di != 0:
            idx = (abs(di)//2)
            T = table[idx]
            R = j_add(R, T if di>0 else (T[0], (-T[1])%p, T[2]))
    return from_jac(R)

# === 工具函数 ===
def bytes_be(x: int, length: int=32) -> bytes: return x.to_bytes(length, 'big')
def int_be(b: bytes) -> int: return int.from_bytes(b, 'big')

def ZA(ID: bytes, Px: int, Py: int) -> bytes:
    # ENTL = ID 的比特长度
    ENTL = (len(ID)*8).to_bytes(2,'big')
    data = (ENTL + ID + bytes_be(a) + bytes_be(b) +
            bytes_be(Gx) + bytes_be(Gy) + bytes_be(Px) + bytes_be(Py))
    return sm3(data)

def sm2_hash_with_ZA(msg: bytes, ID: bytes, Px: int, Py: int) -> int:
    e = sm3(ZA(ID, Px, Py) + msg)
    return int_be(e) % n

# 基于 RFC6979 的 SM3/SM2 确定性 k（可替换为安全随机数）
import hmac, hashlib
def deterministic_k(d: int, e: int) -> int:
    # 这里用 HMAC-SM3 生成，避免依赖外部库
    def hmac_sm3(key: bytes, data: bytes) -> bytes:
        block = 64
        if len(key) > block: key = sm3(key)
        key = key + b'\x00'*(block-len(key))
        o = bytes([x ^ 0x5c for x in key])
        i = bytes([x ^ 0x36 for x in key])
        return sm3(o + sm3(i + data))
    x = d.to_bytes(32,'big')
    m = e.to_bytes(32,'big')
    V = b'\x01'*32
    K = b'\x00'*32
    K = hmac_sm3(K, V + b'\x00' + x + m)
    V = hmac_sm3(K, V)
    K = hmac_sm3(K, V + b'\x01' + x + m)
    V = hmac_sm3(K, V)
    while True:
        V = hmac_sm3(K, V)
        k = (int_be(V) % n) or 1
        if 1 <= k < n: return k
        K = hmac_sm3(K, V + b'\x00')
        V = hmac_sm3(K, V)

# === SM2 密钥生成 / 签名 / 验证 ===
def sm2_keygen(d: Optional[int]=None) -> Tuple[int, Tuple[int,int]]:
    import secrets
    d = d or (secrets.randbelow(n-1) + 1)
    P = scalar_mul_G(d)
    return d, P

def sm2_sign(msg: bytes, d: int, ID: bytes=b'1234567812345678', P: Optional[Tuple[int,int]]=None) -> Tuple[int,int]:
    P = P or scalar_mul_G(d)
    e = sm2_hash_with_ZA(msg, ID, P[0], P[1])
    while True:
        k = deterministic_k(d, e)
        x1, y1 = scalar_mul_G(k)
        r = (e + x1) % n
        if r == 0 or r + k == n: 
            continue
        s = (inv_mod(1 + d, n) * (k - r*d)) % n
        if s != 0:
            return (r, s)

def sm2_verify(msg: bytes, sig: Tuple[int,int], P: Tuple[int,int], ID: bytes=b'1234567812345678') -> bool:
    r, s = sig
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = sm2_hash_with_ZA(msg, ID, P[0], P[1])
    t = (r + s) % n
    if t == 0: return False
    # 计算 s*G + t*P
    P1 = scalar_mul_G(s)
    P2 = scalar_mul(P, t)
    if P1 is None or P2 is None: return False
    X1, Y1 = P1
    X2, Y2 = P2
    R = from_jac(j_add(to_jac((X1,Y1)), to_jac((X2,Y2))))
    if R is None: return False
    x_, y_ = R
    R_ = (e + x_) % n
    return R_ == r

# === 自测 ===
if __name__ == "__main__":
    d, P = sm2_keygen()
    m = b"hello sm2"
    sig = sm2_sign(m, d, P=P)
    print("签名:", tuple(hex(x) for x in sig))
    print("验证结果: ", sm2_verify(m, sig, P))
