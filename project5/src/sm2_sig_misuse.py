from gmssl import sm2, func
import numpy as np

# 初始化SM2对象
private_key = "00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5"
public_key = "B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0445364F8FDBE9C049B4F6F4D4C04967E2D5652A4A542205452DBAF7F4050ED6D66CF4C9C6C479D446B4FE8E247B03A9862E104655D2651E8593FE0247236034C04EA60130CCDBA4E09C9441184698D62494032C7D9591"
sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)

# 两个不同的消息
msg1 = b"Message 1 for SM2 signature test"
msg2 = b"Message 2 for SM2 signature test"

# 错误做法：重用同一个随机数进行签名
k = func.random_hex(sm2_crypt.para_len)  # 生成一个随机数
sign1 = sm2_crypt.sign(msg1, k)  # 使用随机数k签名消息1
sign2 = sm2_crypt.sign(msg2, k)  # 重用随机数k签名消息2

print("消息1的签名:", sign1)
print("消息2的签名:", sign2)

# 从签名中提取r和s值
def parse_signature(sign):
    # 签名格式为r + s，各32字节
    r = int(sign[:64], 16)
    s = int(sign[64:], 16)
    return r, s

r1, s1 = parse_signature(sign1)
r2, s2 = parse_signature(sign2)

# 计算消息哈希
e1 = int(func.hash_msg(msg1, sm2_crypt.para_len), 16)
e2 = int(func.hash_msg(msg2, sm2_crypt.para_len), 16)

# 有限域参数
p = int(sm2_crypt.para['p'], 16)

# 从两个签名推导私钥 (演示目的，实际攻击原理)
# 公式：d = (s1 - s2 + e1 - e2) * (r2 - r1)^(-1) mod p
try:
    numerator = (s1 - s2 + e1 - e2) % p
    denominator = (r2 - r1) % p
    inv_denominator = pow(denominator, p-2, p)  # 费马小定理求逆元
    d_cracked = (numerator * inv_denominator) % p
    
    print("\n通过重用随机数推导出的私钥: 0x%x" % d_cracked)
    print("原始私钥: 0x%s" % private_key)
    print("私钥是否匹配:", hex(d_cracked).upper() == "0X" + private_key)
except Exception as e:
    print("推导过程出错:", e)
