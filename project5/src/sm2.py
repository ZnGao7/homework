from gmssl import sm2, func
import random

# 生成密钥对
private_key = "00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5"
public_key = "B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0445364F8FDBE9C049B4F6F4D4C04967E2D5652A4A542205452DBAF7F4050ED6D66CF4C9C6C479D446B4FE8E247B03A9862E104655D2651E8593FE0247236034C04EA60130CCDBA4E09C9441184698D62494032C7D9591"

# 初始化SM2对象
sm2_crypt = sm2.CryptSM2(
    public_key=public_key, 
    private_key=private_key
)

# 待加密数据
data = b"Hello SM2 Algorithm"
print("原始数据:", data.decode())

# 加密
enc_data = sm2_crypt.encrypt(data)
print("加密后数据:", enc_data.hex())

# 解密
dec_data = sm2_crypt.decrypt(enc_data)
print("解密后数据:", dec_data.decode())

# 签名
random_hex_str = func.random_hex(sm2_crypt.para_len)
sign = sm2_crypt.sign(data, random_hex_str)
print("签名结果:", sign)

# 验签
verify = sm2_crypt.verify(sign, data)
print("验签结果:", verify)  # True为验签成功，False为失败
