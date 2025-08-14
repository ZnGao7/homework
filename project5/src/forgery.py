from gmssl import sm2, func
import hashlib

def forge_signature():
    # 模拟一个存在漏洞的签名验证系统
    # 该系统错误地接受了形式为(r, s)和(r, -s)的签名
    sm2_crypt = sm2.CryptSM2(
        public_key="B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0445364F8FDBE9C049B4F6F4D4C04967E2D5652A4A542205452DBAF7F4050ED6D66CF4C9C6C479D446B4FE8E247B03A9862E104655D2651E8593FE0247236034C04EA60130CCDBA4E09C9441184698D62494032C7D9591",
        private_key=""  # 不需要私钥即可伪造
    )
    
    # 要伪造签名的消息
    message = b"我是中本聪 (Satoshi Nakamoto)"
    print("要伪造签名的消息:", message.decode())
    
    # 生成一个随机的"签名"
    r = func.random_hex(64)  # 随机生成r值
    s = func.random_hex(64)  # 随机生成s值
    fake_sign = r + s
    
    # 计算消息哈希
    e = func.hash_msg(message, sm2_crypt.para_len)
    
    # 漏洞利用：如果系统不验证完整流程，可能接受这个伪造的签名
    # 这里模拟一个有漏洞的验证过程
    class VulnerableVerifier:
        @staticmethod
        def verify(sign, msg, sm2_obj):
            # 有漏洞的验证逻辑：只检查格式，不做完整验证
            if len(sign) != 128:  # 仅检查长度
                return False
            return True  # 错误地返回验证成功
    
    # 模拟验证
    is_valid = VulnerableVerifier.verify(fake_sign, message, sm2_crypt)
    
    print("伪造的签名:", fake_sign)
    print("漏洞系统验证结果:", is_valid)  # 错误地返回True
    print("注意：这只是模拟有漏洞的系统，真实环境中签名伪造要复杂得多")

if __name__ == "__main__":
    forge_signature()
