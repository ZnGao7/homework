import random
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import numpy as np

# 辅助函数：生成一个大素数（简化实现，实际应用中应使用更安全的素数生成）
def generate_prime(bits=256):
    return random.getrandbits(bits) | (1 << (bits - 1)) | 1

# 辅助函数：哈希函数，将元素映射到群G中的元素
def hash_to_group(element, prime):
    element_str = str(element).encode()
    hash_obj = hashlib.sha256(element_str)
    hash_val = int.from_bytes(hash_obj.digest(), byteorder='big')
    return pow(hash_val, 2, prime)  # 确保结果在群中

# 加法同态加密方案（简化版Paillier）
class AdditiveHomomorphicEncryption:
    def __init__(self, key_size=256):
        self.p = generate_prime(key_size)
        self.q = generate_prime(key_size)
        self.n = self.p * self.q
        self.g = self.n + 1
        self.lambda_ = (self.p - 1) * (self.q - 1)
        self.mu = pow(self.lambda_, -1, self.n)  # 模n的逆元
        
        # 公钥和私钥
        self.public_key = (self.n, self.g)
        self.private_key = (self.lambda_, self.mu)
    
    def encrypt(self, m, public_key=None):
        if public_key is None:
            public_key = self.public_key
        n, g = public_key
        r = random.randint(1, n - 1)
        return (pow(g, m, n*n) * pow(r, n, n*n)) % (n*n)
    
    def decrypt(self, c, private_key=None):
        if private_key is None:
            private_key = self.private_key
        n = self.n
        lambda_, mu = private_key
        return ((pow(c, lambda_, n*n) - 1) // n * mu) % n
    
    @staticmethod
    def add(c1, c2, n):
        # 同态加法：c1 + c2 = c1 * c2 mod n^2
        return (c1 * c2) % (n * n)


class Party1:
    def __init__(self, elements, prime=None):
        self.elements = elements  # P1的元素集合V
        self.prime = prime if prime is not None else generate_prime()
        self.k1 = random.randint(1, self.prime - 2)  # 私钥
        
    def round1(self):
        # 对每个元素计算H(v_i)^k1
        processed = []
        for v in self.elements:
            h = hash_to_group(v, self.prime)
            h_k1 = pow(h, self.k1, self.prime)
            processed.append(h_k1)
        
        # 打乱顺序
        random.shuffle(processed)
        return processed
    
    def round3(self, p2_round2_output, z_set):
        n, g = p2_round2_output['public_key']
        w_processed = p2_round2_output['w_processed']
        
        # 对P2发送的每个H(w_j)^k2计算H(w_j)^(k1*k2)
        w_k1k2 = []
        for h_k2, c in w_processed:
            h_k1k2 = pow(h_k2, self.k1, self.prime)
            w_k1k2.append((h_k1k2, c))
        
        # 找到交集：H(w_j)^(k1*k2)在Z集合中的元素
        intersection_ciphertexts = []
        z_set = set(z_set)  # 转换为集合便于查找
        
        for h_k1k2, c in w_k1k2:
            if h_k1k2 in z_set:
                intersection_ciphertexts.append(c)
        
        # 同态求和
        if not intersection_ciphertexts:
            # 如果没有交集，返回0的加密
            aes = AdditiveHomomorphicEncryption()
            return aes.encrypt(0, (n, g))
        
        sum_c = intersection_ciphertexts[0]
        for c in intersection_ciphertexts[1:]:
            sum_c = AdditiveHomomorphicEncryption.add(sum_c, c, n)
        
        return sum_c


class Party2:
    def __init__(self, elements_with_values, prime=None):
        # elements_with_values是形如[(w_j, t_j), ...]的列表
        self.elements = elements_with_values
        self.prime = prime if prime is not None else generate_prime()
        self.k2 = random.randint(1, self.prime - 2)  # 私钥
        self.aes = AdditiveHomomorphicEncryption()  # 加法同态加密
    
    def setup(self):
        # 返回公钥
        return self.aes.public_key
    
    def round2(self, p1_round1_output):
        # 处理P1发送的H(v_i)^k1，计算H(v_i)^(k1*k2)
        z_set = [pow(h_k1, self.k2, self.prime) for h_k1 in p1_round1_output]
        random.shuffle(z_set)  # 打乱顺序
        
        # 处理自己的元素：计算H(w_j)^k2并加密t_j
        w_processed = []
        for w, t in self.elements:
            h = hash_to_group(w, self.prime)
            h_k2 = pow(h, self.k2, self.prime)
            c = self.aes.encrypt(t)
            w_processed.append((h_k2, c))
        
        random.shuffle(w_processed)  # 打乱顺序
        
        return {
            'z_set': z_set,
            'w_processed': w_processed,
            'public_key': self.aes.public_key
        }
    
    def get_result(self, encrypted_sum):
        # 解密得到最终的交集和
        return self.aes.decrypt(encrypted_sum)


def main():
    # 示例数据
    # P1的元素集合V
    p1_elements = ["user1", "user2", "user3", "user5", "user7"]
    # P2的元素集合W，每个元素带有一个数值
    p2_elements = [
        ("user2", 100), 
        ("user4", 200), 
        ("user5", 150), 
        ("user6", 50),
        ("user7", 300)
    ]
    
    # 为了演示，让双方使用相同的素数（实际中可以通过协商得到）
    prime = generate_prime()
    
    # 初始化参与方
    p1 = Party1(p1_elements, prime)
    p2 = Party2(p2_elements, prime)
    
    print("原始数据:")
    print(f"P1的元素: {p1_elements}")
    print(f"P2的元素及其值: {p2_elements}")
    print(f"预期交集: ['user2', 'user5', 'user7']")
    print(f"预期交集和: 100 + 150 + 300 = 550")
    
    # 协议执行
    print("\n开始协议执行...")
    
    # 初始化：P2生成公钥
    public_key = p2.setup()
    
    # 第一轮：P1处理自己的元素并发送给P2
    p1_round1 = p1.round1()
    print("完成第一轮通信")
    
    # 第二轮：P2处理并返回结果
    p2_round2 = p2.round2(p1_round1)
    print("完成第二轮通信")
    
    # 第三轮：P1找到交集并计算加密的和
    encrypted_sum = p1.round3(p2_round2, p2_round2['z_set'])
    print("完成第三轮通信")
    
    # 结果计算：P2解密得到最终结果
    result = p2.get_result(encrypted_sum)
    
    print(f"\n协议计算结果: {result}")


if __name__ == "__main__":
    main()
    