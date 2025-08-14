from sm3 import sm3_hash, padding, IV
import struct

# 将哈希字符串转成初始向量格式
def parse_hash(hash_str: str) -> list:
    return [int(hash_str[i:i+8], 16) for i in range(0, 64, 8)]

# 长度扩展攻击函数
def length_extension_attack(original_hash: str, original_len: int, append_data: bytes) -> tuple:
    # 解析原始哈希为初始向量
    initial_vector = parse_hash(original_hash)
    
    # 计算原始消息的填充
    original_message = b'x' * original_len  # 不需要知道真实消息内容
    padded_original = padding(original_message)
    padding_len = len(padded_original) - original_len
    
    # 构造扩展消息
    extended_message = original_message + padded_original[original_len:] + append_data
    
    # 从原始哈希继续计算附加数据的哈希
    forged_hash = sm3_hash(append_data, initial_vector)
    
    return forged_hash, extended_message

# 验证长度扩展攻击
def verify_length_extension():
    # 原始消息
    original_message = b"secret"
    original_len = len(original_message)
    original_hash = sm3_hash(original_message)
    print(f"原始消息: {original_message}")
    print(f"原始哈希: {original_hash}")
    
    # 要附加的数据
    append_data = b"extension"
    
    # 执行长度扩展攻击
    forged_hash, extended_message = length_extension_attack(original_hash, original_len, append_data)
    print(f"扩展消息长度: {len(extended_message)}字节")
    
    # 计算真实的扩展消息哈希（用于验证）
    true_extended_hash = sm3_hash(extended_message)
    print(f"真实扩展哈希: {true_extended_hash}")
    print(f"伪造扩展哈希: {forged_hash}")
    
    # 验证攻击是否成功
    if forged_hash == true_extended_hash:
        print("长度扩展攻击验证成功!")
    else:
        print("长度扩展攻击验证失败!")

if __name__ == "__main__":
    verify_length_extension()
