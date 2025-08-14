from sm3 import sm3_hash_optimized
import math
from typing import List, Tuple, Optional

class MerkleTree:
    # 初始化Merkle树，leaves 表示叶子节点数据列表
    def __init__(self, leaves: List[bytes]):
        self.leaves = leaves
        self.leaf_hashes = [sm3_hash_optimized(leaf) for leaf in leaves]
        self.tree = self.build_tree()
        self.root = self.tree[0][0] if self.tree else ""
    
    # 构建Merkle树
    def build_tree(self) -> List[List[str]]:
        if not self.leaf_hashes:
            return []
            
        # 树的每一层，从叶子开始
        tree = [self.leaf_hashes.copy()]
        
        # 构建上层节点直到根节点
        while len(tree[-1]) > 1:
            current_level = tree[-1]
            next_level = []
            
            # 处理当前层，两两组合计算父节点
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # 如果是最后一个节点且为奇数，与自身组合
                right = current_level[i+1] if i+1 < len(current_level) else left
                # 父节点哈希：SM3(left || right)
                parent = sm3_hash_optimized(left.encode() + right.encode())
                next_level.append(parent)
            
            tree.append(next_level)
        
        return tree
    
    # 获取指定索引叶节点的存在性证明，返回证明路径
    def get_proof(self, index: int) -> List[Tuple[str, bool]]:
        if index < 0 or index >= len(self.leaves):
            return []
            
        proof = []
        current_index = index
        
        # 从叶子层向上构建证明路径
        for level in range(len(self.tree) - 1):
            current_level = self.tree[level]
            is_left = (current_index % 2 == 0)
            sibling_index = current_index - 1 if is_left else current_index + 1
            
            # 如果是最后一个节点且为奇数，兄弟节点是自身
            if sibling_index >= len(current_level):
                sibling_index = current_index
            
            proof.append((current_level[sibling_index], not is_left))
            current_index = current_index // 2
        
        return proof
    
    # 验证存在性证明
    def verify_proof(self, leaf: bytes, index: int, proof: List[Tuple[str, bool]], root: str) -> bool:
        current_hash = sm3_hash_optimized(leaf)
        
        for hash_val, is_left in proof:
            if is_left:
                # 兄弟节点在左，当前节点在右
                current_hash = sm3_hash_optimized(hash_val.encode() + current_hash.encode())
            else:
                # 兄弟节点在右，当前节点在左
                current_hash = sm3_hash_optimized(current_hash.encode() + hash_val.encode())
        
        return current_hash == root
    
    # 获取不存在证明
    def get_non_existence_proof(self, value: bytes) -> Tuple[Optional[bytes], Optional[bytes], List[Tuple[str, bool]], List[Tuple[str, bool]]]:
        # 对叶子进行排序（假设叶子可排序）
        sorted_leaves = sorted(self.leaves)
        n = len(sorted_leaves)
        
        # 二分查找确定位置
        left = 0
        right = n - 1
        pos = 0
        
        while left <= right:
            mid = (left + right) // 2
            if sorted_leaves[mid] < value:
                pos = mid + 1
                left = mid + 1
            else:
                right = mid - 1
        
        # 检查是否存在
        if pos < n and sorted_leaves[pos] == value:
            return (None, None, [], [])  # 该值存在
        
        # 获取左、右相邻叶子
        left_leaf = sorted_leaves[pos-1] if pos > 0 else None
        right_leaf = sorted_leaves[pos] if pos < n else None
        
        # 获取相邻叶子的存在性证明
        left_proof = self.get_proof(sorted_leaves.index(left_leaf)) if left_leaf is not None else []
        right_proof = self.get_proof(sorted_leaves.index(right_leaf)) if right_leaf is not None else []
        
        return (left_leaf, right_leaf, left_proof, right_proof)

# 测试函数：生成10万个叶子节点并构建Merkle树
def test_merkle_tree():
    print("生成10w个叶子节点...")
    # 生成10w个测试叶子节点
    num_leaves = 100000
    leaves = [f"leaf_{i}".encode() for i in range(num_leaves)]
    
    print("构建Merkle树...")
    merkle_tree = MerkleTree(leaves)
    print(f"Merkle树根节点: {merkle_tree.root}")
    print(f"Merkle树高度: {len(merkle_tree.tree)}")
    
    # 测试存在性证明
    test_index = 12345
    test_leaf = leaves[test_index]
    proof = merkle_tree.get_proof(test_index)
    print(f"存在性证明长度: {len(proof)}")
    
    verify_result = merkle_tree.verify_proof(test_leaf, test_index, proof, merkle_tree.root)
    print(f"存在性证明验证结果: {'成功' if verify_result else '失败'}")
    
    # 测试不存在性证明
    non_existent_leaf = b"non_existent_leaf_12345"
    left, right, left_proof, right_proof = merkle_tree.get_non_existence_proof(non_existent_leaf)
    
    print(f"左相邻叶子: {left.decode() if left else '无'}")
    print(f"右相邻叶子: {right.decode() if right else '无'}")
    
    # 验证相邻叶子的存在性
    left_valid = merkle_tree.verify_proof(left, leaves.index(left), left_proof, merkle_tree.root) if left else True
    right_valid = merkle_tree.verify_proof(right, leaves.index(right), right_proof, merkle_tree.root) if right else True
    
    print(f"左相邻叶子证明验证: {'成功' if left_valid else '失败'}")
    print(f"右相邻叶子证明验证: {'成功' if right_valid else '失败'}")
    
    if left_valid and right_valid:
        print("不存在性证明验证成功")
    else:
        print("不存在性证明验证失败")

if __name__ == "__main__":
    test_merkle_tree()
