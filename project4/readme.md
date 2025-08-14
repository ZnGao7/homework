# SM3 密码杂凑算法实现与应用

本项目实现了SM3密码杂杂凑算法的基础功能、效率优化，以及基于SM3的长度扩展攻击验证和Merkle树构建（符合RFC6962规范）。

## 项目结构

```
.
├── sm3.py               # SM3算法基础实现与优化版本
├── length_extension_attack.py  # 长度扩展攻击验证
├── merkle_tree.py       # 基于SM3的Merkle树实现
└── readme.md            # 项目说明文档
```

## 1. SM3算法实现（sm3.py）

### 算法流程

SM3算法的核心流程包括：
1. **消息填充**：将输入消息填充为512bit的整数倍
2. **消息扩展**：将每个512bit分组扩展为132个字（W0-W67, W'0-W'63）
3. **压缩函数**：使用初始向量IV对每个分组进行64轮迭代压缩
4. **输出结果**：最终压缩结果即为哈希值

### 主要函数说明

#### `sm3_hash_basic(message: bytes) -> str`
SM3算法的基础实现，用于验证算法正确性

#### `sm3_hash_optimized(message: bytes, iv: Optional[List[int]] = None) -> str`
优化后的SM3实现，提升了执行效率

**优化措施**：
- 减少临时变量，直接计算中间结果
- 循环展开处理消息分组，提高缓存利用率
- 位运算优化，合并逻辑判断
- 预计算常量Tj，避免重复计算

#### 辅助函数
- `_padding(message: bytes) -> bytes`: 实现SM3消息填充
- `_message_extension(B: bytes) -> Tuple[List[int], List[int]]`: 消息扩展函数
- `_cf(v: List[int], B: bytes) -> List[int]`: 压缩函数

## 2. 长度扩展攻击验证（length_extension_attack.py）

### 算法原理

长度扩展攻击利用哈希函数的迭代特性：若已知`H = SM3(m)`，则无需知道`m`，即可计算`SM3(m || pad(m) || m')`，其中`pad(m)`是`m`的填充部分，`m'`是扩展消息。

### 主要函数说明

#### `parse_hash_to_iv(hash_str: str) -> List[int]`
将哈希值解析为初始向量，用于攻击

#### `length_extension_attack(original_hash: str, original_length: int, extension: bytes) -> Tuple[str, bytes]`
执行长度扩展攻击

#### `verify_attack() -> None`
验证长度扩展攻击的正确性，输出验证结果

## 3. Merkle树实现（merkle_tree.py）

### 算法流程

基于SM3的Merkle树构建流程：
1. 计算所有叶子节点的SM3哈希值
2. 自下而上构建树结构，每个父节点是其两个子节点哈希的SM3哈希
3. 对于奇数个节点的层，最后一个节点与自身组合计算父节点
4. 构建完成后，根节点是整个树的唯一标识

### 主要类与函数说明

#### `class MerkleTree`
基于SM3的Merkle树实现，遵循RFC6962规范

##### `__init__(self, leaves: List[bytes])`
构造函数，初始化Merkle树

##### `build_tree(self) -> List[List[str]]`
构建Merkle树，返回树的层次结构，每层包含该层所有节点的哈希值

##### `get_proof(self, index: int) -> List[Tuple[str, bool]]`
获取指定索引叶子节点的存在性证明，返回证明路径列表，每个元素为(哈希值, 是否为左节点)

##### `verify_proof(self, leaf: bytes, index: int, proof: List[Tuple[str, bool]], root: str) -> bool`
验证存在性证明，需要输入：

- `leaf`: 叶子节点数据
- `index`: 叶子节点索引
- `proof`: 证明路径
- `root`: Merkle树根节点

##### `get_non_existence_proof(self, value: bytes) -> Tuple[Optional[bytes], ...]`
获取不存在性证明，输入 `value` 即要验证不存在的值，返回左相邻叶子、右相邻叶子、左叶子证明、右叶子证明

#### `test_merkle_tree() -> None`
测试Merkle树功能，包括10w叶子节点的构建与两种证明的验证

## 使用示例

### 1. 计算SM3哈希
```python
from sm3 import sm3_hash_optimized

message = b"Hello, SM3!"
hash_result = sm3_hash_optimized(message)
print(f"SM3哈希结果: {hash_result}")
```

### 2. 验证长度扩展攻击
```python
python length_extension_attack.py
```

### 3. 测试Merkle树
```python
python merkle_tree.py
```

## 实验结果
### 1. 计算SM3哈希


### 2. 验证长度扩展攻击


### 3. 测试Merkle树

