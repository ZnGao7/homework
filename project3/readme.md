# Poseidon2 哈希算法的 Circom 实现

这是基于 Circom 语言实现的 Poseidon2 哈希算法电路，针对零知识证明场景优化，使用 Groth16 证明系统生成和验证证明。

## 算法概述

Poseidon2 是一种基于 sponge 结构的密码学哈希算法，专为零知识证明电路设计，具有高效的计算性能和较小的电路规模。本实现采用参数 `(n,t,d)=(256,3,5)`：
- `n=256`：输出哈希值位数为 256 位
- `t=3`：状态元素数量为 3（rate=2，capacity=1）
- `d=5`：使用 5 次幂的 S-box 变换

### Poseidon2 算法流程

1. **初始化**：状态向量初始化，包含 rate 部分（输入）和 capacity 部分（内部状态）
2. **吸收阶段**：将输入数据块吸收到状态中
   - 将输入元素与状态的 rate 部分相加
   - 应用完整轮变换（Full Round）
3. **变换阶段**：
   - 应用部分轮变换（Partial Round）：只对状态的一个元素应用 S-box
   - 应用完整轮变换（Full Round）：对所有状态元素应用 S-box
4. **挤压阶段**：从状态的 rate 部分提取哈希结果

## 电路实现

### 主要组件

- `Mux.circom`：多路复用器组件，用于选择不同轮操作时的信号
- `PoseidonSbox5.circom`：实现 5 次幂 S-box 变换（x⁵ mod p）
- `Poseidon2Hash.circom`：主电路模板，实现完整的 Poseidon2 哈希计算流程

### 输入输出定义

- **隐私输入**：2 个 256 位元素（哈希原象，对应 t=3 中的 rate 部分）
- **公开输出**：1 个 256 位元素（哈希结果，对应 t=3 中的 capacity 部分）

## 使用方法

### 环境要求

- Node.js (v14+)
- Circom (v2.0+)
- SnarkJS (用于 Groth16 证明系统)

### 编译与证明生成步骤

1. **编译电路**
   ```bash
   circom poseidon2.circom --r1cs --wasm --sym
   ```

2. **准备输入文件**
   创建 `input.json` 文件，格式如下：
   ```json
   {
     "in": [
       "1234567890123456789012345678901234567890123456789012345678901234",
       "9876543210987654321098765432109876543210987654321098765432109876"
     ]
   }
   ```

3. **生成见证**
   ```bash
   node poseidon2_js/generate_witness.js poseidon2_js/poseidon2.wasm input.json witness.wtns
   ```

4. **执行 Groth16 信任设置**
   ```bash
   # 下载 powers of tau 文件（示例使用 10 次方，实际应根据电路规模选择）
   wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_10.ptau
   
   # 初始设置
   snarkjs groth16 setup poseidon2.r1cs powersOfTau28_hez_final_10.ptau poseidon2_0000.zkey
   
   # 贡献随机性（可多次）
   snarkjs zkey contribute poseidon2_0000.zkey poseidon2_0001.zkey --name="First contribution" -v
   
   # 导出验证密钥
   snarkjs zkey export verificationkey poseidon2_0001.zkey verification_key.json
   ```

5. **生成证明**
   ```bash
   snarkjs groth16 prove poseidon2_0001.zkey witness.wtns proof.json public.json
   ```

6. **验证证明**
   ```bash
   snarkjs groth16 verify verification_key.json public.json proof.json
   ```

## 注意事项

1. 代码中的轮常量（RC）和线性层矩阵（M）仅为示例结构，实际使用时需要替换为 [Poseidon2 规范文档](https://eprint.iacr.org/2023/323.pdf) 中 Table 1 定义的正确值。

2. 本实现仅处理单个数据块输入，如需处理长消息，需添加：
   - 消息填充机制（遵循 sponge 结构规范）
   - 多块处理逻辑

3. 电路规模可能需要根据实际应用场景进行优化，可调整参数 `t`（状态元素数量）来平衡性能和安全性。

## 参考资料

- [Poseidon2: A New Hash Function for Zero-Knowledge Proof Systems](https://eprint.iacr.org/2023/323.pdf)
- [Circom 官方文档](https://docs.circom.io/)
- [iden3/circomlib](https://github.com/iden3/circomlib)