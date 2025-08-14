// Poseidon2 哈希算法实现 (n=256, t=3, d=5)
// 参考文档: https://eprint.iacr.org/2023/323.pdf

include "poseidon2_constants.circom";
include "gadgets/mux.circom";
include "gadgets/poseidon_sbox.circom";

template Poseidon2Hash() {
    // 公开输入: 哈希结果 (256位)
    signal output out[1];
    
    // 隐私输入: 哈希原象 (2个元素，每个256位)
    signal input in[2];
    
    // 状态变量 (t=3)
    signal state[3];
    
    // 初始化状态: 容量部分为0，速率部分为输入
    state[0] <== in[0];
    state[1] <== in[1];
    state[2] <== 0;
    
    // 应用常量加法和置换网络
    for (var r = 0; r < ROUNDS_FULL + ROUNDS_PARTIAL; r++) {
        // 步骤1: 添加轮常量
        for (var i = 0; i < t; i++) {
            state[i] <== state[i] + RC[r][i];
        }
        
        // 步骤2: 应用S-box
        if (r < ROUNDS_FULL/2 || r >= ROUNDS_FULL/2 + ROUNDS_PARTIAL) {
            // 完整轮: 对所有状态元素应用S-box
            for (var i = 0; i < t; i++) {
                state[i] <== PoseidonSbox5(state[i]);
            }
        } else {
            // 部分轮: 只对第一个元素应用S-box
            state[0] <== PoseidonSbox5(state[0]);
        }
        
        // 步骤3: 应用线性层 (矩阵乘法)
        signal new_state[3];
        for (var i = 0; i < t; i++) {
            new_state[i] <== 0;
            for (var j = 0; j < t; j++) {
                new_state[i] <== new_state[i] + state[j] * M[i][j];
            }
        }
        
        // 更新状态
        for (var i = 0; i < t; i++) {
            state[i] <== new_state[i];
        }
    }
    
    // 输出容量部分作为哈希结果
    out[0] <== state[2];
}

// 主组件: 声明公开输入和隐私输入
component main {
    public [out]
} = Poseidon2Hash();
