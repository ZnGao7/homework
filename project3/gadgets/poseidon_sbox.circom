// Poseidon2 S-box 实现 (d=5)
// S-box 定义: x^5 mod p

template PoseidonSbox5() {
    signal input in;
    signal output out;
    
    // 计算 x^5 = x * x * x * x * x
    signal x2 = in * in;       // x^2
    signal x3 = x2 * in;       // x^3
    signal x4 = x3 * in;       // x^4
    out <== x4 * in;           // x^5
}
