// 多路复用器组件
// 根据选择信号选择输入a或b

template Mux() {
    signal input a;
    signal input b;
    signal input sel; // 选择信号: 0选择a, 1选择b
    signal output out;
    
    // 约束: out = a*(1-sel) + b*sel
    out <== a*(1 - sel) + b*sel;
}
