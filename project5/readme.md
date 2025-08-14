# SM2 的软件实现和优化

## 1. 概览

- 曲线：SM2 `sm2p256v1`（256-bit，素域）。
- 哈希：SM3。
- 绑定：`ZA = H(ENTL || ID || a || b || Gx || Gy || Px || Py)`，签名对 `ZA || M` 取 SM3。
- 优化：Jacobian 坐标、wNAF 标量乘、固定基点预计算（w=5）

## 2. 算法说明

### 2.1 参数与域

- 素域 `Fp`，参数 `a,b,p`；基点 `G=(Gx,Gy)`；阶 `n`。  
- 私钥 `d ∈ [1, n-1]`，公钥 `P = d·G`。

### 2.2 ZA 计算

- `ENTL = bitlen(ID)` 的 16-bit 大端。
- `ZA = SM3( ENTL || ID || a || b || Gx || Gy || Px || Py )`。  
- 签名消息摘要：`e = SM3( ZA || M ) (mod n)`。

### 2.3 签名

给定消息 `M`、身份 `ID`、私钥 `d`、公钥 `P=(Px,Py)`：

1. 计算 `e = H_ZA(M)`（上一节）。
2. 取随机数 `k ∈ [1, n-1]`
3. 计算 `k·G = (x1, y1)`；`r = (e + x1) mod n`。若 `r==0` 或 `r+k==n` 重新取 `k`。
4. 计算 `s = ( (k - r·d) * (1+d)^(-1) ) mod n`。若 `s==0` 重新取 `k`。
5. 输出签名 `(r, s)`。

### 2.4 验签

输入 `(r,s)`、公钥 `P`、消息 `M` 与 `ID`：

1. 检查 `1 ≤ r,s < n`。
2. 计算 `e = H_ZA(M)`、`t = (r + s) mod n`（若 `t==0` 拒绝）。
3. 计算 `R = (xR, yR) = s·G + t·P`。
4. 计算 `R' = (e + xR) mod n`；若 `R' == r` 则通过。

### 2.5 实现优化点

- **Jacobian**：避免每一步都做域内求逆，主要用乘加与平方。
- **wNAF**：将标量分解为稀疏的 signed-digits，减少加法次数。
- **固定基点预计算**：对常用的 `G` 构建奇数倍表，提高签名端速度。

## 3. 误用与 PoC（仅测试密钥）


### 3.1 Nonce（k）复用导致私钥恢复

签名方程：
$ r \equiv e + x_1 \pmod n,\quad (x_1, y_1) = kG, s\equiv (k - r d) (1+d)^{-1} \pmod n $

- 对两条不同消息 $m_1,m_2$ 使用**相同**的 $k$，得签名 $(r, s_1)、(r, s_2)$。
- 由签名式：
$
k \equiv (1+d)s_i + r d \pmod n \quad (i=1,2).
$
- 等式相减消去 $k$：
$
(1+d)(s_1 - s_2) \equiv 0 \pmod n.$
- 联立原式可解得 \(d\) 的闭式解（实务上更稳的等价表达）：
$
\boxed{ \ d \equiv (s_1 - s_2) \cdot (s_1 + s_2 - r)^{-1} \pmod n \ }.
$

**PoC 代码（节选）**：
```python
from sm2 import n, inv_mod

def recover_d_from_reused_k(r, s1, s2):
    num = (s1 - s2) % n
    den = (s1 + s2 - r) % n
    return (num * inv_mod(den, n)) % n
```

> 防护：**永不复用 k**；使用确定性 `k` 或真 RNG + 故障检测。

### 3.2 签名可塑性（malleability）：\(s \mapsto n-s\)

对任意有效 `(r,s)`，`(r, n-s)` 在多数实现下同样通过验签，造成同一消息存在多个不同编码的签名。

- **修复**：强制 **low-s** 规则：验签拒绝 `s > n/2`；签名产生阶段若 `s > n/2` 则替换为 `n-s`。

**PoC 代码（节选）**：
```python
from sm2 import n

def malleate(sig): 
    r,s = sig
    return (r, (n - s) % n)
```

### 3.3 忽略 ZA/ID 绑定

若把 `e` 错误地设为 `SM3(M)` 而非 `SM3(ZA||M)`，攻击者可在不同身份/参数环境中移植签名（跨协议/跨域参数重放）。

- **修复**：严格实现 `ZA`；将域参数/公钥绑定进摘要输入并随证书体系分发。

### 3.4 Key-Substitution（密钥替换）/基点混淆

在某些系统中，如果允许替换域参数或将其视作公钥的一部分，存在将“看似同一身份”的不同密钥对调的空间。

- **修复**：固定曲线域参数；把域参数指纹纳入证书与策略；在应用层校验固定曲线。

## 4. 使用示例

```python
from sm2 import sm2_keygen, sm2_sign, sm2_verify

d, P = sm2_keygen()
ID = b"1234567812345678"
msg = b"hello sm2"

sig = sm2_sign(msg, d, ID=ID, P=P)
assert sm2_verify(msg, sig, P, ID=ID)
print("sig r,s =", [hex(x) for x in sig])
```


