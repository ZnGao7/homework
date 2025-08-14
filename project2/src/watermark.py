#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Project 2: 基于数字水印的图片泄露检测（Python实现）

核心特性：
- 频域（8x8 DCT + QIM）不可见水印：面向灰度或彩色图（对Y通道嵌入）。
- 支持二值logo / 文本 / 随机比特序列作为水印载荷。
- 可重复提取（半盲方式，只需密钥与量化步长等参数）。
- 典型攻击与鲁棒性评测：翻转、平移、裁剪、旋转、缩放、调对比度/亮度、JPEG压缩、高斯噪声等。
- 质量评估：PSNR、SSIM；鲁棒评估：BER、检测率。

依赖：
- Python 3.8+
- numpy, opencv-python (cv2), scikit-image (用于SSIM), pillow（可选，用于读取PNG 含透明）

使用方式（命令行示例）：
- 嵌入：
  python watermark.py embed \
      --in input.jpg --out watermarked.png \
      --payload logo.png --key 12345 --alpha 6.0 --qstep 12.0 --rate 0.5

- 提取：
  python watermark.py extract \
      --in watermarked.png --out extracted.png \
      --width 64 --height 64 --key 12345 --qstep 12.0

- 攻击与评测（批量）：
  python watermark.py eval \
      --in watermarked.png --orig input.jpg --payload logo.png \
      --key 12345 --qstep 12.0 --alpha 6.0 --attacks "flip,translate,crop,contrast,jpeg,noise,rotate,scale" \
      --report report.csv

注意：本实现为教学/研究目的，参数需要根据素材调优。QIM+中频系数设定在常见图像操作下具有较好鲁棒性，但并非万无一失。
"""

import os
import io
import cv2
import math
import json
import base64
import random
import string
import argparse
import numpy as np
from dataclasses import dataclass
from typing import Tuple, List, Optional, Dict
from skimage.metrics import structural_similarity as ssim

# ------------------------------
# 工具函数
# ------------------------------

def imread_rgb(path: str) -> np.ndarray:
    img = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_UNCHANGED)
    if img is None:
        raise FileNotFoundError(path)
    if img.ndim == 2:
        img = cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
    elif img.shape[2] == 4:
        # 丢弃透明通道
        img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
    return img


def imwrite(path: str, img: np.ndarray) -> None:
    ext = os.path.splitext(path)[1].lower()
    params = []
    if ext in [".jpg", ".jpeg"]:
        params = [int(cv2.IMWRITE_JPEG_QUALITY), 95]
    ok, buf = cv2.imencode(ext if ext else ".png", img, params)
    if not ok:
        raise RuntimeError("Failed to encode image")
    buf.tofile(path)


def bgr2ycbcr(img_bgr: np.ndarray) -> np.ndarray:
    return cv2.cvtColor(img_bgr, cv2.COLOR_BGR2YCrCb)


def ycbcr2bgr(img_ycbcr: np.ndarray) -> np.ndarray:
    return cv2.cvtColor(img_ycbcr, cv2.COLOR_YCrCb2BGR)


def to_gray(img_bgr: np.ndarray) -> np.ndarray:
    return cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)


def psnr(a: np.ndarray, b: np.ndarray) -> float:
    a = a.astype(np.float32)
    b = b.astype(np.float32)
    mse = np.mean((a - b) ** 2)
    if mse <= 1e-12:
        return 99.0
    PIX = 255.0
    return 20 * math.log10(PIX) - 10 * math.log10(mse)


# ------------------------------
# 载荷处理（logo / 文本 / 随机比特）
# ------------------------------

def load_payload(payload_path: Optional[str], width: int = 64, height: int = 64) -> np.ndarray:
    """读取payload为二值矩阵（0/1）。若payload_path为空则生成随机比特块。"""
    if payload_path is None:
        bits = np.random.randint(0, 2, size=(height, width), dtype=np.uint8)
        return bits
    logo = imread_rgb(payload_path)
    logo_gray = to_gray(logo)
    logo_resized = cv2.resize(logo_gray, (width, height), interpolation=cv2.INTER_AREA)
    # Otsu阈值二值化
    _, bw = cv2.threshold(logo_resized, 0, 1, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return bw.astype(np.uint8)


def text_to_bits(text: str, bit_len: int) -> np.ndarray:
    data = text.encode("utf-8")
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    # 填充/截断到 bit_len
    out = np.zeros(bit_len, dtype=np.uint8)
    n = min(bit_len, bits.size)
    out[:n] = bits[:n]
    return out


def bits_to_image(bits: np.ndarray, width: int, height: int) -> np.ndarray:
    if bits.size != width * height:
        raise ValueError("bits size mismatch")
    img = (bits.reshape(height, width) * 255).astype(np.uint8)
    return img

# ------------------------------
# DCT + QIM 水印（基于8x8分块）
# ------------------------------

MID_FREQ_COORDS = [
    (2, 3), (3, 2), (1, 4), (4, 1), (2, 2), (3, 3), (4, 2), (2, 4),
]

@dataclass
class WMParams:
    key: int = 12345           # 伪随机密钥
    qstep: float = 12.0        # QIM 量化步长
    alpha: float = 6.0         # 嵌入强度（对DCT系数的附加扰动）
    rate: float = 0.5          # 每个8x8块嵌入比特的概率（0~1），控制容量/冗余
    use_y_channel: bool = True # 彩色图在Y通道嵌入


class DCTQIMWatermarker:
    def __init__(self, params: WMParams):
        self.params = params
        self.rng = np.random.RandomState(params.key)

    def _choose_positions(self, h: int, w: int, nbits: int) -> List[Tuple[int, int]]:
        """随机挑选要嵌入的8x8块位置（左上角索引），以及在块内选择一组中频坐标。"""
        blocks_y = h // 8
        blocks_x = w // 8
        coords = [(by * 8, bx * 8) for by in range(blocks_y) for bx in range(blocks_x)]
        self.rng.shuffle(coords)
        # rate 控制实际使用的块数量；每个块嵌入一个比特
        k = max(1, int(len(coords) * self.params.rate))
        coords = coords[:max(k, nbits)]  # 至少覆盖nbits个块
        return coords

    def _embed_block(self, block: np.ndarray, bit: int) -> np.ndarray:
        dct = cv2.dct(block.astype(np.float32))
        # 选择一个中频位置（随即选择，增强安全性）
        yx = MID_FREQ_COORDS[self.rng.randint(0, len(MID_FREQ_COORDS))]
        v = dct[yx]
        # QIM：将系数向量化到 0/1 对应的量化格
        q = self.params.qstep
        target = (np.floor(v / q) + 0.5 * (1 + bit)) * q
        dct[yx] = target + np.sign(target) * self.params.alpha
        idct = cv2.idct(dct)
        idct = np.clip(idct, 0, 255)
        return idct.astype(np.uint8)

    def _extract_block(self, block: np.ndarray) -> int:
        dct = cv2.dct(block.astype(np.float32))
        yx = MID_FREQ_COORDS[self.rng.randint(0, len(MID_FREQ_COORDS))]
        v = dct[yx]
        q = self.params.qstep
        # 判决：比较到最近的两类量化中心
        # 量化后的小数部分决定比特
        r = (v / q) - np.floor(v / q)
        return 1 if r >= 0.5 else 0

    def embed(self, img_bgr: np.ndarray, payload_bits: np.ndarray) -> Tuple[np.ndarray, Dict]:
        """返回嵌入后的BGR图像和元信息（用于评测）。"""
        if self.params.use_y_channel:
            ycbcr = bgr2ycbcr(img_bgr)
            y = ycbcr[:, :, 0]
            work = y.copy()
        else:
            gray = to_gray(img_bgr)
            work = gray.copy()

        h, w = work.shape
        coords = self._choose_positions(h, w, nbits=payload_bits.size)
        bits = payload_bits.flatten()
        out = work.copy()

        count = 0
        for i, (yy, xx) in enumerate(coords):
            b = bits[count % bits.size]
            block = work[yy:yy+8, xx:xx+8]
            if block.shape != (8, 8):
                continue
            out[yy:yy+8, xx:xx+8] = self._embed_block(block, int(b))
            count += 1
            if count >= max(bits.size, int(len(coords))):
                break

        if self.params.use_y_channel:
            ycbcr[:, :, 0] = out
            stego = ycbcr2bgr(ycbcr)
        else:
            stego = cv2.cvtColor(out, cv2.COLOR_GRAY2BGR)

        info = {
            "h": h,
            "w": w,
            "n_blocks_used": count,
        }
        return stego, info

    def extract(self, img_bgr: np.ndarray, nbits: int) -> np.ndarray:
        if self.params.use_y_channel:
            y = bgr2ycbcr(img_bgr)[:, :, 0]
            work = y
        else:
            work = to_gray(img_bgr)
        h, w = work.shape
        coords = self._choose_positions(h, w, nbits=nbits)
        bits = []
        for i, (yy, xx) in enumerate(coords[:nbits]):
            block = work[yy:yy+8, xx:xx+8]
            if block.shape != (8, 8):
                bits.append(0)
                continue
            bits.append(self._extract_block(block))
        return np.array(bits, dtype=np.uint8)

# ------------------------------
# 攻击/失真仿真
# ------------------------------

class AttackKit:
    @staticmethod
    def flip(img: np.ndarray, mode: str = "h") -> np.ndarray:
        if mode == "h":
            return cv2.flip(img, 1)
        if mode == "v":
            return cv2.flip(img, 0)
        if mode == "hv":
            return cv2.flip(img, -1)
        return img

    @staticmethod
    def translate(img: np.ndarray, dx: int = 10, dy: int = 10) -> np.ndarray:
        H, W = img.shape[:2]
        M = np.float32([[1, 0, dx], [0, 1, dy]])
        return cv2.warpAffine(img, M, (W, H), borderMode=cv2.BORDER_REFLECT)

    @staticmethod
    def crop(img: np.ndarray, ratio: float = 0.9) -> np.ndarray:
        H, W = img.shape[:2]
        nh, nw = int(H * ratio), int(W * ratio)
        y0 = max(0, (H - nh) // 2)
        x0 = max(0, (W - nw) // 2)
        crop = img[y0:y0+nh, x0:x0+nw]
        return cv2.resize(crop, (W, H), interpolation=cv2.INTER_LINEAR)

    @staticmethod
    def rotate(img: np.ndarray, angle: float = 5.0) -> np.ndarray:
        H, W = img.shape[:2]
        M = cv2.getRotationMatrix2D((W/2, H/2), angle, 1.0)
        return cv2.warpAffine(img, M, (W, H), borderMode=cv2.BORDER_REFLECT)

    @staticmethod
    def scale(img: np.ndarray, ratio: float = 0.9) -> np.ndarray:
        H, W = img.shape[:2]
        resized = cv2.resize(img, (int(W*ratio), int(H*ratio)), interpolation=cv2.INTER_LINEAR)
        return cv2.resize(resized, (W, H), interpolation=cv2.INTER_LINEAR)

    @staticmethod
    def contrast(img: np.ndarray, alpha: float = 1.2, beta: int = 0) -> np.ndarray:
        # new = alpha * img + beta
        out = cv2.convertScaleAbs(img, alpha=alpha, beta=beta)
        return out

    @staticmethod
    def jpeg(img: np.ndarray, q: int = 60) -> np.ndarray:
        _, buf = cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), int(q)])
        return cv2.imdecode(buf, cv2.IMREAD_COLOR)

    @staticmethod
    def noise(img: np.ndarray, sigma: float = 5.0) -> np.ndarray:
        n = np.random.normal(0, sigma, img.shape).astype(np.float32)
        out = img.astype(np.float32) + n
        return np.clip(out, 0, 255).astype(np.uint8)

# ------------------------------
# 评测指标
# ------------------------------

def bit_error_rate(a: np.ndarray, b: np.ndarray) -> float:
    if a.size != b.size:
        raise ValueError("bit arrays must be same size")
    return float(np.sum(a != b) / a.size)


# ------------------------------
# 命令行与流程
# ------------------------------

def cmd_embed(args):
    img = imread_rgb(args.inp)
    wm = DCTQIMWatermarker(WMParams(key=args.key, qstep=args.qstep, alpha=args.alpha, rate=args.rate, use_y_channel=not args.gray))

    # 载荷
    if args.text:
        nbits = args.width * args.height
        payload_bits = text_to_bits(args.text, nbits)
    else:
        payload_bits = load_payload(args.payload, args.width, args.height).flatten()

    stego, info = wm.embed(img, payload_bits)
    imwrite(args.out, stego)

    # 质量
    p = psnr(to_gray(img), to_gray(stego))
    s = ssim(to_gray(img), to_gray(stego))

    meta = {
        "embed_info": info,
        "psnr": p,
        "ssim": float(s),
        "payload_size": int(payload_bits.size),
        "payload_wh": [args.width, args.height],
        "params": {
            "key": args.key, "qstep": args.qstep, "alpha": args.alpha, "rate": args.rate,
            "use_y_channel": not args.gray
        }
    }
    if args.meta:
        with open(args.meta, 'w', encoding='utf-8') as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
    print(json.dumps(meta, ensure_ascii=False, indent=2))


def cmd_extract(args):
    img = imread_rgb(args.inp)
    wm = DCTQIMWatermarker(WMParams(key=args.key, qstep=args.qstep, alpha=args.alpha, rate=args.rate, use_y_channel=not args.gray))
    bits = wm.extract(img, nbits=args.width * args.height)
    img_bits = bits_to_image(bits, args.width, args.height)
    imwrite(args.out, cv2.cvtColor(img_bits, cv2.COLOR_GRAY2BGR))

    if args.gt:
        gt = load_payload(args.gt, args.width, args.height).flatten()
        ber = bit_error_rate(bits, gt)
        print(json.dumps({"BER": ber}, indent=2))


def apply_attacks(img: np.ndarray, name: str) -> List[Tuple[str, np.ndarray]]:
    out = []
    if name == "flip":
        for m in ["h", "v", "hv"]:
            out.append((f"flip_{m}", AttackKit.flip(img, m)))
    elif name == "translate":
        for d in [5, 10, 20]:
            out.append((f"translate_{d}", AttackKit.translate(img, d, d)))
    elif name == "crop":
        for r in [0.95, 0.9, 0.8]:
            out.append((f"crop_{r}", AttackKit.crop(img, r)))
    elif name == "rotate":
        for a in [-5, 5, 10]:
            out.append((f"rotate_{a}", AttackKit.rotate(img, a)))
    elif name == "scale":
        for r in [0.9, 0.8, 1.1]:
            out.append((f"scale_{r}", AttackKit.scale(img, r)))
    elif name == "contrast":
        for a in [0.8, 1.2, 1.5]:
            out.append((f"contrast_{a}", AttackKit.contrast(img, a, 0)))
    elif name == "jpeg":
        for q in [85, 70, 50, 30]:
            out.append((f"jpeg_{q}", AttackKit.jpeg(img, q)))
    elif name == "noise":
        for s in [3, 5, 10]:
            out.append((f"noise_{s}", AttackKit.noise(img, s)))
    else:
        out.append((name, img))
    return out


def cmd_eval(args):
    orig = imread_rgb(args.orig)
    watermarked = imread_rgb(args.inp)
    wm = DCTQIMWatermarker(WMParams(key=args.key, qstep=args.qstep, alpha=args.alpha, rate=args.rate, use_y_channel=not args.gray))

    # 载荷基准
    gt_bits = load_payload(args.payload, args.width, args.height).flatten()

    attacks = [s.strip() for s in args.attacks.split(',') if s.strip()]
    rows = []

    # 原图与水印对比
    base_psnr = psnr(to_gray(orig), to_gray(watermarked))
    base_ssim = ssim(to_gray(orig), to_gray(watermarked))

    # 不攻击直接提取
    bits_clean = wm.extract(watermarked, nbits=gt_bits.size)
    ber_clean = bit_error_rate(bits_clean, gt_bits)
    rows.append({"attack": "none", "param": "-", "PSNR": base_psnr, "SSIM": float(base_ssim), "BER": ber_clean})

    # 逐类攻击
    for name in attacks:
        variants = apply_attacks(watermarked, name)
        for tag, attacked in variants:
            p = psnr(to_gray(orig), to_gray(attacked))
            s = ssim(to_gray(orig), to_gray(attacked))
            bits = wm.extract(attacked, nbits=gt_bits.size)
            ber = bit_error_rate(bits, gt_bits)
            rows.append({"attack": name, "param": tag, "PSNR": p, "SSIM": float(s), "BER": ber})

    # 保存CSV
    import csv
    if args.report:
        with open(args.report, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["attack", "param", "PSNR", "SSIM", "BER"])
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
    # 控制台摘要
    print("评测结果（前10行）：")
    for r in rows[:10]:
        print(r)
    print(f"共 {len(rows)} 条记录，报告保存到: {args.report}")


# ------------------------------
# CLI
# ------------------------------

def build_argparser():
    p = argparse.ArgumentParser(description="DCT+QIM 数字水印，嵌入/提取/鲁棒评测")
    sub = p.add_subparsers(dest="cmd", required=True)

    # embed
    p_e = sub.add_parser("embed", help="嵌入水印")
    p_e.add_argument("--in", dest="inp", required=True, help="原始图片路径")
    p_e.add_argument("--out", dest="out", required=True, help="输出带水印图像")
    p_e.add_argument("--payload", default=None, help="水印payload（logo图片），为空则随机")
    p_e.add_argument("--text", default=None, help="使用文本作为payload（可选）")
    p_e.add_argument("--width", type=int, default=64, help="payload宽")
    p_e.add_argument("--height", type=int, default=64, help="payload高")
    p_e.add_argument("--key", type=int, default=12345, help="密钥")
    p_e.add_argument("--qstep", type=float, default=12.0, help="QIM量化步长")
    p_e.add_argument("--alpha", type=float, default=6.0, help="嵌入强度")
    p_e.add_argument("--rate", type=float, default=0.5, help="块使用率[0,1]")
    p_e.add_argument("--gray", action="store_true", help="在灰度上嵌入（默认Y通道）")
    p_e.add_argument("--meta", default=None, help="保存嵌入元信息到JSON")

    # extract
    p_x = sub.add_parser("extract", help="提取水印")
    p_x.add_argument("--in", dest="inp", required=True, help="带水印图像路径")
    p_x.add_argument("--out", dest="out", required=True, help="输出提取的二值水印图")
    p_x.add_argument("--width", type=int, default=64, help="payload宽")
    p_x.add_argument("--height", type=int, default=64, help="payload高")
    p_x.add_argument("--key", type=int, default=12345, help="密钥")
    p_x.add_argument("--qstep", type=float, default=12.0, help="QIM量化步长")
    p_x.add_argument("--alpha", type=float, default=6.0, help="（与嵌入时一致即可，不参与判决）")
    p_x.add_argument("--rate", type=float, default=0.5, help="（与嵌入时一致）")
    p_x.add_argument("--gray", action="store_true", help="在灰度上提取（默认Y通道）")
    p_x.add_argument("--gt", default=None, help="若提供ground-truth payload图片，则计算BER")

    # eval
    p_v = sub.add_parser("eval", help="攻击与鲁棒评测")
    p_v.add_argument("--in", dest="inp", required=True, help="水印图片路径")
    p_v.add_argument("--orig", required=True, help="原始图片路径")
    p_v.add_argument("--payload", required=True, help="payload图片（作为gt）")
    p_v.add_argument("--width", type=int, default=64, help="payload宽")
    p_v.add_argument("--height", type=int, default=64, help="payload高")
    p_v.add_argument("--key", type=int, default=12345, help="密钥")
    p_v.add_argument("--qstep", type=float, default=12.0, help="QIM量化步长")
    p_v.add_argument("--alpha", type=float, default=6.0, help="嵌入强度")
    p_v.add_argument("--rate", type=float, default=0.5, help="块使用率")
    p_v.add_argument("--gray", action="store_true", help="在灰度/而非Y通道提取")
    p_v.add_argument("--attacks", default="flip,translate,crop,contrast,jpeg,noise,rotate,scale", help="逗号分隔的攻击清单")
    p_v.add_argument("--report", default="report.csv", help="输出CSV报告")

    return p


def main():
    parser = build_argparser()
    args = parser.parse_args()
    if args.cmd == "embed":
        cmd_embed(args)
    elif args.cmd == "extract":
        cmd_extract(args)
    elif args.cmd == "eval":
        cmd_eval(args)


if __name__ == "__main__":
    main()
