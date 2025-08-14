# 基于数字水印的图片泄露检测

基于数字水印的图片泄露检测系统能够在图片中嵌入不可见水印，并在需要时提取水印以验证图片的所有权和完整性。本系统实现了水印的嵌入、提取功能，并能对水印在各种常见图像处理攻击下的鲁棒性进行测试。

## 算法流程

### 1. 水印生成
- 将文本水印转换为二进制序列
- 根据图像尺寸生成与图像像素数量匹配的二值水印图案
- 通过重复二进制序列确保水印与图像尺寸完全匹配

### 2. 水印嵌入
- 将原始图像转换为YCrCb颜色空间
- 仅在亮度通道(Y通道)嵌入水印，避免影响色彩通道
- 使用加法嵌入：`watermarked_y = y_channel + alpha * 255 * watermark`
- alpha参数控制水印强度，值越大水印越明显但鲁棒性可能更好
- 将处理后的图像转换回RGB格式并保存

### 3. 水印提取
- 将带水印图像转换为YCrCb颜色空间
- 提取亮度通道(Y通道)
- 使用阈值法从亮度通道中提取水印：`extracted_watermark[y_channel > np.mean(y_channel)] = 1`
- 当图像经过裁剪等尺寸变化操作时，自动调整提取的水印尺寸以匹配原始水印

### 4. 鲁棒性测试
- 对带水印图像应用多种常见攻击
- 从受攻击图像中提取水印
- 计算提取的水印与原始水印的相似度(基于汉明距离)
- 生成可视化结果比较不同攻击下的水印保留情况

## 系统结构

```
watermark_detection_system/
├── watermark_detector.py   # 核心算法实现
├── test_image.jpg          # 测试用例图像
├── robustness_tests/       # 鲁棒性测试结果
│   ├── original_vs_watermarked.png  # 原始图像与带水印图像对比
│   ├── attack_comparison.png        # 不同攻击下水印相似度对比
│   ├── watermarked_image.png        # 带水印的原始图像
│   ├── attacked_flip.png            # 翻转攻击后的图像
│   ├── result_flip.png              # 翻转攻击后的结果分析
│   ├── attacked_crop.png            # 裁剪攻击后的图像
│   ├── result_crop.png              # 裁剪攻击后的结果分析
│   ├── attacked_contrast.png        # 对比度调整攻击后的图像
│   ├── result_contrast.png          # 对比度调整攻击后的结果分析
│   ├── attacked_noise.png           # 噪声攻击后的图像
│   ├── result_noise.png             # 噪声攻击后的结果分析
│   ├── attacked_resize.png          # 缩放攻击后的图像
│   └── result_resize.png            # 缩放攻击后的结果分析
└── README.md               # 系统说明文档
```

## 文件夹作用

1. **根目录**
   - `watermark.py`: 系统核心代码，包含水印生成、嵌入、提取和鲁棒性测试的实现
   - `test_image.jpg`: 用于测试的原始图像，若不存在将自动生成
   - `README.md`: 系统说明文档

2. **robustness_tests/**
   - 存储所有鲁棒性测试的结果图像
   - 包含原始图像与带水印图像的对比图
   - 包含各种攻击处理后的图像及其提取的水印
   - 包含不同攻击下水印相似度的柱状对比图

## 使用方法

1. 确保安装必要的依赖库:
   ```
   pip install numpy pillow matplotlib
   ```

2. 运行程序:
   ```
   python3 watermark.py
   ```

3. 查看结果:
   - 程序会自动生成测试图像(若不存在)
   - 所有测试结果将保存在`robustness_tests`文件夹中
   - 控制台会输出每种攻击后的水印相似度

## 攻击类型说明

系统测试以下五种常见图像处理攻击对水印的影响:

1. **翻转攻击(Flip)**: 随机进行水平或垂直翻转
2. **裁剪攻击(Cropping)**: 裁剪掉图像的部分区域(10%-50%)
3. **对比度调整攻击(Contrast Adjustment)**: 调整图像对比度(0.2-2.0倍)
4. **噪声攻击(Noise Addition)**: 添加高斯噪声
5. **缩放攻击(Resizing)**: 先缩小再恢复原始尺寸(30%-100%)

