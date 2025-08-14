# 基于数字水印的图片泄露检测系统

该项目实现了一个数字水印系统，能够在图像中嵌入水印信息并在需要时提取，用于图片泄露检测。系统还包含了多种鲁棒性测试功能，可评估水印在不同图像操作下的稳定性。

## 功能概述

- 生成随机二值水印
- 向图像中嵌入水印
- 从图像中提取水印
- 计算原始水印与提取水印的相似度
- 进行多种图像攻击测试（翻转、旋转、裁剪等）
- 可视化展示实验结果

## 环境要求

- Python 3.6+
- OpenCV (cv2)
- NumPy
- Matplotlib

安装依赖：
```bash
pip install opencv-python numpy matplotlib
```

## 使用方法

1. 在image文件夹存放测试图片，然后修改 `src/code.py` 代码中函数 `main()` 的图片路径
2. 运行主程序：
```bash
python code.py
```
3. 查看控制台输出的相似度结果和弹出的可视化窗口

## 算法流程

### 水印嵌入流程

1. 读取原始图像并转换至YCrCb色彩空间
2. 从YCrCb图像中提取亮度通道(Y通道)
3. 随机生成指定大小的二值水印
4. 在亮度通道的随机位置嵌入水印（使用添加法）
   - 将二值水印(0/1)转换为-1/1表示
   - 按照公式：`watermarked = original + alpha * watermark`嵌入水印
5. 将处理后的亮度通道放回YCrCb图像
6. 转换回BGR色彩空间，得到含水印的图像

### 水印提取流程

1. 分别将原始图像和含水印图像转换至YCrCb色彩空间
2. 提取两者的亮度通道
3. 计算亮度通道差异：`diff = watermarked_y - original_y`
4. 从差异图像中提取水印区域
5. 将提取的结果转换回二值水印(0/1)
6. 计算与原始水印的相似度

## 类与函数说明

### WatermarkSystem类

水印系统核心类，负责水印的生成、嵌入和提取。

#### 初始化方法
```python
def __init__(self, seed=42)
```
- 参数：seed - 随机数种子，确保实验可重复

#### 生成水印
```python
def generate_watermark(self, size)
```
- 参数：size - 水印尺寸，元组形式(h, w)
- 返回：随机二值水印数组

#### 嵌入水印
```python
def embed_watermark(self, image_path, watermark, alpha=0.05)
```
- 参数：
  - image_path - 原始图像路径
  - watermark - 要嵌入的水印
  - alpha - 水印强度因子，默认0.05
- 返回：原始图像、含水印图像、水印嵌入位置

#### 提取水印
```python
def extract_watermark(self, original_image, watermarked_image, watermark_size, position, alpha=0.05)
```
- 参数：
  - original_image - 原始图像
  - watermarked_image - 含水印的图像
  - watermark_size - 水印尺寸(h, w)
  - position - 水印嵌入位置(start_h, start_w)
  - alpha - 水印强度因子，需与嵌入时一致
- 返回：提取的水印

#### 计算相似度
```python
def calculate_similarity(self, original_watermark, extracted_watermark)
```
- 参数：
  - original_watermark - 原始水印
  - extracted_watermark - 提取的水印
- 返回：两个水印的归一化相关系数（0-1之间）

### RobustnessTester类

水印鲁棒性测试器，提供多种图像攻击方法。

#### 翻转图像
```python
@staticmethod
def flip_image(image, flip_code=1)
```
- 参数：
  - image - 输入图像
  - flip_code - 翻转方式（1:水平, 0:垂直, -1:水平垂直）
- 返回：翻转后的图像

#### 旋转图像
```python
@staticmethod
def rotate_image(image, angle=30)
```
- 参数：
  - image - 输入图像
  - angle - 旋转角度，默认30度
- 返回：旋转后的图像

#### 裁剪图像
```python
@staticmethod
def crop_image(image, ratio=0.8)
```
- 参数：
  - image - 输入图像
  - ratio - 保留比例，默认0.8（裁剪20%）
- 返回：裁剪后的图像

#### 调整对比度
```python
@staticmethod
def adjust_contrast(image, alpha=1.5)
```
- 参数：
  - image - 输入图像
  - alpha - 对比度因子，>1增强，<1减弱
- 返回：调整后的图像

#### 添加噪声
```python
@staticmethod
def add_noise(image, mean=0, var=0.001)
```
- 参数：
  - image - 输入图像
  - mean - 噪声均值
  - var - 噪声方差
- 返回：添加噪声后的图像

#### 缩放图像
```python
@staticmethod
def resize_image(image, scale=0.5)
```
- 参数：
  - image - 输入图像
  - scale - 缩放比例，默认0.5（缩小50%）
- 返回：缩放后的图像

## 结果解读

程序运行后会输出各种攻击情况下的水印相似度，值越接近1表示水印抗攻击能力越强。同时会显示可视化结果，包括：

- 原始图像与含水印图像对比
- 原始水印展示
- 各种攻击后的图像及其提取的水印对比

通过这些结果可以评估水印系统的鲁棒性，判断其在实际应用中的有效性。如下图所示

