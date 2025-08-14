import os
import numpy as np
from PIL import Image, ImageEnhance, ImageOps
import matplotlib.pyplot as plt
import random

class WatermarkDetector:
    def __init__(self, watermark_text="Confidential", seed=42):
        """初始化水印检测器"""
        self.watermark_text = watermark_text
        self.seed = seed
        np.random.seed(seed)  # 设置随机种子，确保水印嵌入和提取的一致性
        self.original_watermark = None  # 存储原始水印以便后续使用
        self.original_width = None
        self.original_height = None
        
    def generate_watermark(self, width, height):
        """生成与图像尺寸匹配的二值水印"""
        # 将文本转换为二进制序列
        binary_watermark = ''.join(format(ord(c), '08b') for c in self.watermark_text)
        
        # 计算需要重复多少次才能填满图像
        watermark_length = len(binary_watermark)
        total_pixels = width * height
        repeat_times = (total_pixels // watermark_length) + 1
        
        # 重复二进制序列以匹配图像大小
        extended_watermark = (binary_watermark * repeat_times)[:total_pixels]
        
        # 转换为二维数组
        watermark_array = np.array([int(bit) for bit in extended_watermark], dtype=np.uint8)
        watermark_array = watermark_array.reshape(height, width)
        
        return watermark_array
    
    def embed_watermark(self, image_path, output_path=None, alpha=0.05):
        """
        在图像中嵌入水印，返回带水印的图像数组、图像对象以及原始宽高
        """
        # 打开图像并转换为YCrCb颜色空间，我们只在亮度通道嵌入水印
        img = Image.open(image_path).convert('YCbCr')
        img_array = np.asarray(img, dtype=np.float32)
        
        # 获取原始图像尺寸
        self.original_width, self.original_height = img.size
        
        # 分离通道
        y_channel = img_array[:, :, 0]
        cr_channel = img_array[:, :, 1]
        cb_channel = img_array[:, :, 2]
        
        # 获取图像尺寸并生成水印
        height, width = y_channel.shape
        self.original_watermark = self.generate_watermark(width, height)
        
        # 嵌入水印到亮度通道
        watermarked_y = y_channel + alpha * 255 * self.original_watermark
        
        # 确保像素值在有效范围内
        watermarked_y = np.clip(watermarked_y, 0, 255)
        
        # 合并通道
        watermarked_array = np.stack([watermarked_y, cr_channel, cb_channel], axis=2)
        watermarked_array = watermarked_array.astype(np.uint8)
        
        # 转换回RGB格式
        watermarked_img = Image.fromarray(watermarked_array, mode='YCbCr').convert('RGB')
        
        # 保存图像（如果指定了输出路径）
        if output_path:
            watermarked_img.save(output_path)
            print(f"Watermarked image saved to: {output_path}")
        
        return watermarked_array, watermarked_img, self.original_width, self.original_height
    
    # 提取水印
    def extract_watermark(self, watermarked_image_path=None, watermarked_array=None, target_shape=None):
        if watermarked_array is None and watermarked_image_path:
            # 从路径加载图像
            img = Image.open(watermarked_image_path).convert('YCbCr')
            watermarked_array = np.asarray(img, dtype=np.float32)
        
        # 提取亮度通道
        y_channel = watermarked_array[:, :, 0]
        
        # 获取图像尺寸
        height, width = y_channel.shape
        
        # 生成与当前图像匹配的水印用于提取
        current_watermark = self.generate_watermark(width, height)
        
        # 提取水印
        extracted_watermark = np.zeros_like(current_watermark, dtype=np.uint8)
        extracted_watermark[y_channel > np.mean(y_channel)] = 1
        
        # 如果指定了目标形状且与当前形状不同，则调整提取的水印尺寸
        if target_shape and (height, width) != target_shape:
            # 将水印转换为图像进行尺寸调整
            img = Image.fromarray(extracted_watermark * 255, mode='L')
            img = img.resize((target_shape[1], target_shape[0]), Image.LANCZOS)
            extracted_watermark = np.array(img) // 255  # 转回二值数组
        
        return extracted_watermark
    
    def calculate_similarity(self, original_watermark, extracted_watermark):
        """计算原始水印和提取水印的相似度（汉明距离）"""
        # 确保两个水印具有相同的尺寸
        if original_watermark.shape != extracted_watermark.shape:
            # 调整提取的水印尺寸以匹配原始水印
            h, w = original_watermark.shape
            img = Image.fromarray(extracted_watermark * 255, mode='L')
            img = img.resize((w, h), Image.LANCZOS)
            extracted_watermark = np.array(img) // 255
        
        return np.mean(original_watermark == extracted_watermark) * 100
    
    # 对图像应用各种攻击以测试水印的鲁棒性
    def apply_attack(self, image, attack_type, severity=1.0):
        
        attacked_img = image.copy()
        
        if attack_type == "flip":
            # 水平或垂直翻转
            if random.random() > 0.5:
                attacked_img = ImageOps.flip(attacked_img)  # 垂直翻转
            else:
                attacked_img = ImageOps.mirror(attacked_img)  # 水平翻转
                
        elif attack_type == "crop":
            # 裁剪图像
            width, height = attacked_img.size
            crop_percent = 0.1 + 0.4 * severity  # 裁剪10%-50%
            new_width = int(width * (1 - crop_percent))
            new_height = int(height * (1 - crop_percent))
            
            left = (width - new_width) // 2
            top = (height - new_height) // 2
            right = (width + new_width) // 2
            bottom = (height + new_height) // 2
            
            attacked_img = attacked_img.crop((left, top, right, bottom))
            
        elif attack_type == "contrast":
            # 调整对比度
            factor = 0.2 + 1.8 * severity  # 0.2-2.0之间
            enhancer = ImageEnhance.Contrast(attacked_img)
            attacked_img = enhancer.enhance(factor)
            
        elif attack_type == "noise":
            # 添加高斯噪声
            img_array = np.asarray(attacked_img, dtype=np.float32)
            noise = np.random.normal(0, 10 * severity, img_array.shape)
            noisy_array = np.clip(img_array + noise, 0, 255).astype(np.uint8)
            attacked_img = Image.fromarray(noisy_array)
            
        elif attack_type == "resize":
            # 缩放图像
            scale = 0.3 + 0.7 * severity  # 30%-100%之间
            width, height = attacked_img.size
            new_width = int(width * scale)
            new_height = int(height * scale)
            attacked_img = attacked_img.resize((new_width, new_height))
            # 恢复原始大小
            attacked_img = attacked_img.resize((width, height))
            
        else:
            raise ValueError(f"Unsupported attack type: {attack_type}")
            
        return attacked_img
    
    def test_robustness(self, original_image_path, output_dir="robustness_tests"):
        """测试水印在各种攻击下的鲁棒性"""
        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        
        # 嵌入水印
        watermarked_array, watermarked_img, original_width, original_height = self.embed_watermark(original_image_path)
        watermarked_img.save(os.path.join(output_dir, "watermarked_image.png"))
        
        # 定义要测试的攻击类型
        attacks = [
            ("flip", "Flip"),
            ("crop", "Cropping"),
            ("contrast", "Contrast Adjustment"),
            ("noise", "Noise Addition"),
            ("resize", "Resizing")
        ]
        
        results = []
        
        # 显示原始图像和带水印图像
        plt.figure(figsize=(12, 6))
        plt.subplot(121)
        plt.imshow(Image.open(original_image_path))
        plt.title("Original Image")
        plt.axis('off')
        
        plt.subplot(122)
        plt.imshow(watermarked_img)
        plt.title("Watermarked Image")
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "original_vs_watermarked.png"))
        plt.close()
        
        # 对每种攻击进行测试
        for attack_code, attack_name in attacks:
            print(f"Testing {attack_name} attack...")
            
            # 应用攻击
            attacked_img = self.apply_attack(watermarked_img, attack_code)
            attacked_img.save(os.path.join(output_dir, f"attacked_{attack_code}.png"))
            
            # 提取水印，指定目标形状为原始水印的形状
            attacked_array = np.asarray(attacked_img.convert('YCbCr'), dtype=np.float32)
            extracted_watermark = self.extract_watermark(
                watermarked_array=attacked_array,
                target_shape=self.original_watermark.shape
            )
            
            # 计算相似度
            similarity = self.calculate_similarity(self.original_watermark, extracted_watermark)
            results.append((attack_name, similarity))
            
            print(f"Watermark similarity after {attack_name} attack: {similarity:.2f}%")
            
            # 显示攻击后的图像和提取的水印
            plt.figure(figsize=(12, 6))
            plt.subplot(121)
            plt.imshow(attacked_img)
            plt.title(f"Image after {attack_name} Attack")
            plt.axis('off')
            
            plt.subplot(122)
            plt.imshow(extracted_watermark, cmap='gray')
            plt.title(f"Extracted Watermark from {attack_name} Attack")
            plt.axis('off')
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f"result_{attack_code}.png"))
            plt.close()
        
        # 显示所有攻击的结果对比
        plt.figure(figsize=(10, 6))
        attacks, similarities = zip(*results)
        plt.bar(attacks, similarities)
        plt.ylim(0, 100)
        plt.title("Watermark Extraction Similarity Under Different Attacks")
        plt.ylabel("Similarity (%)")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "attack_comparison.png"))
        plt.close()
        
        print("\nRobustness test completed. Results saved to:", output_dir)
        return results

# 使用示例
if __name__ == "__main__":
    # 创建水印检测器实例
    detector = WatermarkDetector(watermark_text="CompanyConfidential2023")
    
    # 测试图像路径（请替换为你的图像路径）
    test_image_path = "test_image.jpg"
    
    # 检查测试图像是否存在，如果不存在则创建一个简单的图像
    if not os.path.exists(test_image_path):
        print(f"Test image {test_image_path} not found, creating a simple image...")
        img = Image.new('RGB', (500, 300), color='white')
        for i in range(100):
            x1, y1 = random.randint(0, 500), random.randint(0, 300)
            x2, y2 = random.randint(0, 500), random.randint(0, 300)
            from PIL import ImageDraw
            draw = ImageDraw.Draw(img)
            draw.line([(x1, y1), (x2, y2)], fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)), width=2)
        img.save(test_image_path)
    
    # 执行鲁棒性测试
    detector.test_robustness(test_image_path)
    