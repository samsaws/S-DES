# core/cracker.py

import time
import random
import concurrent.futures

try:
    from core.sdes import encrypt_8bit
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.sdes import encrypt_8bit

# ==========================================
# 1. 暴力破解与多线程核心 (第4关)
# ==========================================

def _check_keys_in_range(start_idx, end_idx, plaintext, ciphertext):
    """
    线程工作函数：在指定的密钥索引范围内寻找匹配的密钥
    """
    found_keys = []
    for i in range(start_idx, end_idx):
        # 将十进制转为 10-bit 二进制字符串
        key = format(i, '010b')
        if encrypt_8bit(plaintext, key) == ciphertext:
            found_keys.append(key)
    return found_keys

def brute_force_crack(plaintext, ciphertext, num_threads=4):
    """
    多线程暴力破解函数，带时间戳记录耗时
    """
    print(f"[*] 开始多线程暴力破解...")
    print(f"[*] 已知明文: {plaintext} | 已知密文: {ciphertext}")
    print(f"[*] 启用线程数: {num_threads}")
    
    total_keys = 1024
    chunk_size = total_keys // num_threads
    
    futures = []
    found_keys = []
    
    # 记录开始时间戳
    start_time = time.perf_counter()
    
    # 启动线程池
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        for i in range(num_threads):
            start_idx = i * chunk_size
            # 最后一个线程负责处理剩余所有密钥
            end_idx = total_keys if i == num_threads - 1 else (i + 1) * chunk_size
            
            # 提交任务
            future = executor.submit(_check_keys_in_range, start_idx, end_idx, plaintext, ciphertext)
            futures.append(future)
            
        # 收集结果
        for future in concurrent.futures.as_completed(futures):
            found_keys.extend(future.result())
            
    # 记录结束时间戳
    end_time = time.perf_counter()
    time_cost = end_time - start_time
    
    print(f"[+] 破解完成！耗时: {time_cost:.6f} 秒")
    print(f"[+] 找到可能正确的密钥共 {len(found_keys)} 个: {found_keys}\n")
    
    return found_keys, time_cost


# ==========================================
# 2. 封闭测试分析 (第5关)
# ==========================================

def test_multiple_keys_for_random_pair():
    """
    封闭测试 1：随机选择一个明密文对，分析是否存在不止一个密钥
    """
    print("="*50)
    print("【第5关封闭测试分析 1：单对明密文的多密钥现象】")
    
    # 随机生成明文和正确的密钥
    p_int = random.randint(0, 255)
    k_int = random.randint(0, 1023)
    p = format(p_int, '08b')
    k_true = format(k_int, '010b')
    
    # 获取密文
    c = encrypt_8bit(p, k_true)
    
    print(f"随机生成的明文 P: {p}")
    print(f"随机选用的真密钥 K: {k_true}")
    print(f"加密得到的密文 C: {c}")
    
    # 使用暴力破解寻找所有可能的密钥
    keys, _ = brute_force_crack(p, c, num_threads=4)
    
    if len(keys) > 1:
        print(f">>> 结论：对于这组随机明密文对，【存在不止一个】密钥可以完成正确的加解密转换！")
    else:
        print(f">>> 结论：对于这组随机明密文对，只存在【唯一】的正确密钥。")
    print("="*50 + "\n")

def test_key_collisions_for_given_plaintext():
    """
    封闭测试 2：给定明文 P_n，测试不同密钥 K_i != K_j 加密得到相同密文 C_n 的情况
    """
    print("="*50)
    print("【第5关封闭测试分析 2：同一明文下的密文碰撞分析】")
    
    p = "10101010" # 任意选定一个固定明文
    print(f"选定固定明文 P_n: {p}")
    
    # 字典用于映射 密文 -> 对应的密钥列表
    ciphertext_map = {}
    
    # 遍历所有 1024 种密钥
    for i in range(1024):
        k = format(i, '010b')
        c = encrypt_8bit(p, k)
        
        if c not in ciphertext_map:
            ciphertext_map[c] = []
        ciphertext_map[c].append(k)
        
    # 分析结果
    total_unique_ciphertexts = len(ciphertext_map)
    print(f"使用全部 1024 种密钥加密该明文，共产生了 {total_unique_ciphertexts} 种不同的密文。")
    
    # 筛选出有碰撞的密文（即对应多个密钥的密文）
    collisions = {c: keys for c, keys in ciphertext_map.items() if len(keys) > 1}
    print(f"其中，有 {len(collisions)} 种密文是由不同的密钥加密生成的（发生碰撞）。")
    
    if collisions:
        print(">>> 结论：给定明文空间任意给定的明文分组 P_n，【会出现】选择不同密钥加密得到相同密文的情况。")
        # 展示一个碰撞的例子
        example_c = list(collisions.keys())[0]
        example_keys = collisions[example_c]
        print(f">>> 碰撞实例：使用密钥 {example_keys[0]} 和 {example_keys[1]} 对明文 {p} 加密，得到的密文全是 {example_c}！")
    else:
        print(">>> 结论：未发现不同密钥生成相同密文的情况（在 S-DES 的 8-bit 空间中这几乎不可能发生，通常都会有碰撞）。")
    print("="*50 + "\n")

if __name__ == "__main__":
    # 执行破解测试
    test_p = "01110010"
    test_c = "11110010"
    
    print("--- 启动第4关：多线程暴力破解展示 ---")
    brute_force_crack(test_p, test_c, num_threads=8)
    
    print("\n--- 启动第5关：封闭测试理论分析 ---")
    # 运行封闭测试 1
    test_multiple_keys_for_random_pair()
    
    # 运行封闭测试 2
    test_key_collisions_for_given_plaintext()