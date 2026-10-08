# core/sdes.py

"""
S-DES (Simplified DES) 核心算法模块
包含所有的置换定义、密钥扩展机制和加解密核心功能。
"""

# ==========================================
# 1. 算法标准常量定义
# ==========================================

# 密钥扩展置换盒
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)

# 初始与最终置换盒
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)

# F函数轮函数置换盒
EPBox = (4, 1, 2, 3, 2, 3, 4, 1)
SPBox = (2, 4, 3, 1)

# S-Box 替换盒
SBox1 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 0, 2]
]

SBox2 = [
    [0, 1, 2, 3],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [2, 1, 0, 3]
]

# ==========================================
# 2. 基础辅助工具函数
# ==========================================

def apply_permutation(data_str, perm_box):
    """根据传入的置换盒重新排列字符串"""
    # 置换盒索引从1开始，Python索引从0开始，故 i-1
    return ''.join([data_str[i - 1] for i in perm_box])

def left_shift(data_str, shifts):
    """循环左移函数"""
    shifts = shifts % len(data_str)
    return data_str[shifts:] + data_str[:shifts]

def xor(str1, str2):
    """对两个等长的二进制字符串进行异或操作"""
    return ''.join(['1' if a != b else '0' for a, b in zip(str1, str2)])

# ==========================================
# 3. 核心算法逻辑
# ==========================================

def generate_keys(key_10bit):
    """从 10-bit 密钥生成两个 8-bit 子密钥 K1 和 K2"""
    # 1. P10 置换
    p10_key = apply_permutation(key_10bit, P10)
    left_half = p10_key[:5]
    right_half = p10_key[5:]

    # 2. LS-1 & P8 生成 K1
    left_half_1 = left_shift(left_half, 1)
    right_half_1 = left_shift(right_half, 1)
    k1 = apply_permutation(left_half_1 + right_half_1, P8)

    # 3. LS-2 & P8 生成 K2 (在LS-1的基础上再左移2位)
    left_half_2 = left_shift(left_half_1, 2)
    right_half_2 = left_shift(right_half_1, 2)
    k2 = apply_permutation(left_half_2 + right_half_2, P8)

    return k1, k2

def sbox_lookup(data_4bit, sbox):
    """S-Box 查找替换"""
    # 第1位和第4位组合为行号，第2位和第3位组合为列号
    row = int(data_4bit[0] + data_4bit[3], 2)
    col = int(data_4bit[1] + data_4bit[2], 2)
    val = sbox[row][col]
    return format(val, '02b') # 将整数格式化为2位二进制字符串

def f_function(right_half, subkey):
    """轮函数 F"""
    # EPBox 扩展
    ep_res = apply_permutation(right_half, EPBox)
    # 异或子密钥
    xor_res = xor(ep_res, subkey)
    
    # 拆分投入 S-Box
    left_4 = xor_res[:4]
    right_4 = xor_res[4:]
    s1_res = sbox_lookup(left_4, SBox1)
    s2_res = sbox_lookup(right_4, SBox2)
    
    # SPBox 直排置换
    return apply_permutation(s1_res + s2_res, SPBox)

# ==========================================
# 4. 对外加解密接口
# ==========================================

def encrypt_8bit(plaintext, key):
    """基础 8-bit 数据加密"""
    k1, k2 = generate_keys(key)
    ip_res = apply_permutation(plaintext, IP)

    # 提取 L0, R0
    l0 = ip_res[:4]
    r0 = ip_res[4:]

    # 第 1 轮 (f_K1 + SW)
    f1_res = f_function(r0, k1)
    l1 = r0                  # 交换后，原来的右半部分变成了左半部分
    r1 = xor(l0, f1_res)     # 交换后，计算结果变成了右半部分

    # 第 2 轮 (f_K2，无SW)
    f2_res = f_function(l1, k2)
    l2 = xor(r1, f2_res)
    r2 = l1                  # 注意第二轮后不进行交换操作

    return apply_permutation(l2 + r2, IP_INV)

def decrypt_8bit(ciphertext, key):
    """基础 8-bit 数据解密"""
    k1, k2 = generate_keys(key)
    ip_res = apply_permutation(ciphertext, IP)

    l0 = ip_res[:4]
    r0 = ip_res[4:]

    # 解密第 1 轮 (使用 K2 + SW)
    f1_res = f_function(r0, k2)
    l1 = r0
    r1 = xor(l0, f1_res)

    # 解密第 2 轮 (使用 K1，无SW)
    f2_res = f_function(l1, k1)
    l2 = xor(r1, f2_res)
    r2 = l1

    return apply_permutation(l2 + r2, IP_INV)

def encrypt_ascii(ascii_str, key):
    """ASCII 字符串加密"""
    # 将每个字符转为 8-bit 二进制
    binary_str = ''.join([format(ord(c), '08b') for c in ascii_str])
    cipher_bins = []
    
    # 每 8-bit 分组加密
    for i in range(0, len(binary_str), 8):
        block = binary_str[i:i+8]
        cipher_bins.append(encrypt_8bit(block, key))
        
    return ''.join(cipher_bins)

def decrypt_ascii(cipher_bin_str, key):
    """ASCII 字符串解密"""
    plain_bins = []
    
    # 每 8-bit 分组解密
    for i in range(0, len(cipher_bin_str), 8):
        block = cipher_bin_str[i:i+8]
        plain_bins.append(decrypt_8bit(block, key))
        
    # 将解密后的二进制串按 8-bit 转换回 ASCII 字符
    binary_str = ''.join(plain_bins)
    ascii_chars = []
    for i in range(0, len(binary_str), 8):
        char_code = int(binary_str[i:i+8], 2)
        ascii_chars.append(chr(char_code))
        
    return ''.join(ascii_chars)