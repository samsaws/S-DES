# gui/main_window.py

import tkinter as tk
from tkinter import messagebox
from core import sdes

class SDESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("S-DES 加解密系统 (Python Tkinter)")
        self.root.geometry("550x450")
        
        # 模式选择区
        self.mode_var = tk.StringVar(value="8bit")
        mode_frame = tk.LabelFrame(root, text="1. 选择数据模式", font=("Arial", 10, "bold"))
        mode_frame.pack(padx=15, pady=10, fill="x")
        
        tk.Radiobutton(mode_frame, text="8-bit 二进制模式 (第1关)", variable=self.mode_var, value="8bit").pack(side="left", padx=20, pady=5)
        tk.Radiobutton(mode_frame, text="ASCII 字符串模式 (第3关)", variable=self.mode_var, value="ascii").pack(side="left", padx=20, pady=5)
        
        # 密钥输入区
        key_frame = tk.Frame(root)
        key_frame.pack(padx=15, pady=5, fill="x")
        tk.Label(key_frame, text="10-bit 密钥: ", font=("Arial", 10, "bold")).pack(side="left")
        self.key_entry = tk.Entry(key_frame, width=25, font=("Courier", 12))
        self.key_entry.pack(side="left", padx=10)
        self.key_entry.insert(0, "0000000000") # 默认密钥提示
        
        # 输入数据区
        input_frame = tk.LabelFrame(root, text="2. 输入数据 (明文/密文)", font=("Arial", 10, "bold"))
        input_frame.pack(padx=15, pady=10, fill="x")
        self.input_text = tk.Text(input_frame, height=4, font=("Courier", 11), wrap="word")
        self.input_text.pack(padx=10, pady=5, fill="x")
        
        # 按钮交互区
        btn_frame = tk.Frame(root)
        btn_frame.pack(padx=15, pady=5)
        # 使用醒目的颜色区分加密和解密
        tk.Button(btn_frame, text="⬇ S-DES 加密 ⬇", command=self.encrypt, bg="#ADD8E6", font=("Arial", 10, "bold"), width=18, height=2).pack(side="left", padx=20)
        tk.Button(btn_frame, text="⬇ S-DES 解密 ⬇", command=self.decrypt, bg="#90EE90", font=("Arial", 10, "bold"), width=18, height=2).pack(side="left", padx=20)
        
        # 输出结果区
        output_frame = tk.LabelFrame(root, text="3. 输出结果", font=("Arial", 10, "bold"))
        output_frame.pack(padx=15, pady=10, fill="x")
        self.output_text = tk.Text(output_frame, height=4, font=("Courier", 11), wrap="word")
        self.output_text.pack(padx=10, pady=5, fill="x")

    def validate_key(self, key):
        """校验密钥是否严格为10位二进制"""
        if len(key) != 10 or not all(c in '01' for c in key):
            messagebox.showerror("密钥错误", "密钥必须是确切的 10位 二进制数 (仅包含0和1)！")
            return False
        return True

    def validate_8bit_data(self, data):
        """校验8-bit模式下的输入是否合法"""
        if len(data) != 8 or not all(c in '01' for c in data):
            messagebox.showerror("数据错误", "8-bit模式下，输入数据必须是确切的 8位 二进制数！")
            return False
        return True

    def encrypt(self):
        """处理加密点击事件"""
        key = self.key_entry.get().strip()
        data = self.input_text.get("1.0", tk.END).strip()
        
        if not self.validate_key(key): return
        if not data:
            messagebox.showwarning("警告", "请输入需要加密的数据！")
            return
            
        mode = self.mode_var.get()
        self.output_text.delete("1.0", tk.END) # 清空输出区
        
        try:
            if mode == "8bit":
                if not self.validate_8bit_data(data): return
                result = sdes.encrypt_8bit(data, key)
            else:
                # ASCII 模式直接传入字符串，返回二进制密文串
                result = sdes.encrypt_ascii(data, key)
            self.output_text.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("加密异常", f"执行加密时发生错误:\n{str(e)}")

    def decrypt(self):
        """处理解密点击事件"""
        key = self.key_entry.get().strip()
        data = self.input_text.get("1.0", tk.END).strip()
        
        if not self.validate_key(key): return
        if not data:
            messagebox.showwarning("警告", "请输入需要解密的数据！")
            return
            
        mode = self.mode_var.get()
        self.output_text.delete("1.0", tk.END)
        
        try:
            if mode == "8bit":
                if not self.validate_8bit_data(data): return
                result = sdes.decrypt_8bit(data, key)
            else:
                # ASCII 模式解密时，输入必须是二进制密文（清理掉可能误敲的空格）
                clean_data = data.replace(" ", "").replace("\n", "")
                if len(clean_data) % 8 != 0 or not all(c in '01' for c in clean_data):
                    messagebox.showerror("解密错误", "ASCII模式下解密，输入必须是长度为 8 的倍数的二进制密文序列！")
                    return
                result = sdes.decrypt_ascii(clean_data, key)
            self.output_text.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("解密异常", f"执行解密时发生错误:\n{str(e)}")