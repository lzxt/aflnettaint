#!/usr/bin/env python3
import os
import sys
import json
import pickle
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple
from openai import OpenAI

# ================= 配置区 =================
# 建议通过环境变量设置：export DASHSCOPE_API_KEY='your_key'
API_KEY = os.getenv("DASHSCOPE_API_KEY", "sk-ef867978d1204cf0b04154cbad94f6dd")
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
MODEL_NAME = "qwen-plus" 

# 缓存文件，避免重复为相同的源码生成向量
CACHE_FILE = ".kb_cache.pkl"

# 延迟初始化客户端以避免版本兼容性问题
_client = None

def get_client():
    """获取 OpenAI 客户端（延迟初始化）"""
    global _client
    if _client is None:
        try:
            # 方法1: 标准初始化
            _client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
        except (TypeError, AttributeError) as e:
            # 方法2: 如果标准方式失败，可能是 httpx 版本问题
            # 尝试升级 httpx 或使用环境变量
            try:
                # 设置环境变量来避免某些参数问题
                os.environ.pop('HTTP_PROXY', None)
                os.environ.pop('HTTPS_PROXY', None)
                os.environ.pop('http_proxy', None)
                os.environ.pop('https_proxy', None)
                
                # 再次尝试标准初始化
                _client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
            except Exception as e2:
                # 方法3: 尝试使用 requests 库作为后备（如果可用）
                try:
                    import requests
                    # 使用 requests 适配器
                    import httpx
                    # 创建最简单的 httpx 客户端
                    http_client = httpx.Client(timeout=60.0)
                    _client = OpenAI(api_key=API_KEY, base_url=BASE_URL, http_client=http_client)
                except Exception as e3:
                    print(f"[!] 无法初始化 OpenAI 客户端", file=sys.stderr)
                    print(f"    原始错误: {e}", file=sys.stderr)
                    print(f"    尝试2错误: {e2}", file=sys.stderr)
                    print(f"    尝试3错误: {e3}", file=sys.stderr)
                    print(f"\n    解决方案:", file=sys.stderr)
                    print(f"    1. 升级 httpx: pip install --upgrade httpx", file=sys.stderr)
                    print(f"    2. 升级 openai: pip install --upgrade openai", file=sys.stderr)
                    print(f"    3. 或者降级: pip install 'httpx<0.24' 'openai<1.0'", file=sys.stderr)
                    raise
    return _client

# ================= 路径处理 =================
def find_knowledge_base_dir() -> Path:
    """查找knowledge_base目录，支持多种路径"""
    # 脚本在 tutorials/upnp/ 目录下，需要向上查找3级到项目根目录
    search_paths = [
        Path(__file__).parent.parent.parent / "knowledge_base",  # 从 tutorials/upnp/ 向上3级
        Path.cwd() / "knowledge_base",  # 当前工作目录
        Path.cwd().parent / "knowledge_base",  # 当前目录的父目录
    ]
    # 如果设置了AFL_PATH环境变量，也尝试从那里查找
    afl_path = os.getenv("AFL_PATH")
    if afl_path:
        search_paths.insert(0, Path(afl_path) / "knowledge_base")
    
    for path in search_paths:
        if path.exists():
            return path
    
    # 如果都找不到，返回默认路径（相对于脚本位置）
    return Path(__file__).parent.parent.parent / "knowledge_base"

KNOWLEDGE_BASE_DIR = find_knowledge_base_dir()

# ================= 核心工具函数 =================

def get_text_hash(text: str) -> str:
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def cosine_similarity(v1, v2):
    dot = sum(a * b for a, b in zip(v1, v2))
    norm1 = sum(a * a for a in v1) ** 0.5
    norm2 = sum(b * b for b in v2) ** 0.5
    return dot / (norm1 * norm2) if norm1 * norm2 > 0 else 0

def fix_http_packet(raw_text: str) -> bytes:
    """
    严格修复HTTP报文：
    1. 确保 \r\n 换行
    2. 自动计算并格式化 10位 Content-Length
    """
    # 清理 Markdown 标记
    lines = [line for line in raw_text.strip().splitlines() if not line.strip().startswith("```")]
    raw_content = "\n".join(lines).replace("\r\n", "\n").replace("\n", "\r\n")
    
    # 分割 header 和 body
    parts = raw_content.split("\r\n\r\n", 1)
    header_section = parts[0] if parts else ""
    body_section = parts[1] if len(parts) > 1 else ""
    
    # 确保 header 不为空（至少要有请求行）
    if not header_section.strip():
        raise ValueError("HTTP请求缺少header部分")
    
    body_bytes = body_section.encode('utf-8', errors='ignore')
    content_length = len(body_bytes)
    
    # 重新构建 Header
    new_headers = []
    has_content_length = False
    for line in header_section.split("\r\n"):
        if line.strip() and line.lower().startswith("content-length:"):
            new_headers.append(f"Content-Length: {content_length:010d}")
            has_content_length = True
        elif line.strip():  # 忽略空行
            new_headers.append(line)
            
    # 如果没找到 Content-Length，在header末尾补上
    if not has_content_length:
        new_headers.append(f"Content-Length: {content_length:010d}")
        
    return "\r\n".join(new_headers).encode('ascii', errors='ignore') + b"\r\n\r\n" + body_bytes

# ================= RAG 逻辑类 =================

class RAGManager:
    def __init__(self, kb_dir: Path):
        self.kb_dir = kb_dir
        self.cache = self._load_cache()

    def _load_cache(self):
        """加载缓存，如果文件损坏则返回空字典"""
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "rb") as f:
                    return pickle.load(f)
            except (pickle.UnpicklingError, EOFError, IOError) as e:
                print(f"[!] 缓存文件损坏，将重新生成: {e}", file=sys.stderr)
                return {}
        return {}

    def _save_cache(self):
        with open(CACHE_FILE, "wb") as f: pickle.dump(self.cache, f)

    def load_and_embed(self):
        """加载文件并生成向量（带缓存）"""
        print(f"[*] 扫描知识库: {self.kb_dir}")
        files = list(self.kb_dir.glob("**/*.c")) + list(self.kb_dir.glob("**/*.xml"))
        
        updated = False
        for f_path in files:
            content = f_path.read_text(encoding='utf-8', errors='ignore')
            f_hash = get_text_hash(content)
            
            if f_hash not in self.cache:
                print(f"[*] 为 {f_path.name} 生成向量...")
                resp = get_client().embeddings.create(model="text-embedding-ada-002", input=[content[:2000]])
                self.cache[f_hash] = {
                    "content": content[:4000], # 存储部分内容用于上下文
                    "embedding": resp.data[0].embedding,
                    "name": str(f_path.relative_to(self.kb_dir))
                }
                updated = True
        
        if updated: self._save_cache()

    def query(self, text: str, top_k=3) -> str:
        resp = get_client().embeddings.create(model="text-embedding-ada-002", input=[text])
        q_emb = resp.data[0].embedding
        
        scores = []
        for h, data in self.cache.items():
            score = cosine_similarity(q_emb, data['embedding'])
            scores.append((score, data['content'], data['name']))
        
        scores.sort(key=lambda x: x[0], reverse=True)
        context = ""
        for s, c, n in scores[:top_k]:
            context += f"\n--- Source: {n} ---\n{c}\n"
        return context

# ================= 生成逻辑 =================

def generate_diverse_seeds(context: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    
    prompt = f"""
    你是一个安全专家。请基于以下代码和接口定义，生成 3 个用于模糊测试的 UPnP SOAP HTTP 请求种子。
    
    {context}
    
    要求：
    1. 每个种子必须是一个完整的 HTTP POST 请求。
    2. 包含 SOAPAction 头，且必须符合知识库中的定义。
    3. Content-Length 必须存在（值可以随便写，我会后处理）。
    4. 种子 1：常规有效请求（如 GetExternalIPAddress）。
    5. 种子 2：带复杂参数的请求（如 AddPortMapping）。
    6. 种子 3：异常路径或边界值请求。
    
    请使用 '###SEED_SEP###' 作为三个请求之间的分隔符。
    只返回原始报文内容，不要有任何 Markdown 解释。
    """

    print("[*] 正在请求 LLM 生成多样化种子...")
    response = get_client().chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.8
    )
    
    raw_output = response.choices[0].message.content.strip()
    seeds = raw_output.split("###SEED_SEP###")
    
    generated_count = 0
    for i, seed_content in enumerate(seeds):
        seed_content = seed_content.strip()
        if len(seed_content) < 20:
            continue
        
        try:
            filename = f"seed_{i+1}.raw"
            fixed_data = fix_http_packet(seed_content)
            
            with open(os.path.join(output_dir, filename), "wb") as f:
                f.write(fixed_data)
            print(f"[+] 已生成种子: {filename} ({len(fixed_data)} bytes)")
            generated_count += 1
        except Exception as e:
            print(f"[!] 处理种子 {i+1} 时出错: {e}", file=sys.stderr)
            continue
    
    if generated_count == 0:
        raise ValueError("未能成功生成任何种子文件")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_seeds_rag.py <output_dir>")
        sys.exit(1)

    out_dir = sys.argv[1]
    rag = RAGManager(KNOWLEDGE_BASE_DIR)
    
    try:
        rag.load_and_embed()
        context = rag.query("UPnP SOAP request structure, SOAPAction, Service Type, XML Arguments")
        generate_diverse_seeds(context, out_dir)
        print("\n[!] 种子生成任务完成。请将这些种子放入 AFLnet 的输入目录。")
    except Exception as e:
        print(f"[!] 错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()