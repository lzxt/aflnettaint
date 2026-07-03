#!/usr/bin/env python3
import os
import sys
import json
import pickle
import hashlib
import httpx
import re
from pathlib import Path
from typing import List, Dict, Tuple
from openai import OpenAI

# ================= 配置区 =================
API_KEY = os.getenv("DASHSCOPE_API_KEY", "sk-ef867978d1204cf0b04154cbad94f6dd")
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
MODEL_NAME = "qwen-plus" 
CACHE_FILE = ".kb_cache.pkl"

# ================= 客户端初始化 =================

def get_client():
    try:
        for env_var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
            if env_var in os.environ: del os.environ[env_var]
        
        http_client = httpx.Client(trust_env=False, timeout=60.0)
        return OpenAI(api_key=API_KEY, base_url=BASE_URL, http_client=http_client)
    except Exception as e:
        print(f"[!] 初始化客户端失败: {e}", file=sys.stderr)
        sys.exit(1)

# ================= 路径处理 =================

def find_knowledge_base_dir() -> Path:
    search_paths = [
        Path("/aflnetupnpllm/knowledge_base"),
        Path(__file__).parent.parent.parent / "knowledge_base",
        Path.cwd() / "knowledge_base"
    ]
    for path in search_paths:
        if path.exists() and path.is_dir(): return path
    return Path("./knowledge_base")

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
    增强版 HTTP 报文修复：
    1. 自动处理多种换行符 (\n, \r\n)。
    2. 精准定位 Header 与 Body 的分界线。
    3. 自动计算并填充 10 位补零的 Content-Length。
    """
    # 预处理：移除代码块标记，统一换行符为 \n 便于处理
    raw_text = raw_text.strip()
    raw_text = re.sub(r'^```[^\n]*\n', '', raw_text)
    raw_text = re.sub(r'\n```$', '', raw_text)
    
    # 将所有可能的换行符统一转为 \n 以便分割
    normalized_text = raw_text.replace("\r\n", "\n")
    
    # 寻找 Header 和 Body 的分界（即第一个空行）
    if "\n\n" in normalized_text:
        header_part, body_part = normalized_text.split("\n\n", 1)
    else:
        # 如果 LLM 没给空行，尝试寻找第一个 XML 标签作为 Body 起点
        xml_start = normalized_text.find("<?xml")
        if xml_start != -1:
            header_part = normalized_text[:xml_start].strip()
            body_part = normalized_text[xml_start:].strip()
        else:
            header_part = normalized_text
            body_part = ""

    # 处理 Body：转回 bytes 字节流用于计算长度
    body_bytes = body_part.strip().encode('utf-8', errors='ignore')
    content_length = len(body_bytes)
    
    # 重新构建 Header
    new_headers = []
    has_cl = False
    
    for line in header_part.split("\n"):
        line = line.strip()
        if not line: continue
        
        # 匹配并替换原有的 Content-Length
        if re.match(r'(?i)Content-Length\s*:', line):
            new_headers.append(f"Content-Length: {content_length:010d}")
            has_cl = True
        else:
            new_headers.append(line)
            
    if not has_cl:
        new_headers.append(f"Content-Length: {content_length:010d}")
        
    # 拼接最终报文，使用标准网络换行符 \r\n
    final_header = "\r\n".join(new_headers)
    return final_header.encode('ascii', errors='ignore') + b"\r\n\r\n" + body_bytes

# ================= RAG 逻辑类 =================

class RAGManager:
    def __init__(self, kb_dir: Path):
        self.kb_dir = kb_dir
        self.client = get_client()
        self.cache = self._load_cache()

    def _load_cache(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "rb") as f: return pickle.load(f)
            except: return {}
        return {}

    def _save_cache(self):
        with open(CACHE_FILE, "wb") as f: pickle.dump(self.cache, f)

    def load_and_embed(self):
        print(f"[*] 扫描知识库: {self.kb_dir}")
        files = list(self.kb_dir.glob("**/*.c")) + list(self.kb_dir.glob("**/*.xml")) + list(self.kb_dir.glob("**/*.h"))
        
        updated = False
        for f_path in files:
            try:
                content = f_path.read_text(encoding='utf-8', errors='ignore')
                f_hash = get_text_hash(content)
                if f_hash not in self.cache:
                    print(f"[*] 建立索引: {f_path.name}")
                    resp = self.client.embeddings.create(model="text-embedding-v2", input=[content[:2000]])
                    self.cache[f_hash] = {
                        "content": content[:3000], 
                        "embedding": resp.data[0].embedding,
                        "name": str(f_path.relative_to(self.kb_dir))
                    }
                    updated = True
            except Exception as e: pass
        if updated: self._save_cache()

    def query(self, text: str, top_k=3) -> str:
        resp = self.client.embeddings.create(model="text-embedding-v2", input=[text])
        q_emb = resp.data[0].embedding
        scores = []
        for h, data in self.cache.items():
            score = cosine_similarity(q_emb, data['embedding'])
            scores.append((score, data['content'], data['name']))
        scores.sort(key=lambda x: x[0], reverse=True)
        return "\n".join([f"--- Source: {n} ---\n{c}" for s, c, n in scores[:top_k]])

# ================= 执行逻辑 =================

def generate_diverse_seeds(rag: RAGManager, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    context = rag.query("UPnP SOAP action, GetExternalIPAddress, AddPortMapping, HTTP POST")
    
    prompt = f"""
    你是安全专家。基于以下代码，生成 3 个用于模糊测试的 UPnP SOAP HTTP POST 请求。
    
    {context}
    
    要求：
    1. 严禁输出 Markdown 代码块。只输出原始报文。
    2. 每个种子之间必须用 '###SEED_SEP###' 分隔。
    3. 每个报文必须有 Header 和 Body（XML 内容）。
    """

    print("[*] 正在向 LLM 请求新种子...")
    response = rag.client.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7
    )
    
    raw_output = response.choices[0].message.content.strip()
    seeds = raw_output.split("###SEED_SEP###")
    
    for i, s_content in enumerate(seeds):
        if len(s_content.strip()) < 50: continue
        try:
            fixed_data = fix_http_packet(s_content.strip())
            out_path = os.path.join(output_dir, f"seed_{i+1}.raw")
            with open(out_path, "wb") as f:
                f.write(fixed_data)
            print(f"[+] 成功生成种子: {out_path} ({len(fixed_data)} 字节)")
        except Exception as e:
            print(f"[!] 修复种子 {i+1} 失败: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_seed_with_rag.py <output_dir>")
        sys.exit(1)
    
    output_dir = sys.argv[1]
    rag = RAGManager(KNOWLEDGE_BASE_DIR)
    try:
        rag.load_and_embed()
        generate_diverse_seeds(rag, output_dir)
    except Exception as e:
        print(f"[!] 运行失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
