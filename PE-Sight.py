#!/usr/bin/env python3

import os
import sys
import hashlib
import csv
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import pefile

# 尝试导入进度条库
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

def compute_hashes(file_path):
    """计算文件的 MD5, SHA1, SHA256"""
    hashers = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                for h in hashers.values():
                    h.update(chunk)
        return {name: h.hexdigest() for name, h in hashers.items()}
    except Exception as e:
        print(f"[!] Hash error {file_path}: {e}")
        return None

def extract_imports(file_path):
    """提取导入表，返回 [(dll_name, function_name), ...]"""
    imports = []
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
                    imports.append((dll_name, func_name))
        pe.close()
    except Exception as e:
        print(f"[!] PEFile error {file_path}: {e}")
    return imports

def analyze_file(file_path):
    """分析单个文件，返回结果字典"""
    hashes = compute_hashes(file_path)
    if not hashes:
        return None
    imports = extract_imports(file_path)
    # 将导入表转为字符串（便于CSV存储）
    imports_str = '; '.join([f"{dll}!{func}" for dll, func in imports])
    return {
        'filename': os.path.basename(file_path),
        'path': str(file_path),
        'md5': hashes['md5'],
        'sha1': hashes['sha1'],
        'sha256': hashes['sha256'],
        'import_count': len(imports),
        'imports': imports_str
    }

def scan_directory(directory, extensions=None, max_workers=8):
    """
    扫描目录下所有 PE 文件（默认 .exe, .dll, .sys, .ocx）
    使用线程池并发处理
    """
    if extensions is None:
        extensions = {'.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl'}
    
    files = []
    for root, _, filenames in os.walk(directory):
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in extensions:
                files.append(os.path.join(root, fname))
    
    if not files:
        print("[*] No PE files found.")
        return []

    print(f"[*] Found {len(files)} PE files. Analyzing...")
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(analyze_file, f): f for f in files}
        iterator = as_completed(future_to_file)
        if tqdm:
            iterator = tqdm(iterator, total=len(files), desc="Analyzing")
        for future in iterator:
            res = future.result()
            if res:
                results.append(res)
    return results

def save_csv(results, output_file):
    """保存结果到 CSV"""
    if not results:
        print("[!] No results to save.")
        return
    fieldnames = ['filename', 'path', 'md5', 'sha1', 'sha256', 'import_count', 'imports']
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"[+] Results saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Malware PE Analyzer - Extract hashes and import tables")
    parser.add_argument('directory', help="Directory to scan recursively")
    parser.add_argument('-o', '--output', default='analysis_report.csv', help="Output CSV file (default: analysis_report.csv)")
    parser.add_argument('-e', '--extensions', nargs='+', help="File extensions to scan (e.g., .exe .dll)", default=None)
    parser.add_argument('-w', '--workers', type=int, default=8, help="Max worker threads (default: 8)")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"[!] Invalid directory: {args.directory}")
        sys.exit(1)

    # 处理扩展名
    exts = set(args.extensions) if args.extensions else None
    results = scan_directory(args.directory, exts, args.workers)
    if results:
        save_csv(results, args.output)
    else:
        print("[!] No analysis results.")

if __name__ == '__main__':
    main()