# Malware PE Analyzer

自动化提取 PE 文件的哈希值（MD5/SHA1/SHA256）和导入表，支持批量递归扫描，输出 CSV 报告。

## 功能
- 递归扫描指定目录下的 PE 文件（.exe, .dll, .sys 等）
- 计算常见哈希值
- 提取导入表（DLL 名称 + 导入函数）
- 多线程并发加速
- 结果导出为 CSV，便于数据透视

## 安装
```bash
pip install pefile tqdm
