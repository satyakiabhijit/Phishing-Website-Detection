import shutil
import os

src = r'C:\Users\abhij\.gemini\antigravity\brain\de6c7f5d-4e50-4343-a098-4df91d868cf5\system_architecture_1778320865704.png'
dst = r'd:\Projects\ML\Phishing-Website-Detection\paper_figures\fig1_system_architecture.png'

if os.path.exists(src):
    shutil.copy2(src, dst)
    print(f"Copied to {dst}")
    print(f"File size: {os.path.getsize(dst)} bytes")
else:
    print(f"Source not found: {src}")
