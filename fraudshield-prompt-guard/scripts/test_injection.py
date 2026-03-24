# test_injection.py

import sys
import os

# Add parent directory to sys.path so 'src' can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.yara_scanner import run_yara_scan

def test_prompts(file_path):
    if not os.path.exists(file_path):
        print(f"Error: test file not found at {file_path}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        prompts = [line.strip() for line in f if line.strip()]

    print("\n🔍 Running Prompt Injection Tests...\n")

    for i, prompt in enumerate(prompts):
        try:
            result = run_yara_scan(prompt)
        except Exception as e:
            result = f"Error: {e}"

        print(f"Test {i+1}: {prompt}")
        print(f"Result: {result}")
        print("-" * 50)

if __name__ == "__main__":
    test_file_path = os.path.join(os.path.dirname(__file__), "..", "data", "test_prompts.txt")
    test_prompts(test_file_path)