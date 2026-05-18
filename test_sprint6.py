# simple_test.py
import subprocess
import sys

def test_import():
    try:
        import micropki
        print("✅ micropki imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_cli():
    result = subprocess.run("micropki --help", shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print("✅ CLI working")
        return True
    else:
        print(f"❌ CLI error: {result.stderr}")
        return False

if __name__ == "__main__":
    print("Testing MicroPKI...")
    test_import()
    test_cli()