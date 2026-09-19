#!/usr/bin/env python3
"""Encrypt a GitHub token with a PIN and write gate.json."""
import base64
import getpass
import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = "fiona-fong/fiona-fong.github.io"
ITER = 120000
GH = "/Users/t02/bin/gh"


def token_from_gh():
    env = os.environ.copy()
    env["PATH"] = "/Users/t02/bin:" + env.get("PATH", "")
    out = subprocess.check_output([GH, "auth", "token"], text=True, env=env)
    return out.strip()


def encrypt(pin, token):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, ITER, dklen=32)
    raw = token.encode("utf-8")
    enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return {
        "v": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iter": ITER,
        "data": base64.b64encode(enc).decode("ascii"),
        "repo": REPO,
    }


def main():
    pin = os.environ.get("FF_PIN") or getpass.getpass("請輸入編輯密碼（至少 4 位）：")
    pin = pin.strip()
    if len(pin) < 4:
        sys.exit("密碼太短")
    if not os.environ.get("FF_PIN"):
        pin2 = getpass.getpass("再輸入一次：").strip()
        if pin != pin2:
            sys.exit("兩次密碼唔同")
    token = os.environ.get("FF_TOKEN") or token_from_gh()
    if not token.startswith(("ghp_", "gho_", "github_pat_")):
        sys.exit("未能取得 GitHub Token")
    gate = encrypt(pin, token)
    path = os.path.join(ROOT, "gate.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(gate, f, indent=2)
        f.write("\n")
    print("已寫入", path)


if __name__ == "__main__":
    main()
