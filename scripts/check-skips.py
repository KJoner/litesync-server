#!/usr/bin/env python3
"""检查 `go test -json` 输出里的跳过用例（CI 门禁：必需的用例不能用 skip 冒充通过）。

用法：
    python3 scripts/check-skips.py go-test.json                 # 不允许任何跳过（PostgreSQL job）
    python3 scripts/check-skips.py go-test.json 'LITESYNC_TEST_PG_DSN'
        # 只允许跳过原因匹配这个正则的用例（SQLite job：PG 专用用例由 PG job 负责）

跳过原因取该用例自己的输出（t.Skip 的消息）。退出码 0 = 通过，1 = 有不被允许的跳过。
"""
import json
import re
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    allow = re.compile(sys.argv[2]) if len(sys.argv) > 2 else None
    outputs: dict[tuple[str, str], list[str]] = {}
    skipped: list[tuple[str, str]] = []
    with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            test = ev.get("Test")
            if not test:
                continue
            key = (ev.get("Package", ""), test)
            if ev.get("Action") == "output":
                outputs.setdefault(key, []).append(ev.get("Output", ""))
            elif ev.get("Action") == "skip":
                skipped.append(key)
    bad = []
    for key in skipped:
        reason = "".join(outputs.get(key, [])).strip()
        if allow is None or not allow.search(reason):
            bad.append((key, reason))
    print(f"skipped tests: {len(skipped)}; not allowed: {len(bad)}")
    for (pkg, test), reason in bad:
        print(f"  {pkg} {test}: {reason[:300]}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
