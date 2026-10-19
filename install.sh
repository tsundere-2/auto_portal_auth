#!/usr/bin/env bash
# ===========================================================================
#  AutoPortalAuth - Linux / macOS 安装脚本
#  用法：  sudo 不需要；直接执行  ./install.sh
#         可选参数： --method systemd|launchd|none   --no-autostart
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")"

METHOD="auto"
AUTOSTART=1
while [ $# -gt 0 ]; do
  case "$1" in
    --method)    METHOD="${2:-auto}"; shift 2 ;;
    --method=*)  METHOD="${1#*=}"; shift ;;
    --no-autostart) AUTOSTART=0; shift ;;
    -h|--help)   sed -n '2,9p' "$0"; exit 0 ;;
    *)           echo "[!] 未知参数: $1"; exit 2 ;;
  esac
done

echo
echo "==========================================================="
echo "  AutoPortalAuth 安装程序"
echo "==========================================================="
echo

# ---------- 1. 查找 Python --------------------------------------------------
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
  echo "[X] 未找到 Python3。"
  echo "    Debian/Ubuntu: sudo apt install python3 python3-pip python3-venv"
  echo "    macOS:         brew install python3"
  exit 1
fi
echo "[1/5] 已找到 $($PY -c 'import sys;print("Python "+sys.version.split()[0])') ($PY)"

# ---------- 2. 安装依赖 -----------------------------------------------------
echo
echo "[2/5] 安装依赖 (requests / PyYAML / psutil) ..."
if ! $PY -m pip install --quiet --upgrade pip 2>/dev/null; then
  echo "      (pip 升级失败，忽略)"
fi
if ! $PY -m pip install -r requirements.txt 2>/dev/null; then
  echo "      普通安装失败，尝试 --user 模式 ..."
  $PY -m pip install --user -r requirements.txt
fi
echo "      依赖安装完成。"

# ---------- 3. 生成配置 -----------------------------------------------------
echo
echo "[3/5] 检查配置文件 ..."
if [ ! -f config.yaml ]; then
  $PY auto_portal_auth.py status >/dev/null 2>&1 || true
  echo "      已生成默认 config.yaml"
else
  echo "      config.yaml 已存在，保留原有配置。"
fi

# ---------- 4. 自检 + 试运行 ------------------------------------------------
echo
echo "[4/5] 运行自检 ..."
$PY auto_portal_auth.py selftest || echo "[!] 自检存在失败项"

echo
echo "[4/5] 试运行一次网络检测 ..."
set +e
$PY auto_portal_auth.py once --no-trigger
CODE=$?
set -e
echo "      (退出码: 0=正常 1=未知 2=需要认证 3=链路断开, 实际=$CODE)"

# ---------- 5. 安装开机自启 -------------------------------------------------
echo
if [ "$AUTOSTART" = "1" ]; then
  echo "[5/5] 安装开机自启 (method=$METHOD) ..."
  $PY auto_portal_auth.py install --method "$METHOD" --start-now || \
    echo "[!] 自启安装失败，可稍后手动执行: $PY auto_portal_auth.py install"
else
  echo "[5/5] 已跳过开机自启安装。"
fi

cat <<EOF

===========================================================
  安装完成
-----------------------------------------------------------
  查看状态:  $PY auto_portal_auth.py status
  查看统计:  $PY auto_portal_auth.py stats
  超时分析:  $PY auto_portal_auth.py analyze
  常驻运行:  $PY auto_portal_auth.py run
  卸载自启:  $PY auto_portal_auth.py uninstall
  日志文件:  logs/auto_portal_auth.log
===========================================================

  提示：将 config.yaml 中 auth.auto_login.enabled 改为 true 并填入
        账号密码，即可实现无人值守的全自动登录。
EOF
