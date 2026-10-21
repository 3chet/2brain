@echo off
rem ============================================================
rem  启动桥.bat —— 2brain ? mnemon 记忆桥一键启动
rem  相对自身目录运行，文件夹整体搬家也可直接用
rem  已在运行时不会重复启动（探测 /health）
rem ============================================================
cd /d "%~dp0"

where node >nul 2>&1
if errorlevel 1 (
  echo [iibrain] 未找到 node 命令，请先安装 Node.js 并加入 PATH。
  pause
  exit /b 1
)

curl -s -m 2 http://127.0.0.1:7723/health >nul 2>&1
if not errorlevel 1 (
  echo [iibrain] 桥已在运行（http://127.0.0.1:7723），无需重复启动。
  echo.
  echo 当前库状态：
  curl -s -m 5 http://127.0.0.1:7723/health
  echo.
  pause
  exit /b 0
)

echo [iibrain] 正在后台启动记忆桥...
rem 内层 cmd 重定向子进程输出到 nul：防句柄继承导致外层阻塞
start "iibrain-bridge" /min cmd /c "node secondbrain-bridge.mjs ^>nul 2^>^&1"
timeout /t 2 /nobreak >nul

curl -s -m 5 http://127.0.0.1:7723/health >nul 2>&1
if errorlevel 1 (
  echo [iibrain] 启动失败或尚未就绪。可前台运行看报错：
  echo     cd /d "%~dp0"
  echo     node secondbrain-bridge.mjs
  pause
  exit /b 1
)

echo [iibrain] 启动成功 —— http://127.0.0.1:7723 任务栏最小化，勿关
echo.
echo 当前库状态：
curl -s -m 5 http://127.0.0.1:7723/health
echo.
echo 记忆库：%%USERPROFILE%%\.mnemon  %USERPROFILE%\.mnemon 即 DSH 同款库，2brain 直接可用。
pause
