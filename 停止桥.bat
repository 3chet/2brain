@echo off
rem 停 secondbrain-bridge 对应的 node 实例（不影响其他 node 进程）
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | Where-Object { $_.CommandLine -like '*secondbrain-bridge*' } | ForEach-Object { Write-Host ('已停止 PID=' + $_.ProcessId); Stop-Process -Id $_.ProcessId -Force }"
curl -s -m 2 http://127.0.0.1:7723/health >nul 2>&1
if not errorlevel 1 (
  echo [iibrain] 桥仍在响应，可能有第二个实例，请再跑一次本脚本。
) else (
  echo [iibrain] 桥已停止。2brain 自动入库/相关记忆将静默降级，本地保存不受影响。
)
pause
