@echo off
chcp 65001 >nul
title 安装 AutoPortalAuth 看门狗计划任务
echo ============================================================
echo  以管理员身份安装看门狗计划任务
echo  触发：登录后20秒 / 每5分钟 / 系统唤醒后3秒
echo ============================================================
echo.

cd /d "%~dp0.."
if not exist "auto_portal_auth.py" (
    echo [错误] 找不到 auto_portal_auth.py，请把本文件放在项目目录下运行
    pause
    exit /b 1
)

schtasks /Create /TN "AutoPortalAuthWatchdog" /XML "%~dp0wd.xml" /F
if errorlevel 1 (
    echo.
    echo [失败] 创建任务失败，请检查上面的错误信息
    pause
    exit /b 1
)

echo.
echo [成功] 计划任务已创建。立即验证一次：
schtasks /Run /TN "AutoPortalAuthWatchdog"
timeout /t 8 /nobreak >nul
schtasks /Query /TN "AutoPortalAuthWatchdog" /FO LIST | findstr /i "状态 Status 上次运行 Last"
echo.
echo 完成后可按任意键关闭。
pause >nul
