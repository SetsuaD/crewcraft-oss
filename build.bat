@echo off
cd /d "%~dp0"
bash ci\validate.sh || (echo GATE FAILED. & pause & exit /b 1)
cargo build --release --workspace --locked
pause
