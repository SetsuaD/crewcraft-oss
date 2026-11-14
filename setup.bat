@echo off
cd /d "%~dp0"
echo   CrewCraft - setup
where git >nul 2>&1 || (echo ERROR: Git not found. & pause & exit /b 1)
where cargo >nul 2>&1 || (echo ERROR: Rust not found. Install it from https://rustup.rs and re-run. & pause & exit /b 1)
rustup component add rustfmt clippy
cargo fetch --locked
echo   Setup complete.
pause
