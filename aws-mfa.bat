@echo off

set VENV_DIR=D:\Learning\MLOps\aws-mfa\.venv
set SCRIPT_DIR=D:\Learning\MLOps\aws-mfa\

pushd %SCRIPT_DIR%
call %VENV_DIR%\Scripts\activate.bat
python aws-mfa.py
deactivate
popd