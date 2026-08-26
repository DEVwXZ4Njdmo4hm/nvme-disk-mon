#!/usr/bin/env sh

#########################################################################################################
# This script sets up Visual Studio Code with the necessary operations for development.
# Before running it, ensure 4 things below:
# 1. You have a Python 3.14+ and pip in your PATH, a virtual environment at "$PWD/.venv" is required.
# 2. Open the project folder in VS Code.
# 3. Install the "rust-analyzer" extension in VS Code.
# 4. Execute this script in the root of the project folder.
#
# NO PREFLIGHT CHECK WILL BE PERFORMED, PREPARE ENVIRONMENT PROPERLY.
#########################################################################################################

_success=0
_err_at_pip=1
_err_at_build_script=2
_err_at_rustup=3
_err_at_rust_analyzer=4

. $PWD/.venv/bin/activate

pip3 install -r requirements.txt

ret=$?
if [ $ret -ne 0 ];
then
    printf "Failed on pip, exit code is:%d\n" "$ret"
    exit ${_err_at_pip}
fi

rm -rf "$PWD/build"; mkdir "$PWD/build"

python3 "$PWD/scripts/build-script/src/main.py" -S . -B $PWD/build -T Debug --init-only

ret=$?
if [ $ret -ne 0 ];
then
    printf "Failed on build script, exit code is: %d\n" "$ret"
    exit ${_err_at_build_script}
fi

export CARGO_HOME="$PWD/build/rust/cargo"
export RUSTUP_HOME="$PWD/build/rust/rustup"
export PATH="$CARGO_HOME/bin:$PATH"

rustup component add --toolchain stable rust-analyzer rust-src rustfmt

ret=$?
if [ $ret -ne 0 ];
then
    printf "Failed on rustup, exit code is: %d\n" "$ret"
    exit ${_err_at_rustup}
fi

if ! command -v rust-analyzer >/dev/null 2>&1;
then
    printf "Although successfully installed rust-analyzer, "
    printf "but current shell is still can't found it in PATH.\n"
    exit ${_err_at_rust_analyzer}
fi

exit ${_success}
