"""Run the installed NDM's authentication commands as root."""

from misc import BIN_PATH
from privilege import PrivilegeRunner


def authentication_commands(method: str) -> tuple[tuple[str, ...], ...]:
    binary = str(BIN_PATH)
    if method == "PLAIN":
        return ((binary, "mail", "validate"),)
    if method in {"XOAUTH2", "OAUTHBEARER"}:
        return (
            (binary, "mail", "authorize"),
            (binary, "mail", "validate"),
        )
    raise ValueError(f"未知 SMTP 认证方式：{method}")


def run_mail_authentication(runner: PrivilegeRunner, method: str) -> None:
    for command in authentication_commands(method):
        runner.run(command)
