"""Strict single-pass renderer for deployment-owned templates."""

import math
import re
from collections.abc import Mapping
from pathlib import Path, PurePath

_NAME = r"[A-Za-z_][A-Za-z0-9_-]*"
_PLACEHOLDER_PATH = rf"{_NAME}\.(?:{_NAME}|__|__implicit__)\.{_NAME}"
_INLINE_PLACEHOLDER = re.compile(rf"@[ \t]+(?P<path>{_PLACEHOLDER_PATH})[ \t]+@")
_BLOCK_PLACEHOLDER = re.compile(
    rf"(?P<indent>[ \t]*)@@[ \t]+(?P<path>{_PLACEHOLDER_PATH})[ \t]+@@[ \t]*"
)


def _is_control(character: str) -> bool:
    codepoint = ord(character)
    return codepoint < 0x20 or 0x7F <= codepoint <= 0x9F


def _validate_scalar(value: str) -> None:
    if any(_is_control(character) for character in value):
        raise ValueError("template value contains a forbidden control character")


def _lookup(container: object, key: str, placeholder: str) -> object:
    if isinstance(container, Mapping):
        try:
            return container[key]
        except KeyError as exc:
            raise ValueError(f"unknown template value: {placeholder}") from exc
    try:
        return getattr(container, key)
    except AttributeError as exc:
        raise ValueError(f"unknown template value: {placeholder}") from exc


def _resolve(contexts: Mapping[str, object], placeholder: str) -> object:
    context_name, section_name, option_name = placeholder.split(".")
    context = _lookup(contexts, context_name, placeholder)
    section = context if section_name == "__" else _lookup(context, section_name, placeholder)
    return _lookup(section, option_name, placeholder)


def _inline_value(value: object, placeholder: str) -> str:
    if isinstance(value, str):
        rendered = value
    elif isinstance(value, bool):
        rendered = str(value).lower()
    elif isinstance(value, int):
        rendered = str(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"template value is not finite: {placeholder}")
        rendered = str(value)
    elif isinstance(value, PurePath):
        rendered = str(value)
    else:
        raise TypeError(f"unsupported template scalar: {placeholder}")
    _validate_scalar(rendered)
    return rendered


def _block_value(value: object, placeholder: str, indent: str, newline: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"block template value must be a string: {placeholder}")
    if value == "":
        return ""
    if "\r" in value or value.startswith("\n") or value.endswith("\n"):
        raise ValueError(f"block template value has invalid boundaries: {placeholder}")
    lines = value.split("\n")
    if len(lines) < 2:
        raise ValueError(f"block template value needs at least two lines: {placeholder}")
    for line in lines:
        _validate_scalar(line)
    separator = newline or "\n"
    return separator.join(f"{indent}{line}" for line in lines) + newline


def _line_parts(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    return line, ""


def _has_placeholder(text: str) -> bool:
    return "@@" in text or re.search(r"@[^@\r\n]*@", text) is not None


def render_template(template: str, contexts: Mapping[str, object]) -> str:
    if not isinstance(template, str) or not isinstance(contexts, Mapping):
        raise TypeError("template and contexts have invalid types")
    for character in template:
        if character not in {"\n", "\r", "\t"} and _is_control(character):
            raise ValueError("template contains a forbidden control character")

    rendered_lines: list[str] = []
    for source_line in template.splitlines(keepends=True):
        body, newline = _line_parts(source_line)
        block_match = _BLOCK_PLACEHOLDER.fullmatch(body)
        if block_match is not None:
            placeholder = block_match.group("path")
            rendered_lines.append(
                _block_value(
                    _resolve(contexts, placeholder),
                    placeholder,
                    block_match.group("indent"),
                    newline,
                )
            )
            continue
        if "@@" in body:
            raise ValueError("block template placeholders must occupy an entire line")
        skeleton = _INLINE_PLACEHOLDER.sub("", body)
        if _has_placeholder(skeleton):
            raise ValueError("template contains an unknown or malformed placeholder")

        def replacement(match: re.Match[str]) -> str:
            placeholder = match.group("path")
            return _inline_value(_resolve(contexts, placeholder), placeholder)

        rendered_lines.append(_INLINE_PLACEHOLDER.sub(replacement, body) + newline)
    return "".join(rendered_lines)


def render_template_file(
    source: Path,
    destination: Path,
    contexts: Mapping[str, object],
) -> None:
    rendered = render_template(source.read_text(encoding="utf-8"), contexts)
    destination.write_text(rendered, encoding="utf-8", newline="")


def systemd_escape(value: str) -> str:
    _validate_scalar(value)
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")


def systemd_exec_escape(value: str) -> str:
    return systemd_escape(value).replace("$", "$$")
