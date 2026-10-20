#!/usr/bin/env python3
"""Map an n8n Error Trigger payload to a class, a notice, and a log line.

The fields this helper reads are the ones described on the n8n Error
Trigger docs page (execution.id, execution.url, execution.retryOf,
execution.error, workflow.id, workflow.name) plus trigger.error, which
that page says is present when the failure is in the main workflow's
trigger. Exact nesting differs by version. Check upstream docs.

execution.id and execution.url are optional in those docs: they are
absent when the execution was not saved, including when the error is in
the trigger node. execution.retryOf is optional and only present on a
retry. This helper copies them when they are strings or integers and
otherwise stores an empty string.

Classification rules are pack heuristics. They are not n8n categories.

Standard library only. No network.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from datetime import datetime, timezone
from typing import Any


RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("auth", ("401", "403", "unauthorized", "forbidden", "authentication failed", "credential")),
    ("rate_limit", ("429", "rate limit", "too many requests")),
    ("timeout", ("timed out", "timeout", "etimedout")),
    ("not_found", ("404", "not found", "enoent")),
    ("upstream", ("500", "502", "503", "504", "bad gateway", "service unavailable")),
    ("config", ("placeholder", "is not set", "missing required")),
)

SEVERITY = {
    "auth": "high",
    "upstream": "high",
    "timeout": "medium",
    "rate_limit": "medium",
    "unknown": "medium",
    "not_found": "low",
    "config": "low",
}

CODE_NEEDLES = {"401", "403", "404", "429", "500", "502", "503", "504"}
PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
SECRET_RES = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"(?i)\b(api[_-]?key|password|secret|token)\b\s*[:=]\s*\S+"),
)
MAX_MESSAGE = 500
MAX_STACK = 800
MAX_NAME = 200


def parse_time(value: str) -> datetime:
    text = (value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"now is not a timestamp this pack accepts: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def format_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def now_stamp(value: str | None) -> str:
    if not value:
        return format_time(datetime.now(timezone.utc))
    return format_time(parse_time(value))


def load_document(raw: str) -> dict[str, Any]:
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"payload is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("payload must be a JSON object")
    return document


def as_text(value: Any, limit: int) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        return ""
    cleaned = []
    for char in text:
        if char in "\n\t" or (ord(char) >= 32 and char != "\x7f"):
            cleaned.append(char)
    clipped = "".join(cleaned).strip()
    if len(clipped) > limit:
        return clipped[: limit - 3] + "..."
    return clipped


def redact(text: str) -> str:
    if not text:
        return ""
    text = PEM_RE.sub("[redacted]", text)
    for pattern in SECRET_RES:
        if pattern.groups:
            text = pattern.sub(lambda match: f"{match.group(1)}=[redacted]", text)
        else:
            text = pattern.sub("[redacted]", text)
    return text


def needle_hit(hay: str, needle: str) -> bool:
    if needle in CODE_NEEDLES:
        return re.search(r"(?<!\d)" + re.escape(needle) + r"(?!\d)", hay) is not None
    return needle in hay


def classify_blob(blob: str) -> str:
    hay = blob.lower()
    for name, needles in RULES:
        for needle in needles:
            if needle_hit(hay, needle):
                return name
    return "unknown"


def error_object(container: Any) -> dict[str, Any] | None:
    if not isinstance(container, dict):
        return None
    error = container.get("error")
    if isinstance(error, dict):
        return error
    return None


def copy_id(value: Any) -> str:
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return as_text(value, 200)
    return ""


def classify_payload(document: dict[str, Any], classified_at: str) -> dict[str, Any]:
    execution = document.get("execution") if isinstance(document.get("execution"), dict) else {}
    trigger = document.get("trigger") if isinstance(document.get("trigger"), dict) else {}
    workflow = document.get("workflow") if isinstance(document.get("workflow"), dict) else {}
    exec_error = error_object(execution)
    trig_error = error_object(trigger)
    if exec_error is not None:
        origin = "execution"
        error = exec_error
    elif trig_error is not None:
        origin = "trigger"
        error = trig_error
    else:
        origin = "unknown"
        error = {}
    message_raw = as_text(error.get("message"), MAX_MESSAGE)
    if not message_raw:
        message_raw = as_text(error.get("description"), MAX_MESSAGE)
    name_raw = as_text(error.get("name"), 120)
    description_raw = as_text(error.get("description"), MAX_MESSAGE)
    stack_raw = as_text(error.get("stack"), MAX_STACK)
    blob = "\n".join(part for part in (message_raw, name_raw, description_raw) if part)
    kind = classify_blob(blob) if origin != "unknown" or blob else "unknown"
    if origin == "unknown" and not blob:
        kind = "unknown"
    severity = SEVERITY[kind]
    message = redact(message_raw) or "no error message"
    stack = redact(stack_raw)
    error_name = redact(name_raw)
    workflow_name = as_text(workflow.get("name"), MAX_NAME)
    workflow_id = copy_id(workflow.get("id"))
    execution_id = copy_id(execution.get("id")) if origin == "execution" else ""
    execution_url = redact(as_text(execution.get("url"), 500)) if origin == "execution" else ""
    retry_of = copy_id(execution.get("retryOf")) if origin == "execution" else ""
    node = as_text(execution.get("lastNodeExecuted"), 200) if origin == "execution" else ""
    display_name = workflow_name or "unnamed workflow"
    subject = f"[n8n error][{severity}][{kind}] {display_name}"
    log_record = {
        "class": kind,
        "classified_at": classified_at,
        "error_name": error_name,
        "execution_id": execution_id,
        "execution_url": execution_url,
        "is_retry": bool(retry_of),
        "message": message,
        "node": node,
        "origin": origin,
        "retry_of": retry_of,
        "severity": severity,
        "workflow_id": workflow_id,
        "workflow_name": workflow_name,
    }
    text = render_text(log_record, stack)
    html = render_html(log_record, stack)
    telegram = render_telegram(log_record)
    return {
        "class": kind,
        "classified_at": classified_at,
        "error_name": error_name,
        "execution_id": execution_id,
        "execution_url": execution_url,
        "html": html,
        "html_bytes": len(html.encode("utf-8")),
        "is_retry": bool(retry_of),
        "log_record": log_record,
        "message": message,
        "node": node,
        "origin": origin,
        "retry_of": retry_of,
        "severity": severity,
        "stack": stack,
        "subject": subject,
        "telegram_text": telegram,
        "text": text,
        "text_bytes": len(text.encode("utf-8")),
        "workflow_id": workflow_id,
        "workflow_name": workflow_name,
    }


def render_text(record: dict[str, Any], stack: str) -> str:
    lines = [
        "n8n error / n8n 错误",
        f"class: {record['class']}",
        f"severity: {record['severity']}",
        f"origin: {record['origin']}",
        f"workflow: {record['workflow_name'] or 'unnamed workflow'} ({record['workflow_id'] or '-'})",
        f"node: {record['node'] or '-'}",
        f"execution: {record['execution_id'] or '-'}",
        f"retry_of: {record['retry_of'] or '-'}",
        f"url: {record['execution_url'] or '-'}",
        f"error_name: {record['error_name'] or '-'}",
        f"classified_at: {record['classified_at']}",
        "",
        record["message"],
    ]
    if stack:
        lines.extend(["", "stack:", stack])
    return "\n".join(lines) + "\n"


def render_telegram(record: dict[str, Any]) -> str:
    lines = [
        "n8n error / n8n 错误",
        f"class: {record['class']}",
        f"severity: {record['severity']}",
        f"workflow: {record['workflow_name'] or 'unnamed workflow'} ({record['workflow_id'] or '-'})",
        f"node: {record['node'] or '-'}",
        f"execution: {record['execution_id'] or '-'}",
        f"retry_of: {record['retry_of'] or '-'}",
        f"url: {record['execution_url'] or '-'}",
        "",
        record["message"],
    ]
    return "\n".join(lines)


def html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_html(record: dict[str, Any], stack: str) -> str:
    rows = [
        ("class", record["class"]),
        ("severity", record["severity"]),
        ("origin", record["origin"]),
        ("workflow", record["workflow_name"] or "unnamed workflow"),
        ("workflow_id", record["workflow_id"] or "-"),
        ("node", record["node"] or "-"),
        ("execution", record["execution_id"] or "-"),
        ("retry_of", record["retry_of"] or "-"),
        ("url", record["execution_url"] or "-"),
        ("error_name", record["error_name"] or "-"),
        ("classified_at", record["classified_at"]),
    ]
    body = "\n".join(
        f"<tr><th>{html_escape(key)}</th><td>{html_escape(value)}</td></tr>" for key, value in rows
    )
    stack_html = ""
    if stack:
        stack_html = f"<pre>{html_escape(stack)}</pre>\n"
    return (
        "<!DOCTYPE html>\n<html><body>\n"
        "<p><strong>n8n error / n8n 错误</strong></p>\n"
        "<table>\n"
        f"{body}\n"
        "</table>\n"
        f"<p>{html_escape(record['message'])}</p>\n"
        f"{stack_html}"
        "</body></html>\n"
    )


def format_text_view(result: dict[str, Any]) -> str:
    lines = [
        "n8n error classification",
        f"class: {result['class']}",
        f"severity: {result['severity']}",
        f"origin: {result['origin']}",
        f"workflow_name: {result['workflow_name']}",
        f"workflow_id: {result['workflow_id']}",
        f"execution_id: {result['execution_id']}",
        f"execution_url: {result['execution_url']}",
        f"node: {result['node']}",
        f"error_name: {result['error_name']}",
        f"is_retry: {'yes' if result['is_retry'] else 'no'}",
        f"retry_of: {result['retry_of']}",
        f"classified_at: {result['classified_at']}",
        f"subject: {result['subject']}",
        f"text_bytes: {result['text_bytes']}",
        f"html_bytes: {result['html_bytes']}",
        "--- telegram ---",
        result["telegram_text"],
        "",
    ]
    return "\n".join(lines)


def dump_json(result: dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def log_line(result_or_record: dict[str, Any]) -> str:
    if "log_record" in result_or_record and isinstance(result_or_record["log_record"], dict):
        record = result_or_record["log_record"]
    else:
        record = result_or_record
    required = ("class", "message", "classified_at")
    for key in required:
        if key not in record:
            raise ValueError(f"log record is missing {key}")
    kept = {
        "class": as_text(record.get("class"), 40),
        "classified_at": as_text(record.get("classified_at"), 40),
        "error_name": as_text(record.get("error_name"), 120),
        "execution_id": as_text(record.get("execution_id"), 200),
        "execution_url": as_text(record.get("execution_url"), 500),
        "is_retry": bool(record.get("is_retry")),
        "message": as_text(record.get("message"), MAX_MESSAGE),
        "node": as_text(record.get("node"), 200),
        "origin": as_text(record.get("origin"), 40),
        "retry_of": as_text(record.get("retry_of"), 200),
        "severity": as_text(record.get("severity"), 20),
        "workflow_id": as_text(record.get("workflow_id"), 200),
        "workflow_name": as_text(record.get("workflow_name"), MAX_NAME),
    }
    return json.dumps(kept, ensure_ascii=False, sort_keys=True)


def append_line(path: str, line: str) -> None:
    from pathlib import Path

    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def read_input(args: argparse.Namespace, field: str) -> str:
    fixture = getattr(args, "fixture", None)
    encoded = getattr(args, field, None)
    stdin = getattr(args, "input_stdin", False)
    if fixture:
        with open(fixture, encoding="utf-8") as handle:
            return handle.read()
    if encoded:
        try:
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        except Exception as exc:
            raise ValueError(f"{field} is not valid base64 utf-8: {exc}") from exc
    if stdin:
        return sys.stdin.read()
    raise ValueError("provide --fixture, --input-b64, or --input-stdin")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify an n8n Error Trigger payload.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    classify = sub.add_parser("classify", help="print the mapped notice as JSON or text")
    source = classify.add_mutually_exclusive_group(required=True)
    source.add_argument("--fixture")
    source.add_argument("--input-b64")
    source.add_argument("--input-stdin", action="store_true")
    classify.add_argument("--now", default="")
    classify.add_argument("--format", choices=("json", "text"), default="json")
    append = sub.add_parser("append", help="append one JSON log line")
    append.add_argument("--log", required=True)
    append_source = append.add_mutually_exclusive_group(required=True)
    append_source.add_argument("--fixture")
    append_source.add_argument("--input-b64")
    append_source.add_argument("--record-b64")
    append_source.add_argument("--input-stdin", action="store_true")
    append.add_argument("--now", default="")
    args = parser.parse_args(argv)
    try:
        stamp = now_stamp(args.now or None)
        if args.cmd == "classify":
            document = load_document(read_input(args, "input_b64"))
            result = classify_payload(document, stamp)
            if args.format == "text":
                sys.stdout.write(format_text_view(result))
            else:
                sys.stdout.write(dump_json(result))
            return 0
        if args.record_b64:
            document = load_document(read_input(args, "record_b64"))
            if "classified_at" not in document and "log_record" not in document:
                document = classify_payload(document, stamp)
            elif "log_record" not in document and "class" in document:
                document.setdefault("classified_at", stamp)
            line = log_line(document)
        else:
            document = load_document(read_input(args, "input_b64"))
            result = classify_payload(document, stamp)
            line = log_line(result)
        append_line(args.log, line)
        sys.stdout.write(line + "\n")
        return 0
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
