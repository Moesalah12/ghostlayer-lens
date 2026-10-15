"""Static inspection only. Never executes, extracts, or contacts embedded content."""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import io
from itertools import islice
import re
import stat
import struct
import time
import unicodedata
import zipfile
import zlib

from . import __version__


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 512 * 1024 * 1024
    member_bytes: int = 2 * 1024 * 1024
    expanded_bytes: int = 32 * 1024 * 1024
    entries: int = 500
    depth: int = 3
    ratio: int = 200
    seconds: int = 10
    findings: int = 1000


EXECUTABLES = {".exe", ".dll", ".scr", ".com", ".msi", ".cpl", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".lnk"}
DOCUMENTS = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".doc", ".docx", ".xlsx", ".mp3", ".mp4"}
TEXT = {".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".xml", ".html", ".css", ".csv", ".log", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".py", ".url"}
SCRIPT = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".py", ".hta", ".wsf"}
UNSUPPORTED = {".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".pdf", ".doc", ".docx", ".xlsx", ".pptx", ".jar", ".apk"}
URL = re.compile(r"https?://[^\s<>\"'`\)\]]{1,500}", re.I)

# Deliberately small, explainable lexical rules. Matches can include comments and
# benign administration; these are review signals, not execution predictions.
RULES = [
    ("remote_retrieval", "medium", "Remote retrieval instruction", r"\b(?:Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|DownloadString|DownloadFile)\b|\b(?:curl|wget)(?:\.exe)?\s", "The text contains a download-related command. Inspect its source and destination before use."),
    ("dynamic_execution", "medium", "Dynamic execution instruction", r"\b(?:Invoke-Expression|IEX)\b|\beval\s*\(|\bexec\s*\(", "The text contains a dynamic execution keyword. A lexical match does not prove it runs."),
    ("startup_reference", "medium", "Startup or scheduled-task reference", r"CurrentVersion[\\/]+Run(?:Once)?\b|\bschtasks(?:\.exe)?\s|[\\/]Start Menu[\\/]Programs[\\/]Startup\b|\bNew-ScheduledTask\b", "The text references a common persistence mechanism; legitimate installers may do this too."),
    ("security_setting", "high", "Security-setting modification instruction", r"\bSet-MpPreference\b[^\r\n]{0,200}(?:DisableRealtimeMonitoring|ExclusionPath)|\bnetsh\b[^\r\n]{0,100}\b(?:firewall|advfirewall)\b[^\r\n]{0,100}\boff\b", "The text includes instructions associated with changing security protections. Verify context and necessity."),
    ("elevation_request", "medium", "Administrator elevation request", r"\b(?:Start-Process)\b[^\r\n]{0,200}-Verb\s+RunAs\b|\brequireAdministrator\b", "The text requests or declares administrator execution. This is not inherently malicious."),
    ("encoded_powershell", "medium", "Encoded PowerShell argument", r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,200}\s-(?:EncodedCommand|enc|ec)\s+([A-Za-z0-9+/=]{4,12000})", "A PowerShell command contains Base64-encoded text; Lens attempts a bounded decode without running it."),
]


def suffix(name):
    tail = name.replace("\\", "/").rsplit("/", 1)[-1].rstrip(" .")
    return "." + tail.rsplit(".", 1)[-1].lower() if "." in tail else ""


def visible(value, limit=1000):
    """Make bidirectional/control characters explicit in every report label."""
    return "".join(f"\\u{ord(ch):04x}" if unicodedata.category(ch).startswith("C") else ch for ch in value[:limit])


def text_decode(data):
    try:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16")
        if b"\x00" in data:
            return None
        value = data.decode("utf-8-sig")
        if value and sum(ord(ch) < 32 and ch not in "\t\r\n" for ch in value) / len(value) > .02:
            return None
        return value
    except UnicodeError:
        return None


class Inspector:
    def __init__(self, limits=None):
        self.limits = limits or Limits()
        self.start = time.monotonic()
        self.nodes = []
        self.findings = []
        self.expanded = 0
        self.incomplete = False
        self.limits_hit = set()

    def expired(self):
        return time.monotonic() - self.start > self.limits.seconds

    def add(self, node, rule, severity, title, detail, evidence=None, line=None):
        if len(self.findings) >= self.limits.findings:
            self.incomplete = True
            self.limits_hit.add("findings")
            return
        item = {"id": f"F{len(self.findings)+1:04}", "node_id": node["id"],
                "rule": rule, "severity": severity, "title": title, "detail": detail}
        if evidence is not None:
            item["evidence"] = visible(evidence, 300)
        if line is not None:
            item["line"] = line
        self.findings.append(item)

    def gap(self, node, reason, detail):
        node["status"] = "not_inspected"
        node["reason"] = reason
        self.incomplete = True
        self.add(node, reason, "info", "Inspection coverage gap", detail)

    def names(self, node, raw):
        normalized = raw.replace("\\", "/")
        base = normalized.rsplit("/", 1)[-1].rstrip(" .")
        parts = base.lower().split(".")
        if len(parts) >= 3 and "." + parts[-1] in EXECUTABLES and any("." + part in DOCUMENTS for part in parts[1:-1]):
            self.add(node, "disguised_extension", "high", "Document-like name ends in an executable extension", "Windows may hide the final extension. This name deserves review; it does not establish maliciousness.", base)
        if any(unicodedata.bidirectional(ch) in {"RLO", "LRO", "RLE", "LRE", "PDF", "RLI", "LRI", "FSI", "PDI"} for ch in raw):
            self.add(node, "bidi_filename", "high", "Bidirectional filename controls", "Unicode direction controls can change how a filename appears. The report escapes them explicitly.", raw)
        if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized) or ".." in normalized.split("/"):
            self.add(node, "unsafe_archive_path", "high", "Path points outside a normal archive directory", "An extractor that mishandles this path could write outside its destination. Lens does not extract entries.", raw)

    def inspect_text(self, node, text, decoded=False):
        lines = text.splitlines()
        for rule, severity, title, pattern, detail in RULES:
            expression = re.compile(pattern, re.I)
            for match in islice(expression.finditer(text), 3):
                line = text.count("\n", 0, match.start()) + 1
                evidence = lines[line-1] if line <= len(lines) else match.group(0)
                self.add(node, rule + ("_decoded" if decoded else ""), severity, title,
                         detail + (" Matched inside decoded text." if decoded else ""), evidence, line)
                if rule == "encoded_powershell" and not decoded:
                    try:
                        raw = base64.b64decode(match.group(1), validate=True)
                        value = raw.decode("utf-16-le")
                        if len(value) <= 6000:
                            self.add(node, "decoded_text", "info", "Decoded command text", "Decoded as UTF-16LE for review only; nothing was executed.", value)
                            self.inspect_text(node, value, decoded=True)
                    except (ValueError, UnicodeError):
                        self.add(node, "decode_failed", "info", "Encoded argument could not be decoded", "The Base64 argument was not valid UTF-16LE text under the decoder's constraints.")
        # Bound extraction work as well as the final report size.
        urls = sorted({match.group(0) for match in islice(URL.finditer(text), 100)})[:30]
        node.setdefault("references", []).extend({"kind": "url", "value": visible(url, 500), "source": "decoded_text" if decoded else "text"} for url in urls)

    def node(self, name, size, parent=None):
        node = {"id": f"N{len(self.nodes)+1:04}", "name": visible(name), "parent_id": parent,
                "size_bytes": size, "status": "pending", "kind": "unknown", "references": []}
        self.nodes.append(node)
        self.names(node, name)
        return node

    def inspect(self, node, data, name, depth=0):
        node["sha256"] = hashlib.sha256(data).hexdigest()
        ext = suffix(name)
        if self.expired():
            self.limits_hit.add("time")
            self.gap(node, "time_limit", "The cooperative time budget expired. Remaining content was not inspected.")
            return
        if ext == ".zip" or data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            node["kind"] = "zip"
            if depth >= self.limits.depth:
                self.limits_hit.add("depth")
                self.gap(node, "depth_limit", "Nested archive depth limit reached.")
                return
            self.archive(node, data, depth)
            return
        if data.startswith(b"MZ"):
            node["kind"] = "windows_binary"
            self.gap(node, "binary_not_analyzed", "Windows binary detected. This release does not perform full executable analysis or verify signatures.")
            if ext not in {".exe", ".dll", ".scr", ".com", ".cpl"}:
                self.add(node, "binary_extension_mismatch", "high", "Executable marker conflicts with filename", "Bytes begin with the DOS MZ marker commonly used by Windows binaries. This marker alone does not establish a valid PE executable.", "MZ")
            if len(data) >= 64:
                offset = struct.unpack_from("<I", data, 60)[0]
                node["pe_signature_present"] = offset <= len(data)-4 and data[offset:offset+4] == b"PE\x00\x00"
            return
        if ext in UNSUPPORTED or ext in EXECUTABLES - SCRIPT:
            node["kind"] = "unsupported"
            self.gap(node, "unsupported_format", "No format-specific content analyzer is available for this file type.")
            return
        text = text_decode(data)
        if text is None:
            node["kind"] = "binary"
            self.gap(node, "unsupported_encoding", "Content is binary or not recognized as UTF-8/UTF-16 text.")
            return
        node["kind"] = "script" if ext in SCRIPT else "text"
        self.inspect_text(node, text)
        node["status"] = "inspected"
        node["coverage"] = "Lexical text rules only; code was not executed or fully parsed."

    def archive(self, node, data, depth):
        local_gaps = False
        try:
            with zipfile.ZipFile(io.BytesIO(data) if isinstance(data, bytes) else data) as archive:
                members = archive.infolist()
                node["declared_entry_count"] = len(members)
                names = set()
                for member in members:
                    if self.expired() or len(self.nodes) >= self.limits.entries:
                        self.limits_hit.add("time" if self.expired() else "entries")
                        self.add(node, "archive_truncated", "info", "Archive inventory truncated", "Entry or time budget reached; additional entries were not inventoried.")
                        local_gaps = self.incomplete = True
                        break
                    child = self.node(member.filename, member.file_size, node["id"])
                    if member.filename in names:
                        self.add(child, "duplicate_entry", "medium", "Duplicate archive filename", "Different extractors may choose different content for a repeated name.", member.filename)
                    names.add(member.filename)
                    if stat.S_ISLNK(member.external_attr >> 16):
                        child["kind"] = "symlink"
                        self.gap(child, "symlink_not_followed", "Symbolic links are not followed.")
                    elif member.is_dir():
                        child.update(kind="directory", status="metadata_only")
                        continue
                    elif member.flag_bits & 1:
                        self.gap(child, "encrypted_entry", "Encrypted entry: content remains uninspected. Passwords are not accepted in this release.")
                    elif member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                        self.gap(child, "unsupported_compression", "Only stored and DEFLATE ZIP entries are supported.")
                    elif member.file_size > self.limits.member_bytes:
                        self.limits_hit.add("member_bytes")
                        self.gap(child, "member_size_limit", "Entry exceeds the per-file inspection limit.")
                    elif member.file_size > max(member.compress_size, 1) * self.limits.ratio:
                        self.limits_hit.add("ratio")
                        self.gap(child, "compression_ratio_limit", "Unusually high declared compression ratio; entry was not decompressed.")
                    elif self.expanded + member.file_size > self.limits.expanded_bytes:
                        self.limits_hit.add("expanded_bytes")
                        self.gap(child, "expanded_size_limit", "Total decompressed-byte budget reached.")
                    else:
                        try:
                            with archive.open(member) as stream:
                                chunk = stream.read(min(self.limits.member_bytes, self.limits.expanded_bytes-self.expanded)+1)
                            self.expanded += len(chunk)
                            if len(chunk) > self.limits.member_bytes or self.expanded > self.limits.expanded_bytes:
                                self.limits_hit.add("expanded_bytes")
                                self.gap(child, "actual_size_limit", "Actual decompressed bytes exceeded a configured limit.")
                            else:
                                self.inspect(child, chunk, member.filename, depth+1)
                        except (OSError, RuntimeError, ValueError, EOFError, NotImplementedError, zipfile.BadZipFile, zlib.error) as exc:
                            self.gap(child, "unreadable_entry", f"ZIP entry could not be read ({type(exc).__name__}).")
                    if child["status"] in {"not_inspected", "partial"}:
                        local_gaps = True
                node["status"] = "partial" if local_gaps else "inspected"
                node["coverage"] = "ZIP metadata and bounded entry inspection. No extraction to disk."
        except (OSError, ValueError, EOFError, zipfile.BadZipFile) as exc:
            self.gap(node, "invalid_archive", f"ZIP structure could not be read ({type(exc).__name__}).")


def scan_bytes(data, name="input", limits=None):
    limits = limits or Limits()
    if len(data) > limits.input_bytes:
        raise ValueError("Input exceeds the configured limit.")
    if not isinstance(name, str) or not name or len(name) > 1000:
        raise ValueError("Filename must contain 1–1000 characters.")
    inspector = Inspector(limits)
    root = inspector.node(name, len(data))
    inspector.inspect(root, data, name)
    return make_report(inspector, limits)


def make_report(inspector, limits):
    attention = any(item["severity"] in {"high", "medium"} for item in inspector.findings)
    return {"schema_version": 1, "engine_version": __version__,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "assessment": "review_recommended" if attention else "no_rule_matches",
            "coverage": "incomplete" if inspector.incomplete else "within_supported_scope",
            "notice": "Static indicators only. No result certifies safety or proves maliciousness. Nothing was executed or contacted.",
            "limits": asdict(limits), "limits_hit": sorted(inspector.limits_hit),
            "stats": {"nodes": len(inspector.nodes), "findings": len(inspector.findings),
                      "decompressed_bytes": inspector.expanded},
            "nodes": inspector.nodes, "findings": inspector.findings}


def scan_file(path, name="input", limits=None):
    """Hash in chunks; inspect ZIPs on disk and bound other content reads."""
    limits = limits or Limits()
    if not isinstance(name, str) or not name or len(name) > 1000:
        raise ValueError("Filename must contain 1–1000 characters.")
    inspector = Inspector(limits)
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > limits.input_bytes:
                raise ValueError("Input exceeds the configured limit.")
            digest.update(chunk)
            if inspector.expired():
                raise ValueError("File reading exceeded the inspection time budget.")
        root = inspector.node(name, size)
        root["sha256"] = digest.hexdigest()
        stream.seek(0)
        prefix = stream.read(64)
        stream.seek(0)
        if suffix(name) == ".zip" or prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            root["kind"] = "zip"
            inspector.archive(root, stream, 0)
        elif size > limits.member_bytes:
            root["kind"] = "windows_binary" if prefix.startswith(b"MZ") else "unsupported"
            inspector.limits_hit.add("member_bytes")
            inspector.gap(root, "content_size_limit", "File was hashed, but content exceeds the 2 MiB text inspection limit. Full content was not analyzed.")
        else:
            inspector.inspect(root, stream.read(limits.member_bytes + 1), name)
    return make_report(inspector, limits)
