from __future__ import annotations

import json
import mimetypes
import os
import re
import shutil
import threading
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import bleach
import markdown
from flask import Flask, Response, jsonify, render_template, request, send_file
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, generate_latest
from werkzeug.exceptions import BadRequest, HTTPException, RequestEntityTooLarge
from werkzeug.utils import secure_filename

STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "./storage")).resolve()
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "256"))
TEXT_LIMIT = int(os.getenv("TEXT_PREVIEW_LIMIT", str(2 * 1024 * 1024)))
METRIC_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
(STORAGE_DIR / "gdcheerioscom" / "pfps").mkdir(parents=True, exist_ok=True)
CHANGELOG_ROOT = (STORAGE_DIR / os.getenv("CHANGELOG_DIR", "changelogs")).resolve()
CHANGELOG_ROOT.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024, SECRET_KEY=os.getenv("SECRET_KEY", "development-only"))

registry = CollectorRegistry()
http_requests = Counter("storage_http_requests_total", "HTTP requests handled", ["method", "status"], registry=registry)
uploaded_bytes = Counter("storage_uploaded_bytes_total", "Bytes uploaded", registry=registry)
downloads = Counter("storage_downloads_total", "Files downloaded", registry=registry)
custom_metrics: dict[str, tuple[str, object, tuple[str, ...]]] = {}
custom_metrics_lock = threading.Lock()


def safe_path(raw_path: str | None = "") -> Path:
    raw_path = (raw_path or "").replace("\\", "/").lstrip("/")
    candidate = (STORAGE_DIR / raw_path).resolve()
    if candidate != STORAGE_DIR and STORAGE_DIR not in candidate.parents:
        raise BadRequest("Invalid path")
    return candidate


def relative(path: Path) -> str:
    value = path.relative_to(STORAGE_DIR).as_posix()
    return "" if value == "." else value


def file_info(path: Path) -> dict:
    stat = path.stat()
    is_dir = path.is_dir()
    return {
        "name": path.name, "path": relative(path), "is_dir": is_dir,
        "size": 0 if is_dir else stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "mime": "inode/directory" if is_dir else (mimetypes.guess_type(path.name)[0] or "application/octet-stream"),
    }


def storage_totals() -> tuple[int, int, int]:
    files = directories = size = 0
    for root, dir_names, file_names in os.walk(STORAGE_DIR):
        directories += len(dir_names)
        files += len(file_names)
        for filename in file_names:
            try:
                size += (Path(root) / filename).stat().st_size
            except OSError:
                pass
    return files, directories, size


def changelog_slug(value: str) -> str:
    slug = secure_filename(value).replace("_", "-").lower()
    if not slug:
        raise BadRequest("A valid project name is required")
    return slug


def changelog_version(value: str) -> str:
    version = value.strip()
    if version.lower().startswith("v"):
        version = version[1:]
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", version):
        raise BadRequest("Version may only contain letters, numbers, dots, dashes, and underscores")
    return version


def bullet_lines(values, placeholder: str) -> list[str]:
    if isinstance(values, str):
        values = [values]
    values = [str(value).strip() for value in (values or []) if str(value).strip()]
    return [f"* {value}" for value in values] or [f"* {placeholder}"]


def github_references(data: dict) -> list[dict]:
    repository = str(data.get("github_repository", "")).strip().strip("/")
    if repository and not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise BadRequest("github_repository must use owner/repository format")
    references = data.get("references") or []
    if not isinstance(references, list):
        raise BadRequest("References must be an array")
    normalized = []
    for reference in references:
        if not isinstance(reference, dict):
            raise BadRequest("Each reference must be an object")
        reference_type = str(reference.get("type", "pull_request")).lower().replace("-", "_")
        if reference_type in {"pr", "pull", "pullrequest"}:
            reference_type = "pull_request"
        if reference_type not in {"pull_request", "issue"}:
            raise BadRequest("Reference type must be pull_request, pr, or issue")
        number = reference.get("number")
        try:
            number = int(number)
        except (TypeError, ValueError) as error:
            raise BadRequest("Each GitHub reference requires a numeric number") from error
        if number < 1:
            raise BadRequest("GitHub reference numbers must be positive")
        url = str(reference.get("url", "")).strip()
        if not url:
            if not repository:
                raise BadRequest("Provide github_repository or an explicit GitHub URL")
            resource = "pull" if reference_type == "pull_request" else "issues"
            url = f"https://github.com/{repository}/{resource}/{number}"
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc.lower() not in {"github.com", "www.github.com"}:
            raise BadRequest("Reference URLs must be HTTPS github.com links")
        normalized.append({
            "type": reference_type,
            "number": number,
            "title": str(reference.get("title", "")).strip(),
            "url": url,
        })
    return normalized


def build_changelog(data: dict, template: bool = False) -> tuple[str, dict]:
    project_name = str(data.get("project", "")).strip()
    version = changelog_version(str(data.get("version", "")).strip())
    release_date = str(data.get("date") or date.today().isoformat())
    try:
        date.fromisoformat(release_date)
    except ValueError as error:
        raise BadRequest("Date must use YYYY-MM-DD format") from error
    references = github_references(data)
    repository = str(data.get("github_repository", "")).strip().strip("/")

    default_sections = ["Added", "Fixed", "Infrastructure"]
    sections = data.get("sections") or {}
    if not isinstance(sections, dict):
        raise BadRequest("Sections must be an object containing arrays of entries")
    categories = data.get("categories") or list(sections) or default_sections
    if not isinstance(categories, list):
        raise BadRequest("Categories must be an array")
    categories = [str(category).strip() for category in categories if str(category).strip()]
    metadata = {
        "version": version,
        "date": release_date,
        "project": project_name,
        "categories": categories,
        "github_repository": repository,
        "references": references,
    }
    category_lines = "\n".join(f"  - {json.dumps(category, ensure_ascii=False)}" for category in categories)
    frontmatter = (
        "---\n"
        f"version: {json.dumps(version)}\n"
        f"date: {json.dumps(release_date)}\n"
        f"project: {json.dumps(project_name, ensure_ascii=False)}\n"
        f"categories:\n{category_lines}\n"
        f"github_repository: {json.dumps(repository)}\n"
        f"references: {json.dumps(references, ensure_ascii=False)}\n"
        "---\n\n"
    )

    body = []
    for category in categories:
        body.extend([f"## {category}", *bullet_lines(sections.get(category), "Describe the change."), ""])
    if references:
        body.extend(["## Related changes"])
        for reference in references:
            label = "PR" if reference["type"] == "pull_request" else "Issue"
            title = f" — {reference['title']}" if reference["title"] else ""
            body.append(f"* [{label} #{reference['number']}]({reference['url']}){title}")
        body.append("")
    return frontmatter + "\n".join(body).rstrip() + "\n", metadata


def parse_changelog(content: str) -> tuple[dict, str]:
    if not content.startswith("---\n"):
        return {}, content
    try:
        header, body = content[4:].split("\n---\n", 1)
        metadata: dict = {}
        active_list = None
        for line in header.splitlines():
            if line.startswith("  - ") and active_list:
                raw_value = line[4:].strip()
                try:
                    value = json.loads(raw_value)
                except json.JSONDecodeError:
                    value = raw_value
                metadata[active_list].append(value)
                continue
            if ":" not in line:
                continue
            key, raw_value = line.split(":", 1)
            key, raw_value = key.strip(), raw_value.strip()
            if not raw_value:
                metadata[key] = []
                active_list = key
            else:
                try:
                    metadata[key] = json.loads(raw_value)
                except json.JSONDecodeError:
                    metadata[key] = raw_value.strip('"')
                active_list = None
        return metadata, body.lstrip()
    except ValueError:
        return {}, content


def changelog_file(project: str, version: str) -> Path:
    project_dir = CHANGELOG_ROOT / changelog_slug(project)
    candidate = (project_dir / f"v{changelog_version(version)}.md").resolve()
    if CHANGELOG_ROOT not in candidate.parents:
        raise BadRequest("Invalid changelog path")
    return candidate


def changelog_payload(path: Path) -> dict:
    content = path.read_text(encoding="utf-8")
    metadata, body = parse_changelog(content)
    return {
        **metadata,
        "project_slug": path.parent.name,
        "filename": path.name,
        "markdown": content,
        "body": body,
        "modified": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
    }


@app.after_request
def observe_request(response: Response) -> Response:
    if request.path != "/metrics":
        http_requests.labels(request.method, str(response.status_code)).inc()
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.errorhandler(HTTPException)
def handle_http_error(error: HTTPException):
    if request.path.startswith("/api/"):
        return jsonify(error=error.description), error.code
    return error


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    return jsonify(error=f"Upload exceeds the {MAX_UPLOAD_MB} MB limit"), 413


@app.get("/")
def index():
    return render_template("index.html", max_upload_mb=MAX_UPLOAD_MB)


@app.get("/health")
def health():
    return jsonify(status="ok", storage=str(STORAGE_DIR))


@app.get("/api/changelogs")
def list_changelogs():
    projects = []
    for project_dir in sorted((path for path in CHANGELOG_ROOT.iterdir() if path.is_dir()), key=lambda path: path.name):
        entries = []
        for path in sorted(project_dir.glob("v*.md"), key=lambda item: item.stat().st_mtime, reverse=True):
            try:
                payload = changelog_payload(path)
                entries.append({key: payload.get(key) for key in ("version", "date", "project", "categories", "github_repository", "references", "filename", "modified")})
            except (OSError, UnicodeDecodeError):
                continue
        projects.append({"slug": project_dir.name, "entries": entries})
    return jsonify(projects=projects)


@app.get("/api/changelogs/template")
def changelog_template():
    data = {
        "project": request.args.get("project", "Project name"),
        "version": request.args.get("version", "0.1.0"),
        "date": request.args.get("date", date.today().isoformat()),
        "github_repository": request.args.get("github_repository", ""),
    }
    content, metadata = build_changelog(data, template=True)
    if request.args.get("format") == "json":
        return jsonify(metadata=metadata, markdown=content)
    return Response(content, content_type="text/markdown; charset=utf-8")


@app.post("/api/changelogs")
def create_changelog():
    data = request.get_json(silent=True) or {}
    content, metadata = build_changelog(data)
    path = changelog_file(str(data.get("project", "")), str(data.get("version", "")))
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not data.get("overwrite", False):
        return jsonify(error="That project version already exists"), 409
    path.write_text(content, encoding="utf-8")
    return jsonify(entry={**metadata, "project_slug": path.parent.name, "filename": path.name, "path": relative(path), "markdown": content}), 201


@app.get("/api/changelogs/<project>/<version>")
def get_changelog(project: str, version: str):
    path = changelog_file(project, version)
    if not path.is_file():
        return jsonify(error="Changelog not found"), 404
    payload = changelog_payload(path)
    output_format = request.args.get("format", "json").lower()
    if output_format == "markdown":
        return Response(payload["markdown"], content_type="text/markdown; charset=utf-8")
    if output_format == "html":
        rendered = markdown.markdown(payload["body"], extensions=["fenced_code", "tables"])
        allowed_tags = set(bleach.sanitizer.ALLOWED_TAGS) | {
            "h1", "h2", "h3", "h4", "p", "pre", "code", "hr", "table", "thead", "tbody", "tr", "th", "td",
        }
        clean_html = bleach.clean(rendered, tags=allowed_tags, attributes={"a": ["href", "title"]})
        return Response(clean_html, content_type="text/html; charset=utf-8")
    if output_format != "json":
        return jsonify(error="Format must be json, markdown, or html"), 400
    return jsonify(payload)


@app.get("/api/files")
def list_files():
    directory = safe_path(request.args.get("path"))
    if not directory.exists():
        return jsonify(error="Folder not found"), 404
    if not directory.is_dir():
        return jsonify(error="Path is not a folder"), 400
    entries = sorted((file_info(item) for item in directory.iterdir()), key=lambda item: (not item["is_dir"], item["name"].lower()))
    files, directories, size = storage_totals()
    return jsonify(path=relative(directory), entries=entries, totals={"files": files, "directories": directories, "bytes": size})


@app.post("/api/upload")
def upload():
    destination = safe_path(request.form.get("path"))
    if not destination.is_dir():
        return jsonify(error="Destination folder not found"), 404
    incoming = request.files.getlist("files")
    if not incoming:
        return jsonify(error="No files supplied"), 400
    saved = []
    for item in incoming:
        filename = secure_filename(Path(item.filename or "").name)
        if not filename:
            continue
        target = destination / filename
        if target.exists() and target.is_dir():
            return jsonify(error=f"A folder named {filename} already exists"), 409
        item.save(target)
        uploaded_bytes.inc(target.stat().st_size)
        saved.append(file_info(target))
    if not saved:
        return jsonify(error="No valid filenames supplied"), 400
    return jsonify(saved=saved), 201


@app.post("/api/folders")
def create_folder():
    data = request.get_json(silent=True) or {}
    parent = safe_path(data.get("path"))
    name = secure_filename(str(data.get("name", "")).strip())
    if not name:
        return jsonify(error="A valid folder name is required"), 400
    target = parent / name
    try:
        target.mkdir()
    except FileExistsError:
        return jsonify(error="That name already exists"), 409
    return jsonify(entry=file_info(target)), 201


@app.post("/api/files")
def create_file():
    data = request.get_json(silent=True) or {}
    parent = safe_path(data.get("path"))
    name = secure_filename(str(data.get("name", "")).strip())
    if not name:
        return jsonify(error="A valid file name is required"), 400
    target = parent / name
    try:
        target.touch(exist_ok=False)
    except FileExistsError:
        return jsonify(error="That name already exists"), 409
    return jsonify(entry=file_info(target)), 201


@app.get("/api/file")
def get_file():
    path = safe_path(request.args.get("path"))
    if not path.is_file():
        return jsonify(error="File not found"), 404
    if path.stat().st_size > TEXT_LIMIT:
        return jsonify(error=f"File is too large to edit (limit: {TEXT_LIMIT} bytes)"), 413
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return jsonify(error="This is not a UTF-8 text file"), 415
    return jsonify(path=relative(path), content=content, modified=file_info(path)["modified"])


@app.put("/api/file")
def update_file():
    data = request.get_json(silent=True) or {}
    path = safe_path(data.get("path"))
    if not path.is_file():
        return jsonify(error="File not found"), 404
    content = data.get("content")
    if not isinstance(content, str):
        return jsonify(error="Content must be text"), 400
    encoded = content.encode("utf-8")
    if len(encoded) > TEXT_LIMIT:
        return jsonify(error=f"Content exceeds the {TEXT_LIMIT}-byte editor limit"), 413
    path.write_bytes(encoded)
    return jsonify(entry=file_info(path))


@app.get("/api/raw")
def raw_file():
    path = safe_path(request.args.get("path"))
    if not path.is_file():
        return jsonify(error="File not found"), 404
    return send_file(path, conditional=True)


@app.get("/api/download")
def download_file():
    path = safe_path(request.args.get("path"))
    if not path.is_file():
        return jsonify(error="File not found"), 404
    downloads.inc()
    return send_file(path, as_attachment=True, download_name=path.name, conditional=True)


@app.patch("/api/entry")
def rename_entry():
    data = request.get_json(silent=True) or {}
    source = safe_path(data.get("path"))
    name = secure_filename(str(data.get("name", "")).strip())
    if source == STORAGE_DIR or not source.exists() or not name:
        return jsonify(error="Invalid entry or name"), 400
    target = source.parent / name
    if target.exists():
        return jsonify(error="That name already exists"), 409
    source.rename(target)
    return jsonify(entry=file_info(target))


@app.delete("/api/entry")
def delete_entry():
    path = safe_path(request.args.get("path"))
    if path == STORAGE_DIR:
        return jsonify(error="The storage root cannot be deleted"), 400
    if not path.exists():
        return jsonify(error="Entry not found"), 404
    shutil.rmtree(path) if path.is_dir() else path.unlink()
    return Response(status=204)


@app.post("/api/metrics")
def record_metric():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", ""))
    metric_type = str(data.get("type", "gauge")).lower()
    labels = data.get("labels", {})
    try:
        value = float(data.get("value", 1))
    except (TypeError, ValueError):
        return jsonify(error="Metric value must be a number"), 400
    if not METRIC_NAME.fullmatch(name) or name.startswith("storage_"):
        return jsonify(error="Use a valid metric name that does not start with storage_"), 400
    if metric_type not in {"counter", "gauge"} or not isinstance(labels, dict):
        return jsonify(error="Type must be counter or gauge, and labels must be an object"), 400
    label_names = tuple(sorted(str(key) for key in labels))
    if any(not METRIC_NAME.fullmatch(key) for key in label_names):
        return jsonify(error="Invalid label name"), 400
    label_values = {key: str(labels[key]) for key in label_names}
    with custom_metrics_lock:
        existing = custom_metrics.get(name)
        if existing and (existing[0] != metric_type or existing[2] != label_names):
            return jsonify(error="Metric already exists with a different type or label set"), 409
        if not existing:
            metric_class = Counter if metric_type == "counter" else Gauge
            try:
                metric = metric_class(name, str(data.get("help") or f"Custom {name} metric"), label_names, registry=registry)
            except ValueError as error:
                return jsonify(error=str(error)), 409
            custom_metrics[name] = (metric_type, metric, label_names)
        else:
            metric = existing[1]
        child = metric.labels(**label_values) if label_names else metric
        child.inc(value) if metric_type == "counter" else child.set(value)
    return jsonify(name=name, type=metric_type, value=value, labels=label_values), 202


@app.get("/metrics")
def metrics():
    files, directories, size = storage_totals()
    snapshot = CollectorRegistry()
    Gauge("storage_files", "Current number of stored files", registry=snapshot).set(files)
    Gauge("storage_directories", "Current number of stored directories", registry=snapshot).set(directories)
    Gauge("storage_bytes", "Current stored bytes", registry=snapshot).set(size)
    return Response(generate_latest(registry) + generate_latest(snapshot), content_type=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=os.getenv("FLASK_DEBUG") == "1")
