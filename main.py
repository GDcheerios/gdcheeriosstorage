from __future__ import annotations

import json
import hmac
import mimetypes
import os
import re
import shutil
import threading
from datetime import date, datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

import bleach
import markdown
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, render_template, request, send_file
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, generate_latest
from werkzeug.exceptions import BadRequest, HTTPException, RequestEntityTooLarge
from werkzeug.utils import secure_filename

load_dotenv()

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


def load_users() -> dict[str, dict]:
    """Load HTTP Basic users from STORAGE_USERS.

    Example: {"alice":{"password":"secret","permissions":["view"]},
              "bob":{"password":"secret","permissions":["view","write"]}}
    """
    raw_users = os.getenv("STORAGE_USERS", "")
    if not raw_users:
        print("STORAGE_USERS not found")
        return {}
    try:
        users = json.loads(raw_users)
    except json.JSONDecodeError as error:
        raise RuntimeError("STORAGE_USERS must be valid JSON") from error
    if not isinstance(users, dict):
        raise RuntimeError("STORAGE_USERS must be a JSON object keyed by username")
    normalized = {}
    for username, details in users.items():
        if not isinstance(username, str) or not username or not isinstance(details, dict):
            raise RuntimeError("Each STORAGE_USERS entry must have a username and settings object")
        password = details.get("password")
        permissions = details.get("permissions", [])
        if not isinstance(password, str) or not password or not isinstance(permissions, list):
            raise RuntimeError(f"STORAGE_USERS user {username!r} needs a password and permissions array")
        permission_set = {str(permission).lower() for permission in permissions}
        if not permission_set <= {"view", "write"}:
            raise RuntimeError(f"STORAGE_USERS user {username!r} has an unknown permission")
        if "write" in permission_set:
            permission_set.add("view")
        normalized[username] = {"password": password, "permissions": permission_set}
    return normalized


STORAGE_USERS = load_users()


def permission_required(permission: str):
    """Require a configured HTTP Basic user with the requested permission."""
    def decorate(view):
        @wraps(view)
        def protected(*args, **kwargs):
            credentials = request.authorization
            user = STORAGE_USERS.get(credentials.username) if credentials and credentials.username else None
            password_matches = bool(
                user and credentials.password is not None
                and hmac.compare_digest(user["password"], credentials.password)
            )
            if not password_matches:
                response = jsonify(error="Authentication required")
                response.status_code = 401
                response.headers["WWW-Authenticate"] = 'Basic realm="Storage", charset="UTF-8"'
                return response
            if permission not in user["permissions"]:
                return jsonify(error=f"The {permission} permission is required"), 403
            return view(*args, **kwargs)
        return protected
    return decorate

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
        category = str(reference.get("category", "")).strip()
        subcategory = str(reference.get("subcategory", "")).strip()
        change = str(reference.get("change", "")).strip()
        if bool(category) != bool(change):
            raise BadRequest("A reference must provide both category and change")
        normalized.append({
            "type": reference_type,
            "number": number,
            "title": str(reference.get("title", "")).strip(),
            "url": url,
            "category": category,
            "subcategory": subcategory,
            "change": change,
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
    live = data.get("live", False)
    if not isinstance(live, bool):
        raise BadRequest("Live must be a boolean")

    default_sections = ["Added", "Fixed", "Infrastructure"]
    sections = data.get("sections") or {}
    if not isinstance(sections, dict):
        raise BadRequest("Sections must be an object containing arrays of entries")
    categories = data.get("categories") or list(sections) or default_sections
    if not isinstance(categories, list):
        raise BadRequest("Categories must be an array")
    categories = [str(category).strip() for category in categories if str(category).strip()]
    normalized_sections = {}
    for category in categories:
        category_sections = sections.get(category) or []
        if isinstance(category_sections, dict):
            normalized_sections[category] = {}
            for subcategory, values in category_sections.items():
                subcategory = str(subcategory).strip()
                if isinstance(values, str):
                    values = [values]
                if not isinstance(values, list):
                    raise BadRequest("Each category and subcategory must contain an array of changes")
                normalized_sections[category][subcategory] = [str(value).strip() for value in values if str(value).strip()]
        else:
            values = [category_sections] if isinstance(category_sections, str) else category_sections
            if not isinstance(values, list):
                raise BadRequest("Each category must contain an array or subcategory object")
            normalized_sections[category] = {"": [str(value).strip() for value in values if str(value).strip()]}
    for reference in references:
        if not reference["change"]:
            continue
        if reference["category"] not in categories:
            raise BadRequest(f"Unknown reference category: {reference['category']}")
        if reference["subcategory"] not in normalized_sections[reference["category"]]:
            raise BadRequest(f"Unknown reference subcategory: {reference['subcategory']}")
        if reference["change"] not in normalized_sections[reference["category"]][reference["subcategory"]]:
            raise BadRequest(f"Referenced change was not found: {reference['change']}")
    metadata = {
        "version": version,
        "date": release_date,
        "project": project_name,
        "live": live,
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
        f"live: {json.dumps(live)}\n"
        f"categories:\n{category_lines}\n"
        f"github_repository: {json.dumps(repository)}\n"
        f"references: {json.dumps(references, ensure_ascii=False)}\n"
        "---\n\n"
    )

    body = []
    for category in categories:
        body.append(f"## {category}")
        category_sections = normalized_sections[category]
        if not any(category_sections.values()):
            category_sections = {"": ["Describe the change."]}
        for subcategory, entries in category_sections.items():
            if subcategory:
                body.append(f"### {subcategory}")
            for entry in entries:
                line = f"* {entry}"
                entry_references = [
                    reference for reference in references
                    if reference["category"] == category
                    and reference["subcategory"] == subcategory
                    and reference["change"] == entry
                ]
                if entry_references:
                    links = []
                    for reference in entry_references:
                        label = "PR" if reference["type"] == "pull_request" else "Issue"
                        links.append(f"[{label} #{reference['number']}]({reference['url']})")
                    line += f" — {', '.join(links)}"
                body.append(line)
            if entries:
                body.append("")
    unlinked_references = [reference for reference in references if not reference["change"]]
    if unlinked_references:
        body.extend(["## Related changes"])
        for reference in unlinked_references:
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


def next_changelog_version(project: str, version: str) -> str:
    """Return the next unused numeric revision for a conflicting version."""
    version = changelog_version(version)
    match = re.fullmatch(r"(.+\.)(\d+)", version)
    prefix = match.group(1) if match else f"{version}."
    revision = int(match.group(2)) + 1 if match else 1
    while changelog_file(project, f"{prefix}{revision}").exists():
        revision += 1
    return f"{prefix}{revision}"


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
@permission_required("view")
def index():
    return render_template("index.html", max_upload_mb=MAX_UPLOAD_MB)


@app.get("/health")
def health():
    return jsonify(status="ok", storage=str(STORAGE_DIR))


@app.get("/api/changelogs")
@permission_required("view")
def list_changelogs():
    projects = []
    for project_dir in sorted((path for path in CHANGELOG_ROOT.iterdir() if path.is_dir()), key=lambda path: path.name):
        entries = []
        for path in sorted(project_dir.glob("v*.md"), key=lambda item: item.stat().st_mtime, reverse=True):
            try:
                payload = changelog_payload(path)
                entries.append({key: payload.get(key) for key in ("version", "date", "project", "live", "categories", "github_repository", "references", "filename", "modified")})
            except (OSError, UnicodeDecodeError):
                continue
        projects.append({"slug": project_dir.name, "entries": entries})
    return jsonify(projects=projects)


@app.get("/api/changelogs/template")
@permission_required("view")
def changelog_template():
    data = {
        "project": request.args.get("project", "Project name"),
        "version": request.args.get("version", "0.1.0"),
        "date": request.args.get("date", date.today().isoformat()),
        "live": request.args.get("live", "false").lower() == "true",
        "github_repository": request.args.get("github_repository", ""),
    }
    content, metadata = build_changelog(data, template=True)
    if request.args.get("format") == "json":
        return jsonify(metadata=metadata, markdown=content)
    return Response(content, content_type="text/markdown; charset=utf-8")


@app.post("/api/changelogs")
@permission_required("write")
def create_changelog():
    data = request.get_json(silent=True) or {}
    content, metadata = build_changelog(data)
    path = changelog_file(str(data.get("project", "")), str(data.get("version", "")))
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not data.get("overwrite", False):
        suggested_version = next_changelog_version(str(data.get("project", "")), str(data.get("version", "")))
        return jsonify(
            error=f"That project version already exists. Try version {suggested_version}.",
            suggested_version=suggested_version,
        ), 409
    path.write_text(content, encoding="utf-8")
    return jsonify(entry={**metadata, "project_slug": path.parent.name, "filename": path.name, "path": relative(path), "markdown": content}), 201


@app.get("/api/changelogs/<project>/<version>")
@permission_required("view")
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
@permission_required("view")
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
@permission_required("write")
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
@permission_required("write")
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
@permission_required("write")
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
@permission_required("view")
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
@permission_required("write")
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
@permission_required("view")
def raw_file():
    path = safe_path(request.args.get("path"))
    if not path.is_file():
        return jsonify(error="File not found"), 404
    return send_file(path, conditional=True)


@app.get("/api/download")
@permission_required("view")
def download_file():
    path = safe_path(request.args.get("path"))
    if not path.is_file():
        return jsonify(error="File not found"), 404
    downloads.inc()
    return send_file(path, as_attachment=True, download_name=path.name, conditional=True)


@app.patch("/api/entry")
@permission_required("write")
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
@permission_required("write")
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
