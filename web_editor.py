import asyncio
import codecs
import mimetypes
import re
import secrets
import shlex
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote
from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from config import env

PREFIX = "/edit9e3d4f94630041ec9dbd69c3d2bcebca"  # Внутренний префикс маршрутов — должен совпадать с тем, что реально доходит до бэкенда
app = APIRouter(tags=['Web Text editor'], prefix=PREFIX)

# Файловые зависимости редактора — все лежат в TEMPLATES_DIR, переносятся вместе с этим файлом
TEMPLATES_DIR = "templates"
TPL_LOGIN = "editor_login.html"
TPL_BROWSER = "editor_browser.html"
TPL_EDITOR = "editor.html"
TPL_READER = "reader.html"
TPL_SQLITE = "sqlite.html"

templates = Jinja2Templates(TEMPLATES_DIR)

SESSION_TIME = 3600 * 8  # Время жизни куки-сессии в секундах
COOKIE_NAME = "editor_token"
DEFAULT_PATH = env.DEFAULT_PATH
ROOT_DIR = Path.cwd().resolve()  # База для относительных путей (доступ разрешён ко всей файловой системе)
MAX_EDIT_SIZE = 5 * 1024 * 1024  # Файлы больше 5 МБ не открываем в textarea
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # Лимит на размер загружаемого файла

# token -> время истечения сессии
sessions: dict[str, float] = {}


# ---------------------------------------------------------------- auth


def _is_authed(request: Request) -> bool:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return False
    expires = sessions.get(token)
    if not expires or expires < time.time():
        sessions.pop(token, None)
        return False
    sessions[token] = time.time() + SESSION_TIME  # продлеваем при активности
    return True


def _login_redirect(request: Request):
    next_url = "./" + (f"?{request.url.query}" if request.url.query else "")
    return RedirectResponse(f"login?next={next_url}", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "./"):
    return templates.TemplateResponse(
        request=request, name=TPL_LOGIN,
        context={"next": next, "error": ""},
    )


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    password = form.get("password", "")
    next_url = form.get("next") or "./"
    if not next_url.startswith("./"):
        next_url = "./"
    if not env.EDITOR_PASSWORD or not secrets.compare_digest(password, env.EDITOR_PASSWORD):
        return templates.TemplateResponse(
            request=request, name=TPL_LOGIN,
            context={"next": next_url, "error": "Неверный пароль"},
            status_code=401,
        )
    token = secrets.token_urlsafe(32)
    sessions[token] = time.time() + SESSION_TIME
    response = RedirectResponse(next_url, status_code=302)
    response.set_cookie(
        COOKIE_NAME, token,
        max_age=SESSION_TIME, httponly=True, samesite="lax",
    )
    return response


@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    sessions.pop(token, None)
    response = RedirectResponse("./login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response


# ---------------------------------------------------------------- files
FS_TIMEOUT = 8  # секунд
EXEC_TIMEOUT = 30  # секунд на выполнение shell-команды
STREAM_MAX_TIME = 3600     # макс. длительность одного SSE-стрима, сек
STREAM_MAX_CONCURRENT = 4  # одновременных SSE-стримов
STREAM_PING = 1.0          # период проверки разрыва соединения / heartbeat, сек


class FSTimeout(Exception):
    pass


async def _fs(func, *args):
    try:
        return await asyncio.wait_for(run_in_threadpool(func, *args), timeout=FS_TIMEOUT)
    except asyncio.TimeoutError:
        raise FSTimeout from None


def _fs_timeout_response(as_json: bool):
    message = "Файловая система не отвечает (таймаут). Похоже, недоступен сетевой диск."
    if as_json:
        return JSONResponse({"error": message}, status_code=504)
    return HTMLResponse(f"<h3>{message}</h3>", status_code=504)


def _resolve(path: str | None) -> Path:
    """Абсолютный путь на сервере (без ограничения ROOT_DIR)"""
    raw = path or DEFAULT_PATH
    base = ROOT_DIR if not Path(raw).is_absolute() else Path("/")
    return (base / raw).resolve()


def _rel(path: Path) -> str:
    return str(path)


def _is_binary(path: Path) -> bool:
    # is_file() — только обычные файлы (не FIFO/сокет/устройство), иначе
    # открытие на чтение ниже рискует зависнуть навсегда
    if not path.is_file():
        return True
    try:
        chunk = path.open("rb").read(8192)
    except OSError:
        return True
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    try:
        codecs.getincrementaldecoder("utf-8")().decode(chunk, final=False)
    except UnicodeDecodeError:
        return True
    return False


_SQLITE_MAGIC = b"SQLite format 3\x00"  # первые 16 байт любого файла БД SQLite


def _is_sqlite(path: Path) -> bool:
    # Определяем по сигнатуре файла, а не по расширению (.db/.sqlite/.sqlite3
    # необязательны). Содержит \x00 → такой файл всегда помечается бинарным.
    if not path.is_file():
        return False
    try:
        with path.open("rb") as f:
            return f.read(16) == _SQLITE_MAGIC
    except OSError:
        return False


def _fmt_size(size: int) -> str:
    for unit in ("B", "K", "M", "G"):
        if size < 1024 or unit == "G":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024


def _scan_entry(item: Path) -> dict:
    """Синхронная обработка одной записи — выполняется в потоке через _fs()."""
    try:
        stat = item.stat()
        broken = False
    except OSError:
        # Битый симлинк или недоступный по правам объект — iterdir() его
        # видит, а stat() (следующий по симлинку) падает
        stat = None
        broken = True
    is_dir = not broken and item.is_dir()
    # FIFO/сокет/устройство — stat() успешен, но open()+read() на таком
    # файле может зависнуть навсегда (например FIFO без второго конца).
    # Открываем только обычные файлы (is_file() = regular file).
    is_special = not broken and not is_dir and not item.is_file()
    is_binary = not broken and not is_dir and not is_special and _is_binary(item)
    return {
        "name": item.name + ("/" if is_dir else ""),
        "path": _rel(item),
        "is_dir": is_dir,
        "is_binary": is_binary,
        "is_sqlite": is_binary and _is_sqlite(item),  # БД SQLite — открываем во вьювере
        "broken": broken,
        "is_special": is_special,
        "size": "" if broken or is_dir else _fmt_size(stat.st_size),
        "mtime": "" if broken else datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
    }


async def _dir_listing(path: Path, show_hidden: bool) -> list[dict]:
    # Имена сначала — readdir() почти всегда быстрый; сортировка "папки
    # сверху" делается позже, когда is_dir уже известен для каждой записи
    # (чтобы не дёргать stat() дважды на медленной ФС).
    names = await _fs(lambda: [p.name for p in path.iterdir()])
    entries = []
    for name in names:
        if not show_hidden and name.startswith("."):
            continue
        item = path / name
        try:
            entries.append(await _fs(_scan_entry, item))
        except FSTimeout:
            entries.append({
                "name": name, "path": _rel(item), "is_dir": False,
                "is_binary": False, "is_sqlite": False, "broken": True,
                "is_special": False, "size": "", "mtime": "таймаут чтения",
            })
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return entries


@app.get("/", response_class=HTMLResponse)
async def root(request: Request, path: str = None, edit: bool = False,
               hidden: bool = False):
    if not _is_authed(request):
        return _login_redirect(request)
    target = _resolve(path)
    try:
        if not await _fs(target.exists):
            return HTMLResponse("<h3>Путь не найден</h3>", status_code=404)

        if await _fs(target.is_dir):
            parent = _rel(target.parent) if target.parent != target else None
            return templates.TemplateResponse(
                request=request, name=TPL_BROWSER,
                context={
                    "dirname": _rel(target) or ".",
                    "parent": parent,
                    "entries": await _dir_listing(target, hidden),
                    "hidden": hidden,
                }
            )

        if not await _fs(target.is_file):
            # FIFO/сокет/устройство — открывать их read()-ом небезопасно (может
            # зависнуть навсегда и заморозить весь процесс), поэтому даже не пробуем
            return HTMLResponse("<h3>Это не обычный файл, открыть нельзя</h3>", status_code=400)
        if await _fs(_is_sqlite, target):
            # База SQLite — не редактируем как текст, открываем в табличном вьювере
            return templates.TemplateResponse(
                request=request, name=TPL_SQLITE,
                context={"filename": _rel(target), "parent": _rel(target.parent)},
            )
        if await _fs(_is_binary, target):
            return HTMLResponse("<h3>Бинарный файл нельзя открыть в редакторе</h3>", status_code=400)
        stat = await _fs(target.stat)
    except FSTimeout:
        return _fs_timeout_response(as_json=False)

    if stat.st_size > MAX_EDIT_SIZE:
        return HTMLResponse("<h3>Файл слишком большой для редактора</h3>", status_code=400)

    html_name = TPL_EDITOR if edit else TPL_READER
    return templates.TemplateResponse(
        request=request, name=html_name,
        context={
            "filename": _rel(target),
            "parent": _rel(target.parent),
            "comment": "",
        }
    )


@app.get("/download")
async def download_file(request: Request, path: str = None):
    """Отдать файл как есть: браузер сам решит — открыть (картинки, PDF, видео,
    аудио и т.п.) или скачать (всё остальное). Используется для бинарных файлов,
    которые нельзя показать в текстовом редакторе."""
    if not _is_authed(request):
        return _login_redirect(request)
    target = _resolve(path)
    try:
        # Только обычные файлы — FIFO/сокет/устройство открывать нельзя (зависнет)
        if not await _fs(target.is_file):
            return HTMLResponse("<h3>Это не обычный файл, скачать нельзя</h3>", status_code=400)
    except FSTimeout:
        return _fs_timeout_response(as_json=False)
    media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    # inline: браузер покажет то, что умеет, остальное предложит скачать —
    # filename задаёт имя при сохранении
    return FileResponse(
        str(target),
        media_type=media_type,
        filename=target.name,
        content_disposition_type="inline",
    )


SQLITE_PAGE_SIZE = 50    # строк на страницу по умолчанию
SQLITE_MAX_LIMIT = 500   # потолок на количество строк за один запрос


def _sqlite_cell(value):
    """Готовим значение ячейки к JSON: BLOB не сериализуется — показываем размер."""
    if isinstance(value, bytes):
        return f"<BLOB {len(value)} байт>"
    return value


def _read_sqlite(path: Path, table: str | None, limit: int, offset: int) -> dict:
    """Синхронно читаем БД в режиме read-only — список таблиц/представлений и
    строки выбранной таблицы с пагинацией. Выполняется в потоке через _fs()."""
    uri = f"file:{quote(str(path))}?mode=ro"  # mode=ro — только чтение, правки исключены
    try:
        con = sqlite3.connect(uri, uri=True, timeout=FS_TIMEOUT)
    except sqlite3.Error as e:
        return {"error": f"Не удалось открыть базу: {e}"}
    try:
        cur = con.cursor()
        cur.execute(
            "SELECT name, type FROM sqlite_master "
            "WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' "
            "ORDER BY type, name"
        )
        objects = [{"name": name, "type": otype} for name, otype in cur.fetchall()]
        names = [o["name"] for o in objects]
        if not names:
            return {"tables": [], "table": None, "columns": [], "rows": [],
                    "total": 0, "limit": limit, "offset": offset}
        if table is None or table not in names:
            table = names[0]
        # Идентификатор берём из реального списка таблиц и экранируем кавычки —
        # защита от SQL-инъекции через параметр table
        quoted = '"' + table.replace('"', '""') + '"'
        total = cur.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
        cur.execute(f"SELECT * FROM {quoted} LIMIT ? OFFSET ?", (limit, offset))
        columns = [d[0] for d in cur.description]
        rows = [[_sqlite_cell(v) for v in row] for row in cur.fetchall()]
    except sqlite3.Error as e:
        return {"error": f"Ошибка SQLite: {e}"}
    finally:
        con.close()
    return {
        "tables": objects,
        "table": table,
        "columns": columns,
        "rows": rows,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/sqlite")
async def sqlite_data(request: Request, path: str = None, table: str = None,
                      limit: int = SQLITE_PAGE_SIZE, offset: int = 0):
    """Содержимое БД SQLite в JSON: список таблиц и строки выбранной таблицы.
    База открывается только на чтение."""
    if not _is_authed(request):
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    target = _resolve(path)
    limit = max(1, min(limit, SQLITE_MAX_LIMIT))
    offset = max(0, offset)
    try:
        if not await _fs(target.is_file):
            return JSONResponse({"error": "Файл не найден"}, status_code=404)
        if not await _fs(_is_sqlite, target):
            return JSONResponse({"error": "Это не файл базы SQLite"}, status_code=400)
        result = await _fs(_read_sqlite, target, table, limit, offset)
    except FSTimeout:
        return _fs_timeout_response(as_json=True)
    if "error" in result:
        return JSONResponse(result, status_code=400)
    return result


@app.get("/exists")
async def file_exists(request: Request, path: str = None):
    if not _is_authed(request):
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    try:
        exists = await _fs(_resolve(path).is_file)
    except FSTimeout:
        return _fs_timeout_response(as_json=True)
    return {"exists": exists}


@app.get("/load")
async def load_file(request: Request, path: str = None, filename: str = None):
    if not _is_authed(request):
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    target = _resolve(path or filename)
    try:
        if not await _fs(target.is_file):
            return JSONResponse({"error": "Файл не найден"}, status_code=404)
        if await _fs(_is_binary, target):
            return JSONResponse({"error": "Бинарный файл"}, status_code=400)
        content = await _fs(target.read_text)
        mtime = (await _fs(target.stat)).st_mtime
    except FSTimeout:
        return _fs_timeout_response(as_json=True)
    return {
        "content": content,
        "filename": _rel(target),
        "mtime": mtime,
    }


@app.post("/save")
async def save_file(request: Request):
    if not _is_authed(request):
        return JSONResponse({"error": "Сессия истекла, войдите заново"}, status_code=401)
    data = await request.json()
    target = _resolve(data.get("path"))
    content = data.get("content")
    if content is None:
        return JSONResponse({"error": "Нет данных"}, status_code=400)
    # Защита от перезаписи: файл изменился после загрузки клиентом
    loaded_mtime = data.get("mtime")
    try:
        if await _fs(target.exists):
            current_mtime = (await _fs(target.stat)).st_mtime
            if loaded_mtime is None or abs(current_mtime - loaded_mtime) > 1e-6:
                return JSONResponse(
                    {"error": "Файл был изменён кем-то другим после загрузки. "
                              "Перезагрузите файл и повторите правки.",
                     "conflict": True},
                    status_code=409,
                )
        await _fs(target.write_text, content)
        mtime = (await _fs(target.stat)).st_mtime
    except FSTimeout:
        return _fs_timeout_response(as_json=True)
    return {"status": "ok", "mtime": mtime}


@app.post("/upload")
async def upload_file(request: Request):
    """Загрузить файл в открытую в браузере папку."""
    if not _is_authed(request):
        return JSONResponse({"error": "Сессия истекла, войдите заново"}, status_code=401)
    form = await request.form()
    upload = form.get("file")
    if upload is None or not getattr(upload, "filename", ""):
        return JSONResponse({"error": "Файл не выбран"}, status_code=400)

    # Каталог назначения — папка, открытая в браузере
    dest_dir = _resolve(form.get("dir"))
    # Берём только имя файла — защита от обхода каталога через слеши в имени
    name = Path(upload.filename).name
    if not name or name in (".", ".."):
        return JSONResponse({"error": "Некорректное имя файла"}, status_code=400)
    target = dest_dir / name

    overwrite = str(form.get("overwrite", "")).lower() in ("1", "true", "on", "yes")
    try:
        if not await _fs(dest_dir.is_dir):
            return JSONResponse({"error": "Папка назначения не найдена"}, status_code=404)
        if await _fs(target.exists) and not overwrite:
            return JSONResponse(
                {"error": f"Файл «{name}» уже существует. Подтвердите перезапись.",
                 "exists": True, "name": name},
                status_code=409,
            )
    except FSTimeout:
        return _fs_timeout_response(as_json=True)

    # Читаем загрузку по частям с ограничением размера, затем пишем на диск
    size = 0
    chunks = []
    while True:
        chunk = await upload.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_UPLOAD_SIZE:
            return JSONResponse(
                {"error": f"Файл больше лимита {_fmt_size(MAX_UPLOAD_SIZE)}"},
                status_code=413,
            )
        chunks.append(chunk)
    data = b"".join(chunks)

    try:
        await _fs(target.write_bytes, data)
    except FSTimeout:
        return _fs_timeout_response(as_json=True)
    except OSError as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    return {"status": "ok", "name": name, "path": _rel(target), "size": size}


# ---------------------------------------------------------------- shell
# Ограничение команд — это «предохранитель» от необратимо разрушительных
# действий, а НЕ песочница: оператор уже прошёл аутентификацию по паролю.
# Настоящая защита — надёжный EDITOR_PASSWORD + доступ только по HTTPS.
# Обойти blacklist при желании можно; его цель — не дать угробить сервер
# случайной командой (снести систему, отформатировать/затереть диск, вырубить
# питание). Для смягчения гибкости оставляем всё остальное разрешённым.

# Каталоги, рекурсивное удаление / смена прав которых блокируется
_PROTECTED_PATHS = {
    "/", "/*", "~", "/bin", "/boot", "/dev", "/etc", "/home", "/lib",
    "/lib64", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/usr", "/var",
}

# Однозначно опасные конструкции (проверяются по сырой строке)
_DANGEROUS_PATTERNS = [
    # Перезагрузка (reboot / systemctl reboot / shutdown -r / init 6) разрешена.
    # Блокируем только полное выключение — после него сервер сам не поднимется.
    (re.compile(r'(?:^|[\s;&|(])(?:poweroff|halt)\b'),
     "полное выключение сервера (poweroff/halt)"),
    (re.compile(r'\bshutdown\b(?!\s.*(?:-r\b|--reboot\b))'),
     "выключение через shutdown (для перезагрузки: shutdown -r или reboot)"),
    (re.compile(r'\binit\s+0\b'),
     "выключение через init 0"),
    (re.compile(r'\bsystemctl\s+(?:poweroff|halt|suspend|hibernate)\b'),
     "выключение/сон через systemctl"),
    (re.compile(r'\b(?:mkfs\S*|wipefs|fdisk|sfdisk|sgdisk|parted|shred)\b'),
     "форматирование/затирание диска или разделов"),
    (re.compile(r'(?:^|[\s;&|(])dd\b'),
     "низкоуровневая запись через dd"),
    (re.compile(r'of=\s*/dev/'),
     "запись напрямую в устройство"),
    (re.compile(r'>\s*/dev/(?:sd|nvme|hd|disk|mmcblk|vd)'),
     "перенаправление вывода в дисковое устройство"),
    (re.compile(r':\s*\(\s*\)\s*\{.*:.*\|.*:.*&'),
     "fork bomb"),
]

_RECURSIVE_FLAGS = {"-r", "-R", "-rf", "-fr", "-Rf", "-fR", "--recursive"}
_DESTRUCTIVE_CMDS = ("rm", "chmod", "chown", "chgrp")


def _is_protected_path(token: str) -> bool:
    p = token.rstrip("/") or "/"
    return token in _PROTECTED_PATHS or p in _PROTECTED_PATHS


def _reject_reason(command: str) -> str | None:
    """Причина отказа выполнить команду, либо None если она допустима."""
    for pattern, reason in _DANGEROUS_PATTERNS:
        if pattern.search(command):
            return reason
    try:
        # shlex не разбивает по ;/&&/|, но операторы попадают в токены — этого
        # достаточно, чтобы увидеть саму опасную под-команду (rm/chmod/...).
        tokens = shlex.split(command, comments=False)
    except ValueError:
        return "не удалось разобрать команду (незакрытые кавычки?)"

    def _is_cmd(tok: str) -> bool:
        return tok in _DESTRUCTIVE_CMDS or tok.rsplit("/", 1)[-1] in _DESTRUCTIVE_CMDS

    if any(_is_cmd(t) for t in tokens):
        recursive = any(
            t in _RECURSIVE_FLAGS
            or (len(t) > 1 and t[0] == "-" and t[1] != "-" and ("r" in t or "R" in t))
            for t in tokens
        )
        hits = sorted({t for t in tokens if _is_protected_path(t)})
        if recursive and hits:
            return f"рекурсивная операция над системным путём: {', '.join(hits)}"
    return None


@app.post("/exec")
async def exec_command(request: Request):
    """Выполнить shell-команду в текущей папке браузера и вернуть вывод."""
    if not _is_authed(request):
        return JSONResponse({"error": "Сессия истекла, войдите заново"}, status_code=401)
    data = await request.json()
    command = (data.get("command") or "").strip()
    if not command:
        return JSONResponse({"error": "Пустая команда"}, status_code=400)

    reason = _reject_reason(command)
    if reason:
        return JSONResponse(
            {"error": f"Команда заблокирована: {reason}"},
            status_code=403,
        )

    # cwd — та же папка, что открыта в браузере (если пришёл путь к файлу,
    # берём его каталог); при недоступной ФС откатываемся к корню проекта
    target = _resolve(data.get("cwd"))
    try:
        cwd = target if await _fs(target.is_dir) else target.parent
    except FSTimeout:
        return _fs_timeout_response(as_json=True)

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,  # объединяем поток ошибок с выводом
        )
    except OSError as e:
        return JSONResponse({"error": str(e), "cwd": str(cwd)}, status_code=500)

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=EXEC_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return JSONResponse(
            {"error": f"Команда превысила лимит {EXEC_TIMEOUT}с и была прервана",
             "cwd": str(cwd)},
            status_code=504,
        )

    return {
        "output": stdout.decode("utf-8", errors="replace"),
        "returncode": proc.returncode,
        "cwd": str(cwd),
    }


# ---------------------------------------------------------------- shell stream (SSE)
# Потоковый вывод долгоживущих команд (tail -f, journalctl -f, docker logs -f)
# через Server-Sent Events. Обычный /exec для этого не годится — он копит вывод
# в буфер и ждёт завершения процесса.

# Число сейчас работающих стримов — ограничиваем, чтобы не плодить процессы
_active_streams = 0


def _sse(data: str, event: str | None = None) -> str:
    """Собрать SSE-кадр. Многострочный текст разбиваем на несколько data:-строк."""
    head = f"event: {event}\n" if event else ""
    body = "".join(f"data: {line}\n" for line in data.split("\n"))
    return head + body + "\n"


@app.get("/stream")
async def stream_command(request: Request, cmd: str = "", cwd: str = None):
    """SSE-поток вывода команды в текущей папке; процесс убивается при разрыве."""
    if not _is_authed(request):
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    command = (cmd or "").strip()
    if not command:
        return JSONResponse({"error": "Пустая команда"}, status_code=400)

    reason = _reject_reason(command)
    if reason:
        return JSONResponse({"error": f"Команда заблокирована: {reason}"}, status_code=403)

    if _active_streams >= STREAM_MAX_CONCURRENT:
        return JSONResponse(
            {"error": f"Слишком много активных потоков (макс. {STREAM_MAX_CONCURRENT})"},
            status_code=429,
        )

    target = _resolve(cwd)
    try:
        run_cwd = target if await _fs(target.is_dir) else target.parent
    except FSTimeout:
        return _fs_timeout_response(as_json=True)

    async def gen():
        global _active_streams
        _active_streams += 1
        proc = None
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                cwd=str(run_cwd),
                stdin=asyncio.subprocess.DEVNULL,   # нет ввода — интерактив не зависнет
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            yield _sse(f"$ {command}   ({run_cwd})", event="meta")
            deadline = time.time() + STREAM_MAX_TIME
            while True:
                # Активная проверка разрыва + heartbeat: запись пинга в закрытый
                # сокет упадёт и мы выйдем в finally, где убьём процесс.
                if await request.is_disconnected():
                    break
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=STREAM_PING)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    if time.time() > deadline:
                        yield _sse(f"[поток остановлен: лимит {STREAM_MAX_TIME}с]", event="end")
                        break
                    continue
                if not line:                        # EOF — процесс завершился сам
                    await proc.wait()
                    yield _sse(f"[процесс завершён, код {proc.returncode}]", event="end")
                    break
                yield _sse(line.decode("utf-8", errors="replace").rstrip("\n"))
                if time.time() > deadline:
                    yield _sse(f"[поток остановлен: лимит {STREAM_MAX_TIME}с]", event="end")
                    break
        finally:
            if proc and proc.returncode is None:
                proc.kill()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    pass
            _active_streams -= 1

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # не буферизовать на обратном прокси (nginx)
        },
    )
