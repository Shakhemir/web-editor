import asyncio
import codecs
import secrets
import time
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from config import env

PREFIX = "/edit"  # Внутренний префикс маршрутов — должен совпадать с тем, что реально доходит до бэкенда
app = APIRouter(tags=['Web Text editor'], prefix=PREFIX)

# Файловые зависимости редактора — все лежат в TEMPLATES_DIR, переносятся вместе с этим файлом
TEMPLATES_DIR = "templates"
TPL_LOGIN = "editor_login.html"
TPL_BROWSER = "editor_browser.html"
TPL_EDITOR = "editor.html"
TPL_READER = "reader.html"

templates = Jinja2Templates(TEMPLATES_DIR)

SESSION_TIME = 3600 * 8  # Время жизни куки-сессии в секундах
COOKIE_NAME = "editor_token"
DEFAULT_PATH = env.DEFAULT_PATH
ROOT_DIR = Path.cwd().resolve()  # База для относительных путей (доступ разрешён ко всей файловой системе)
MAX_EDIT_SIZE = 5 * 1024 * 1024  # Файлы больше 5 МБ не открываем в textarea

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
#
# Любой вызов ниже может упереться в файл на зависшей сетевой/FUSE-точке
# монтирования (NFS, CIFS, sshfs...): stat()/is_file() при этом отвечают
# как для обычного файла, а вот реальное чтение блоков идёт по сети и может
# зависнуть НАВСЕГДА. Раз редактору открыта вся файловая система, а не
# только каталог проекта, наткнуться на такую точку — вопрос времени.
# Поэтому каждый потенциально блокирующий вызов идёт в отдельном потоке
# с таймаутом: поток может зависнуть сам по себе, но event loop (и все
# остальные запросы) при этом не замораживаются.

FS_TIMEOUT = 8  # секунд


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
    return {
        "name": item.name + ("/" if is_dir else ""),
        "path": _rel(item),
        "is_dir": is_dir,
        "is_binary": not broken and not is_dir and not is_special and _is_binary(item),
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
                "is_binary": False, "broken": True, "is_special": False,
                "size": "", "mtime": "таймаут чтения",
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
