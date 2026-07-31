import uvicorn
from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from config import env
from web_editor import app as editor_router

app = FastAPI(title="Web Editor")
app.include_router(editor_router)


@app.get("/")
async def index():
    return RedirectResponse("/edit/")


if __name__ == "__main__":
    uvicorn.run("main:app", host=env.HOST, port=env.PORT, reload=False)
