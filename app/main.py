from fastapi import FastAPI
from app.routes import router
from app.config import PORT

app = FastAPI(title="Crulon Cambium Agent", version="0.2.0")

app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=PORT)
