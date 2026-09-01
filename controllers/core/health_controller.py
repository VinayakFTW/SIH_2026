from fastapi.responses import JSONResponse

async def get_health_status() -> JSONResponse:
    return JSONResponse(content={"status": "online", "version": "1.0.0"})