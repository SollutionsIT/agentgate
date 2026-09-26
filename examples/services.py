"""Deterministic workloads; no external APIs and no money movement."""

import os

from fastapi import FastAPI

app = FastAPI(docs_url=None, redoc_url=None)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


if os.environ.get("DEMO_SERVICE") == "weather":

    @app.get("/weather")
    def weather() -> dict[str, object]:
        return {"city": "Lisbon", "temperature_c": 22, "conditions": "sunny", "demo": True}
else:

    @app.get("/balance")
    def balance() -> dict[str, object]:
        return {"balance": "1000.00", "currency": "EUR", "demo": True}

    @app.post("/transfer-preview")
    def transfer_preview() -> dict[str, object]:
        return {"status": "preview_only", "money_moved": False, "demo": True}
