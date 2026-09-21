from evidencesoc.openapi import EvidenceSOCApp

app = EvidenceSOCApp(
    title="EvidenceSOC API",
    version="0.1.0",
)


@app.get("/health/live")
async def live_health() -> dict[str, str]:
    return {"status": "ok"}