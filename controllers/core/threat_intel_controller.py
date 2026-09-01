from fastapi.responses import JSONResponse
from models.mitre_mapper import ThreatIntelMapper

mapper = ThreatIntelMapper()

async def get_mitre_mapping(attack_type: str) -> JSONResponse:
    intel = mapper.enrich(attack_type.upper(), anomaly_score=0.0)
    return JSONResponse(content=intel)