from app.database.mongodb import get_database
from app.models.schemas import ThreatLog

class SecurityLogger:
    def __init__(self):
        pass

    async def log_event(self, log: ThreatLog):
        db = get_database()
        if db is not None:
            await db.threat_logs.insert_one(log.model_dump())
        else:
            # Fallback for dev/testing without MongoDB running
            print(f"Logged Security Event: {log.dict()}")

security_logger = SecurityLogger()
