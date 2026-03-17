import logging
import os
from datetime import datetime
from typing import List
from app.database.mongodb import get_database

logger = logging.getLogger(__name__)

BEHAVIORAL_WINDOW = 50
BEHAVIORAL_ESCALATION_THRESHOLD = int(os.getenv("BEHAVIORAL_ESCALATION_THRESHOLD", "15"))

class BehavioralRiskAnalyzer:
    """
    Analyzes historical threat logs for a user to calculate a behavioral risk bonus.
    If a user has a high frequency of recent 'Suspicious' or 'Blocked' actions, their risk score is elevated.
    """

    async def compute_delta(self, user_id: str) -> int:
        """
        Calculates a risk bonus based on the last 50 events for this user.
        Bonus = (+15) if (>10% of last 50 results were Blocked/Sanitized).
        """
        db = get_database()
        if db is None:
            return 0

        try:
            # Fetch last 50 threat logs for this user
            cursor = db.threat_logs.find(
                {"user_id": user_id},
                {"action_taken": 1}
            ).sort("timestamp", -1).limit(BEHAVIORAL_WINDOW)
            
            logs = await cursor.to_list(length=BEHAVIORAL_WINDOW)
            if not logs:
                return 0

            # Count recent malicious/suspicious activity
            threat_count = sum(1 for log in logs if log.get("action_taken") in ["Blocked", "Sanitized"])
            
            # If more than 10% (i.e. 5 out of 50, or scaled if fewer logs exist)
            threshold = max(2, int(len(logs) * 0.1))
            if threat_count >= threshold:
                logger.info(f"Behavioral escalation triggered for {user_id}: {threat_count} threats in last {len(logs)} events.")
                return BEHAVIORAL_ESCALATION_THRESHOLD

            return 0
        except Exception as e:
            logger.warning(f"Behavioral analysis failed for {user_id}: {e}")
            return 0

behavioral_analyzer = BehavioralRiskAnalyzer()
