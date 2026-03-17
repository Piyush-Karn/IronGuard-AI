import logging
import os
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, List, Tuple
from app.database.mongodb import get_database

logger = logging.getLogger(__name__)

CONTEXT_WINDOW = int(os.getenv("CONTEXT_WINDOW_SIZE", "5"))
CONTEXT_RISK_BONUS = int(os.getenv("CONTEXT_RISK_BONUS", "20"))

@dataclass
class ContextEntry:
    normalized_text: str
    risk_score: int
    timestamp: datetime

class ContextBuilder:
    """
    Manages multi-turn conversation history in MongoDB to detect context-based attacks.
    Backed by the 'sessions' collection with dual TTL: 24h rolling, 72h hard cap.
    """

    async def get_context(self, session_id: str, n: int = CONTEXT_WINDOW) -> List[ContextEntry]:
        """Fetch the last n messages for this session from MongoDB."""
        db = get_database()
        if db is None:
            return []

        try:
            session = await db.sessions.find_one({"session_id": session_id}, {"messages": {"$slice": -n}})
            if not session or "messages" not in session:
                return []

            return [
                ContextEntry(
                    normalized_text=m["normalized_text"],
                    risk_score=m["risk_score"],
                    timestamp=m["timestamp"]
                )
                for m in session["messages"]
            ]
        except Exception as e:
            logger.warning(f"Failed to fetch session context for {session_id}: {e}")
            return []

    async def add_to_context(
        self, session_id: str, user_id: str, normalized_text: str, risk_score: int
    ) -> None:
        """Append a new message to the session context and update the rolling last_updated TTL."""
        db = get_database()
        if db is None:
            return

        now = datetime.utcnow()
        try:
            # Upsert session with dual TTL: created_at (hard cap) and last_updated (rolling)
            await db.sessions.update_one(
                {"session_id": session_id},
                {
                    "$setOnInsert": {"user_id": user_id, "created_at": now},
                    "$set": {"last_updated": now},
                    "$push": {
                        "messages": {
                            "$each": [{
                                "normalized_text": normalized_text,
                                "risk_score": risk_score,
                                "timestamp": now
                            }],
                            "$slice": -10  # keep a bit more than window for safety
                        }
                    }
                },
                upsert=True
            )
        except Exception as e:
            logger.warning(f"Failed to add message to session {session_id}: {e}")

    async def build_context_prompt(
        self, session_id: str, current_prompt: str
    ) -> Tuple[str, int]:
        """
        Concatenates historical context to the current prompt to detect multi-turn attacks.
        Returns (augmented_prompt, context_bonus).
        """
        history = await self.get_context(session_id)
        if not history:
            return current_prompt, 0

        # Simple heuristic: if previous turns had high risk or we see a pattern of escalation
        # For now, we concatenate the last few messages to the prompt so detection layers see it.
        context_str = "\n".join([f"Turn: {h.normalized_text}" for h in history])
        augmented_prompt = f"Previous Context:\n{context_str}\n\nCurrent Prompt:\n{current_prompt}"
        
        # If any previous turn was suspicious (>30), apply a small bonus to make detection more sensitive
        context_bonus = 0
        if any(h.risk_score >= 30 for h in history):
            context_bonus = CONTEXT_RISK_BONUS

        return augmented_prompt, context_bonus

context_builder = ContextBuilder()
