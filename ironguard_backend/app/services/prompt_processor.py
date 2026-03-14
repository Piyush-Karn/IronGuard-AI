import re

class PromptProcessor:
    def normalize(self, prompt: str) -> str:
        # Lowercase, remove excessive spaces
        normalized = prompt.strip()
        normalized = re.sub(r'\s+', ' ', normalized)
        return normalized

    def sanitize(self, prompt: str) -> str:
        # Basic sanitization, escaping potentially harmful characters if necessary
        # Usually LLMs can handle text, but we stop injection via isolation later
        sanitized = prompt.replace('<', '&lt;').replace('>', '&gt;')
        return sanitized
        
    def isolate_instruction(self, original_prompt: str, user_input: str) -> str:
        # Wrap user input in XML tags to prevent system prompt injection
        return f"{original_prompt}\n<user_input>\n{user_input}\n</user_input>"

prompt_processor = PromptProcessor()
