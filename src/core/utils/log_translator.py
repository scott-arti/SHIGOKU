import logging
import threading
import queue
import time
import os

class OllamaLogTranslator(logging.Handler):
    """
    Log Translator using LLMClient (role=tool_output_analysis).
    Translates logs to Japanese when not using local LLM for main tasks.
    """
    def __init__(self):
        super().__init__()
        self.log_queue = queue.Queue()
        self.stop_event = threading.Event()
        self._llm_client = None
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        
    def emit(self, record):
        """Queue log record for translation."""
        try:
            msg = self.format(record)
            # Skip empty or already Japanese messages (simple heuristic)
            if not msg or self._is_japanese(msg):
                return
            self.log_queue.put(msg)
        except Exception:
            self.handleError(record)

    def _is_japanese(self, text):
        """Simple check if text contains Japanese characters."""
        for char in text:
            if '\u3000' <= char <= '\u9fff':
                return True
        return False

    def _worker(self):
        """Background worker to translate logs."""
        while not self.stop_event.is_set():
            try:
                # Batch processing could be better, but line-by-line for now
                msg = self.log_queue.get(timeout=1.0)
                translated = self._translate(msg)
                if translated:
                    # Print directly to stderr to avoid recursive logging loop
                    # using a distinct prefix
                    print(f"\033[36m[Ollama翻訳] {translated}\033[0m")
                self.log_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                # Silently fail to avoid spamming stderr
                pass

    def _get_llm_client(self):
        """Lazy-initialize LLMClient."""
        if self._llm_client is None:
            from src.core.models.llm import LLMClient
            self._llm_client = LLMClient(role="tool_output_analysis")
        return self._llm_client

    def _translate(self, text):
        """Call LLMClient to translate text."""
        try:
            prompt = f"Translate the following log message to Japanese concisely. Do not add explanations. Log: {text}"
            messages = [{"role": "user", "content": prompt}]
            response = self._get_llm_client().generate(messages)
            if hasattr(response, 'choices') and response.choices:
                return response.choices[0].message.content.strip()
            return text  # fallback to original
        except Exception:
            return text  # fallback to original on failure
            
    def close(self):
        self.stop_event.set()
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=2.0)
        super().close()

def enable_log_translation():
    """Enable log translation if criteria are met."""
    if os.getenv("SHIGOKU_TRANSLATE_LOGS") != "true":
        return

    # Only enable if NOT using local LLM for main generation (to avoid resource contention)
    # Checking env var or settings... assuming simple check for now
    # User said "Ollamaを使っていないときに限って" -> "Only when NOT using Ollama"
    
    # We can assume if the user enables this flag, they know what they are doing.
    translator = OllamaLogTranslator()
    logging.getLogger().addHandler(translator)
    print("\033[36m⚡ Experimental Log Translation Enabled (via Ollama)\033[0m")
