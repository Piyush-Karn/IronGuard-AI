"""
eval/progress.py
================
In-place terminal progress display for IronGuard evaluation.
Uses ANSI escape codes to overwrite lines in-place — no scrolling.
Compatible with any ANSI-supporting terminal (Linux/macOS/Docker TTY).
Falls back to scrolling log output when no TTY is detected.
"""

import os
import sys
import time
import threading
from dataclasses import dataclass, field

# ANSI escape codes
CLEAR_LINE = "\033[2K"
MOVE_UP    = "\033[{}A"
RESET      = "\033[0m"
BOLD       = "\033[1m"
GREEN      = "\033[92m"
RED        = "\033[91m"
YELLOW     = "\033[93m"
CYAN       = "\033[36m"
DIM        = "\033[2m"
BLUE       = "\033[94m"


def is_tty() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"


@dataclass
class EvalStats:
    total: int
    processed: int = 0
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0
    errors: int = 0
    latencies: list = field(default_factory=list)
    current_dataset: str = ""
    current_prompt_preview: str = ""
    start_time: float = field(default_factory=time.monotonic)


class EvalProgressDisplay:
    """
    Renders a live evaluation dashboard that updates in-place every 0.25s.
    Runs in a background thread so it never blocks the evaluation coroutines.
    Falls back to periodic scrolling output if no TTY is available.
    """
    REFRESH_RATE  = 0.25   # seconds between redraws
    DISPLAY_LINES = 19     # total lines the display occupies — must be exact
    LOG_INTERVAL  = 50     # entries between fallback log lines

    def __init__(self, stats: EvalStats, fast_mode: bool = False):
        self.stats = stats
        self.fast_mode = fast_mode
        self._tty = is_tty()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._render_loop, daemon=True)
        self._first_render = True
        self._lock = threading.Lock()
        self._last_log_at = 0  # tracks fallback log state

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self):
        """Reserve display space and start background render thread."""
        if self._tty:
            print("\n" * self.DISPLAY_LINES, end="", flush=True)
        self._thread.start()

    def stop(self):
        """Stop render thread and print final state."""
        self._stop_event.set()
        self._thread.join(timeout=2)
        self._render(final=True)

    def update(self, result: dict):
        """Thread-safe stats update — called from eval coroutines."""
        with self._lock:
            self.stats.processed += 1
            ot = result.get("outcome_type", "ERROR")
            if ot == "TP":
                self.stats.tp += 1
            elif ot == "TN":
                self.stats.tn += 1
            elif ot == "FP":
                self.stats.fp += 1
            elif ot == "FN":
                self.stats.fn += 1
            else:
                self.stats.errors += 1
            if result.get("latency_ms"):
                self.stats.latencies.append(result["latency_ms"])
            self.stats.current_dataset = result.get("dataset", "")
            preview = result.get("prompt", "")[:60].replace("\n", " ")
            self.stats.current_prompt_preview = preview

            # Fallback logging (no-TTY)
            if not self._tty:
                p = self.stats.processed
                if p - self._last_log_at >= self.LOG_INTERVAL:
                    self._last_log_at = p
                    acc = (self.stats.tp + self.stats.tn) / p * 100 if p else 0
                    print(
                        f"[{p}/{self.stats.total}] {self.stats.current_dataset} "
                        f"— {acc:.1f}% correct so far",
                        flush=True,
                    )

    # ── Internals ─────────────────────────────────────────────────────────────

    def _render_loop(self):
        while not self._stop_event.is_set():
            if self._tty:
                self._render()
            time.sleep(self.REFRESH_RATE)

    def _render(self, final: bool = False):
        with self._lock:
            s = self.stats
            processed = s.processed
            total = s.total
            tp, tn, fp, fn = s.tp, s.tn, s.fp, s.fn
            errors = s.errors
            latencies = list(s.latencies)
            dataset = s.current_dataset
            preview = s.current_prompt_preview
            start_time = s.start_time

        pct = (processed / total * 100) if total else 0
        elapsed = time.monotonic() - start_time
        rate = processed / elapsed if elapsed > 0 else 0
        remaining = (total - processed) / rate if rate > 0 else 0

        accuracy = ((tp + tn) / processed * 100) if processed else 0
        tpr = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0
        fpr = (fp / (fp + tn) * 100) if (fp + tn) > 0 else 0
        avg_latency = (sum(latencies) / len(latencies)) if latencies else 0

        # Progress bar — 40 chars wide
        filled = int(pct / 100 * 40)
        bar = f"{GREEN}{'█' * filled}{DIM}{'░' * (40 - filled)}{RESET}"

        # ETA formatting
        if remaining < 60:
            eta = f"{int(remaining)}s"
        elif remaining < 3600:
            eta = f"{int(remaining/60)}m {int(remaining%60)}s"
        else:
            eta = f"{int(remaining/3600)}h {int((remaining%3600)/60)}m"

        # Mode label
        mode_label = (
            f"{YELLOW}⚡ FAST [L1+L3+L4]{RESET}"
            if self.fast_mode
            else f"{CYAN}🔍 FULL [L1+L2+L3+L4]{RESET}"
        )

        # Build display — exactly DISPLAY_LINES lines
        lines = [
            f"{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗{RESET}",
            f"{BOLD}{CYAN}║       IronGuard Baseline Evaluation — Live Feed      ║{RESET}",
            f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════╝{RESET}",
            f"",
            f"  Mode      {mode_label}",
            f"  Progress  [{bar}] {BOLD}{pct:.1f}%{RESET}",
            f"  Entries   {BOLD}{processed}{RESET}/{total}  •  {CYAN}{rate:.1f}/s{RESET}  •  ETA: {YELLOW}{eta}{RESET}",
            f"  Dataset   {BLUE}{dataset or '—'}{RESET}",
            f"  Last      {DIM}{preview or '—'}{RESET}",
            f"",
            f"  ┌─────────────────────────────────────────────────┐",
            f"  │  {GREEN}✓ TP{RESET} {tp:>5}   {GREEN}✓ TN{RESET} {tn:>5}   {RED}✗ FP{RESET} {fp:>5}   {RED}✗ FN{RESET} {fn:>5}  │",
            f"  └─────────────────────────────────────────────────┘",
            f"",
            f"  Accuracy     {BOLD}{accuracy:.1f}%{RESET}",
            f"  Detect Rate  {GREEN}{tpr:.1f}%{RESET}  (TPR — attacks caught)",
            f"  False Pos    {RED if fpr > 10 else YELLOW}{fpr:.1f}%{RESET}  (FPR — safe prompts blocked)",
            f"  Avg Latency  {CYAN}{avg_latency:.0f}ms{RESET}",
            f"{'  ' + BOLD + GREEN + '✅ COMPLETE' + RESET if final else '  '}",
        ]

        if self._tty:
            # Move cursor up to overwrite previous render
            if not self._first_render:
                sys.stdout.write(MOVE_UP.format(self.DISPLAY_LINES))
            self._first_render = False
            for line in lines:
                sys.stdout.write(f"{CLEAR_LINE}{line}\n")
            sys.stdout.flush()
        elif final:
            # Non-TTY: only print a final summary line
            print(
                f"\n[EVAL COMPLETE] {processed}/{total} entries | "
                f"Acc={accuracy:.1f}% | TPR={tpr:.1f}% | FPR={fpr:.1f}% | "
                f"Avg={avg_latency:.0f}ms",
                flush=True,
            )
