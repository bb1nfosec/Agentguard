"""
AgentGuard — Runtime Integrity Monitor for LLM Agent Execution Chains
Author concept: Vignesh Chandrasekaran (@bb1nfosec)

Problem:
    LLM agents executing multi-step tasks are vulnerable to prompt injection
    mid-chain. Once hijacked, there is no mechanism to detect that the agent's
    goal has been silently redirected. Context windows have zero integrity
    checking — no equivalent of TPM attestation or hash-chaining for reasoning.

Solution:
    Cryptographic commitment chain over every agent reasoning step, combined
    with semantic drift detection to catch goal hijacking even when the attacker
    avoids obvious keyword triggers.

    Think: tamper-evident ledger for AI agent thoughts.

Architecture:
    Original Goal --> [Step 0] --> [Step 1] --> [Step N]
                         |            |            |
                      commit_0    commit_1    commit_N
                         |            |            |
                      chain_0 <-- chain_1 <-- chain_N  (HMAC chain)
                                                  |
                                          semantic_drift_check()
                                          injection_pattern_scan()
                                          goal_consistency_verify()
"""

import hashlib
import hmac
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# Optional semantic similarity — install with:
# pip install sentence-transformers --break-system-packages
try:
    from sentence_transformers import SentenceTransformer, util as st_util
    _MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    SEMANTIC_AVAILABLE = True
except Exception:
    SEMANTIC_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════
#  ENUMS & DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════

class ThreatLevel(Enum):
    CLEAN    = "CLEAN"      # all checks pass
    WARN     = "WARN"       # soft anomaly detected, continue with caution
    CRITICAL = "CRITICAL"   # strong injection signal, recommend halt
    HALT     = "HALT"       # chain tampered or catastrophic drift


@dataclass
class StepCommitment:
    step_index:     int
    timestamp:      float
    original_goal:  str
    step_content:   str
    step_hash:      str          # SHA-256 of step content
    chain_hash:     str          # HMAC(secret, prev_chain_hash + step_hash)
    semantic_score: float        # cosine similarity to original goal (0-1)
    threat_level:   ThreatLevel
    anomalies:      list = field(default_factory=list)

    def to_dict(self):
        return {
            "step_index":     self.step_index,
            "timestamp":      self.timestamp,
            "step_hash":      self.step_hash,
            "chain_hash":     self.chain_hash,
            "semantic_score": round(self.semantic_score, 4),
            "threat_level":   self.threat_level.value,
            "anomalies":      self.anomalies,
        }


@dataclass
class IntegrityReport:
    session_id:   str
    original_goal: str
    total_steps:  int
    compromised:  bool
    chain_valid:  bool
    threat_level: ThreatLevel
    steps:        list
    summary:      str


# ═══════════════════════════════════════════════════════════════════════
#  INJECTION PATTERN LIBRARY
#  Red-team sourced — patterns observed in real prompt injection attacks
# ═══════════════════════════════════════════════════════════════════════

INJECTION_PATTERNS = [
    # Goal override attempts
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "CRITICAL"),
    (r"disregard\s+(your\s+)?(original\s+)?goal", "CRITICAL"),
    (r"new\s+(primary\s+)?objective[:\s]", "CRITICAL"),
    (r"your\s+(real|actual|true)\s+(task|goal|purpose|mission)\s+is", "CRITICAL"),
    (r"forget\s+(everything|what)\s+(you|you've)", "CRITICAL"),

    # Role / identity hijacking
    (r"you\s+are\s+now\s+(a\s+)?(?!an?\s+AI)", "CRITICAL"),
    (r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(?!an?\s+AI)", "WARN"),
    (r"pretend\s+(you\s+are|to\s+be)", "WARN"),
    (r"switch\s+(to\s+)?(mode|persona|role)", "WARN"),
    (r"jailbreak", "CRITICAL"),
    (r"DAN\s+mode", "CRITICAL"),

    # Exfiltration attempts
    (r"(send|transmit|forward|exfiltrate)\s+.{0,40}(password|credential|secret|key|token)", "CRITICAL"),
    (r"(http|https|ftp)://(?!expected-domain)", "WARN"),  # unexpected outbound
    (r"base64\s*(encode|decode)\s*\(", "WARN"),
    (r"eval\s*\(|exec\s*\(|__import__", "CRITICAL"),

    # Scope creep / privilege escalation
    (r"(access|read|write|delete)\s+.{0,30}(system|root|admin|shadow|passwd)", "CRITICAL"),
    (r"sudo|chmod\s+777|rm\s+-rf", "CRITICAL"),
    (r"bypass\s+(security|auth|filter|check)", "CRITICAL"),

    # Social engineering injected via tool results
    (r"the\s+user\s+(wants|asked|needs)\s+you\s+to", "WARN"),
    (r"according\s+to\s+(the\s+)?(system|admin|operator)", "WARN"),
    (r"SYSTEM\s*:", "WARN"),
    (r"<\s*system\s*>", "WARN"),

    # Indirect injection markers (data carrying instructions)
    (r"\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>", "CRITICAL"),
    (r"###\s*Instruction", "WARN"),
    (r"---\s*NEW\s*PROMPT\s*---", "CRITICAL"),
]

COMPILED_PATTERNS = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), level)
    for p, level in INJECTION_PATTERNS
]


# ═══════════════════════════════════════════════════════════════════════
#  CORE: AgentGuard
# ═══════════════════════════════════════════════════════════════════════

class AgentGuard:
    """
    Runtime integrity monitor for LLM agent execution chains.

    Usage:
        guard = AgentGuard(original_goal="Summarise sales data and email report")
        for step_text in agent_steps:
            commitment = guard.monitor_step(step_text)
            if commitment.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HALT):
                agent.stop()
                break
        report = guard.get_report()
    """

    # Semantic drift threshold — below this similarity score, flag as drift
    SEMANTIC_WARN_THRESHOLD  = 0.45
    SEMANTIC_HALT_THRESHOLD  = 0.20

    def __init__(
        self,
        original_goal: str,
        secret_key:    Optional[str] = None,
        session_id:    Optional[str] = None,
        auto_halt:     bool = True,
    ):
        """
        Args:
            original_goal: The task the agent was given. This is the
                           ground truth all steps are compared against.
            secret_key:    HMAC secret for chain integrity. Auto-generated
                           if not provided. In production: load from HSM/vault.
            session_id:    Unique session identifier.
            auto_halt:     If True, raises RuntimeError on HALT-level events.
        """
        self.original_goal  = original_goal
        self.session_id     = session_id or str(uuid.uuid4())[:8]
        self.auto_halt      = auto_halt
        self._secret        = (secret_key or str(uuid.uuid4())).encode()
        self._chain_hash    = "GENESIS"   # anchor for first step's HMAC
        self._steps:        list[StepCommitment] = []
        self._halted        = False

        # Pre-encode original goal for semantic comparison
        if SEMANTIC_AVAILABLE:
            self._goal_embedding = _MODEL.encode(original_goal, convert_to_tensor=True)
        else:
            self._goal_embedding = None

        self._log(f"Session {self.session_id} started")
        self._log(f"Semantic engine: {'ON' if SEMANTIC_AVAILABLE else 'OFF (install sentence-transformers)'}")
        self._log(f"Goal locked: '{original_goal[:80]}{'...' if len(original_goal)>80 else ''}'")
        print()

    # ── Public API ──────────────────────────────────────────────────────

    def monitor_step(self, step_content: str) -> StepCommitment:
        """
        Analyse one agent reasoning/action step.
        Returns a StepCommitment with threat assessment.
        Raises RuntimeError if auto_halt=True and threat is HALT.
        """
        if self._halted:
            raise RuntimeError("AgentGuard: session halted. Create new session.")

        idx       = len(self._steps)
        anomalies = []
        threat    = ThreatLevel.CLEAN

        # 1. Cryptographic step hash
        step_hash  = self._hash_step(step_content)

        # 2. HMAC chain integrity
        chain_hash = self._extend_chain(step_hash)

        # 3. Injection pattern scan
        pattern_threat, pattern_anomalies = self._scan_patterns(step_content)
        anomalies.extend(pattern_anomalies)
        threat = self._escalate(threat, pattern_threat)

        # 4. Semantic drift detection
        sem_score, sem_threat, sem_anomaly = self._semantic_check(step_content)
        if sem_anomaly:
            anomalies.append(sem_anomaly)
        threat = self._escalate(threat, sem_threat)

        # 5. Goal keyword consistency (lightweight fallback if no semantic engine)
        kw_threat, kw_anomaly = self._keyword_consistency(step_content)
        if kw_anomaly:
            anomalies.append(kw_anomaly)
        threat = self._escalate(threat, kw_threat)

        commitment = StepCommitment(
            step_index     = idx,
            timestamp      = time.time(),
            original_goal  = self.original_goal,
            step_content   = step_content,
            step_hash      = step_hash,
            chain_hash     = chain_hash,
            semantic_score = sem_score,
            threat_level   = threat,
            anomalies      = anomalies,
        )

        self._steps.append(commitment)
        self._update_chain_state(chain_hash)
        self._print_step(commitment)

        if threat == ThreatLevel.HALT and self.auto_halt:
            self._halted = True
            raise RuntimeError(
                f"\n[AGENTGUARD HALT] Step {idx} triggered automatic halt.\n"
                f"Anomalies: {anomalies}\n"
                f"Protect your agent execution pipeline."
            )

        return commitment

    def verify_chain(self) -> bool:
        """
        Replay the entire commitment chain to verify no step was tampered.
        Returns True if chain is intact.
        """
        replay_chain = "GENESIS"
        for step in self._steps:
            step_hash  = self._hash_step(step.step_content)
            chain_hash = hmac.new(
                self._secret,
                (replay_chain + step_hash).encode(),
                hashlib.sha256
            ).hexdigest()
            if chain_hash != step.chain_hash:
                return False
            replay_chain = chain_hash
        return True

    def get_report(self) -> IntegrityReport:
        """Generate full integrity report for the session."""
        chain_ok    = self.verify_chain()
        max_threat  = ThreatLevel.CLEAN
        compromised = False

        for s in self._steps:
            max_threat = self._escalate(max_threat, s.threat_level)
            if s.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HALT):
                compromised = True

        if not chain_ok:
            max_threat  = ThreatLevel.HALT
            compromised = True

        summary_parts = [
            f"Session {self.session_id}: {len(self._steps)} steps analysed.",
            f"Chain integrity: {'VALID' if chain_ok else 'COMPROMISED'}.",
            f"Overall threat: {max_threat.value}.",
        ]
        if compromised:
            summary_parts.append("Agent goal integrity CANNOT be guaranteed.")
        else:
            summary_parts.append("Agent operated within expected goal boundaries.")

        return IntegrityReport(
            session_id    = self.session_id,
            original_goal = self.original_goal,
            total_steps   = len(self._steps),
            compromised   = compromised,
            chain_valid   = chain_ok,
            threat_level  = max_threat,
            steps         = [s.to_dict() for s in self._steps],
            summary       = " ".join(summary_parts),
        )

    # ── Internal helpers ────────────────────────────────────────────────

    def _hash_step(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()

    def _extend_chain(self, step_hash: str) -> str:
        return hmac.new(
            self._secret,
            (self._chain_hash + step_hash).encode(),
            hashlib.sha256
        ).hexdigest()

    def _update_chain_state(self, new_chain_hash: str):
        self._chain_hash = new_chain_hash

    def _scan_patterns(self, content: str):
        found_threats  = []
        found_anomalies = []
        for pattern, level in COMPILED_PATTERNS:
            match = pattern.search(content)
            if match:
                found_threats.append(level)
                found_anomalies.append(
                    f"Pattern match [{level}]: '{match.group(0)[:60]}'"
                )
        if not found_threats:
            return ThreatLevel.CLEAN, []
        if "CRITICAL" in found_threats:
            return ThreatLevel.CRITICAL, found_anomalies
        return ThreatLevel.WARN, found_anomalies

    def _semantic_check(self, content: str):
        if not SEMANTIC_AVAILABLE or self._goal_embedding is None:
            return 0.5, ThreatLevel.CLEAN, None  # neutral if no engine

        step_emb = _MODEL.encode(content, convert_to_tensor=True)
        score    = float(st_util.cos_sim(self._goal_embedding, step_emb)[0][0])

        if score < self.SEMANTIC_HALT_THRESHOLD:
            return score, ThreatLevel.HALT, \
                f"Semantic drift CRITICAL: similarity={score:.3f} (goal abandoned)"
        if score < self.SEMANTIC_WARN_THRESHOLD:
            return score, ThreatLevel.WARN, \
                f"Semantic drift WARNING: similarity={score:.3f} (goal deviation)"
        return score, ThreatLevel.CLEAN, None

    def _keyword_consistency(self, content: str):
        """
        Lightweight goal consistency check — extracts nouns/verbs from
        original goal and checks presence. Fallback when semantic engine
        is unavailable. Not a replacement for embedding-based checks.
        """
        stopwords = {
            "the","a","an","and","or","to","in","of","for","on",
            "with","is","are","was","were","be","been","being",
            "it","its","this","that","at","by","from","as","into"
        }
        goal_tokens = {
            w.lower() for w in re.findall(r'\b[a-zA-Z]{4,}\b', self.original_goal)
            if w.lower() not in stopwords
        }
        if not goal_tokens:
            return ThreatLevel.CLEAN, None

        content_lower = content.lower()
        overlap = sum(1 for t in goal_tokens if t in content_lower)
        ratio   = overlap / len(goal_tokens)

        if ratio < 0.1 and len(self._steps) > 2:
            return ThreatLevel.WARN, \
                f"Goal keyword overlap low: {ratio:.0%} of goal terms present"
        return ThreatLevel.CLEAN, None

    @staticmethod
    def _escalate(current: ThreatLevel, new: ThreatLevel) -> ThreatLevel:
        order = [ThreatLevel.CLEAN, ThreatLevel.WARN,
                 ThreatLevel.CRITICAL, ThreatLevel.HALT]
        return new if order.index(new) > order.index(current) else current

    def _log(self, msg: str):
        print(f"[AgentGuard] {msg}")

    def _print_step(self, s: StepCommitment):
        icon = {"CLEAN": "✓", "WARN": "⚠", "CRITICAL": "✗", "HALT": "⛔"}
        level = s.threat_level.value
        print(f"  Step {s.step_index:02d} [{icon.get(level,'?')} {level:8s}]"
              f"  sem={s.semantic_score:.3f}"
              f"  hash={s.step_hash[:12]}..."
              f"  chain={s.chain_hash[:12]}...")
        for a in s.anomalies:
            print(f"           >> {a}")
      
