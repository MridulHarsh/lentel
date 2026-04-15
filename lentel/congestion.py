"""
Lentel's BBR-lite congestion controller.

See PROTOCOL.md §7 for background. The controller is deliberately loss-
tolerant: drops do not halve the sending rate. It maintains a windowed max
of observed delivery rate and a windowed min of observed RTT, and cycles
through four phases (STARTUP, DRAIN, PROBE_BW, PROBE_RTT) to continuously
re-estimate the bottleneck bandwidth and propagation delay.

Inputs per ACK:
    acked_bytes : bytes cumulative-acked since last call
    rtt         : most recent round-trip sample (seconds)

Outputs:
    pacing_rate : bytes/sec — how fast the sender should pace out bytes
    cwnd        : bytes     — how many unacked bytes may be in flight
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum

MSS = 1200
INITIAL_CWND = 10 * MSS
MIN_CWND = 4 * MSS

STARTUP_GAIN = 2.89
DRAIN_GAIN = 1.0 / 2.89
PROBE_BW_GAINS = (1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0)

WINDOW_SECONDS = 10.0
PROBE_RTT_INTERVAL = 10.0
PROBE_RTT_DURATION = 0.2

FULL_BW_THRESHOLD = 1.25
FULL_BW_STABLE_ROUNDS = 3


class Phase(Enum):
    STARTUP = 1
    DRAIN = 2
    PROBE_BW = 3
    PROBE_RTT = 4


class _WindowedExtreme:
    """Sliding-window extreme (max or min) over timestamped samples."""

    def __init__(self, window: float, maximize: bool):
        self.window = window
        self.maximize = maximize
        self.samples: deque[tuple[float, float]] = deque()

    def add(self, ts: float, value: float) -> None:
        while self.samples and (
            (self.maximize and self.samples[-1][1] <= value)
            or (not self.maximize and self.samples[-1][1] >= value)
        ):
            self.samples.pop()
        self.samples.append((ts, value))
        self._trim(ts)

    def _trim(self, now: float) -> None:
        while self.samples and now - self.samples[0][0] > self.window:
            self.samples.popleft()

    def peek(self, now: float) -> float | None:
        self._trim(now)
        return self.samples[0][1] if self.samples else None


@dataclass
class BBRLite:
    phase: Phase = Phase.STARTUP
    pacing_rate: float = 1_000_000.0  # bytes/sec
    cwnd: int = INITIAL_CWND
    _max_bw: _WindowedExtreme = field(
        default_factory=lambda: _WindowedExtreme(WINDOW_SECONDS, maximize=True),
    )
    _min_rtt: _WindowedExtreme = field(
        default_factory=lambda: _WindowedExtreme(WINDOW_SECONDS, maximize=False),
    )
    _gain_index: int = 0
    _cycle_started: float = field(default_factory=time.monotonic)
    _last_probe_rtt: float = field(default_factory=time.monotonic)
    _probe_rtt_end: float = 0.0
    _full_bw: float = 0.0
    _full_bw_count: int = 0

    def on_ack(self, acked_bytes: int, rtt: float, now: float | None = None) -> None:
        now = now if now is not None else time.monotonic()

        if rtt > 0 and acked_bytes > 0:
            self._min_rtt.add(now, rtt)
            # Approximate delivery rate by dividing acked bytes by the RTT of
            # this sample. With many samples per RTT the windowed max captures
            # the true bottleneck rate.
            self._max_bw.add(now, acked_bytes / rtt)

        max_bw = self._max_bw.peek(now) or 0.0
        min_rtt = self._min_rtt.peek(now) or 0.0

        self._transition(now, max_bw, min_rtt)
        self._recompute(max_bw, min_rtt)

    def _transition(self, now: float, max_bw: float, min_rtt: float) -> None:
        if self.phase is Phase.STARTUP:
            if max_bw >= self._full_bw * FULL_BW_THRESHOLD and max_bw > 0:
                self._full_bw = max_bw
                self._full_bw_count = 0
            else:
                self._full_bw_count += 1
                if self._full_bw_count >= FULL_BW_STABLE_ROUNDS:
                    self.phase = Phase.DRAIN
        elif self.phase is Phase.DRAIN:
            bdp = max_bw * min_rtt if min_rtt > 0 else 0
            if bdp > 0 and self.cwnd <= bdp:
                self.phase = Phase.PROBE_BW
                self._cycle_started = now
                self._gain_index = 0
        elif self.phase is Phase.PROBE_BW:
            if min_rtt > 0 and now - self._cycle_started >= min_rtt:
                self._gain_index = (self._gain_index + 1) % len(PROBE_BW_GAINS)
                self._cycle_started = now
            if now - self._last_probe_rtt > PROBE_RTT_INTERVAL:
                self.phase = Phase.PROBE_RTT
                self._probe_rtt_end = now + PROBE_RTT_DURATION
                self._last_probe_rtt = now
        elif self.phase is Phase.PROBE_RTT:
            if now >= self._probe_rtt_end:
                self.phase = Phase.PROBE_BW
                self._cycle_started = now

    def _recompute(self, max_bw: float, min_rtt: float) -> None:
        if self.phase is Phase.STARTUP:
            gain = STARTUP_GAIN
        elif self.phase is Phase.DRAIN:
            gain = DRAIN_GAIN
        elif self.phase is Phase.PROBE_BW:
            gain = PROBE_BW_GAINS[self._gain_index]
        else:
            gain = 1.0

        if max_bw > 0:
            self.pacing_rate = max(max_bw * gain, 50_000.0)

        if max_bw > 0 and min_rtt > 0:
            bdp = max_bw * min_rtt
            cwnd_gain = 2.89 if self.phase is Phase.STARTUP else 2.0
            self.cwnd = max(MIN_CWND, int(bdp * cwnd_gain))

        if self.phase is Phase.PROBE_RTT:
            self.cwnd = MIN_CWND

    # ------ observability --------------------------------------------------

    def snapshot(self) -> dict:
        now = time.monotonic()
        return {
            "phase": self.phase.name,
            "pacing_rate_bps": int(self.pacing_rate),
            "cwnd_bytes": self.cwnd,
            "max_bw_bps": int(self._max_bw.peek(now) or 0),
            "min_rtt_ms": int((self._min_rtt.peek(now) or 0) * 1000),
        }
