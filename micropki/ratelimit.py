from __future__ import annotations

import time
import threading
from collections import defaultdict
from typing import Dict, Tuple


class TokenBucket:
    """Реализация token bucket для rate limiting"""

    def __init__(self, rate: float, burst: int):
        """
        rate: запросов в секунду
        burst: максимальный размер burst
        """
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        """
        Потребляет токены. Возвращает True если успешно, False если превышен лимит
        """
        with self.lock:
            now = time.time()
            # Пополняем токены
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def get_retry_after(self) -> int:
        """Возвращает количество секунд до пополнения"""
        with self.lock:
            if self.tokens >= 1:
                return 0
            # Время до следующего токена
            return int((1 - self.tokens) / self.rate) + 1


class RateLimiter:
    """Глобальный rate limiter с поддержкой per-IP"""

    def __init__(self, rate_limit: float, burst: int):
        """
        rate_limit: 0 - отключён, >0 - запросов в секунду
        burst: максимальный размер burst
        """
        self.rate_limit = rate_limit
        self.burst = burst
        self.buckets: Dict[str, TokenBucket] = {}
        self.lock = threading.Lock()
        self.enabled = rate_limit > 0

    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        """
        Проверяет, разрешён ли запрос от клиента
        Возвращает (allowed, retry_after_seconds)
        """
        if not self.enabled:
            return True, 0

        with self.lock:
            if client_ip not in self.buckets:
                self.buckets[client_ip] = TokenBucket(self.rate_limit, self.burst)

            bucket = self.buckets[client_ip]
            allowed = bucket.consume()
            retry_after = bucket.get_retry_after() if not allowed else 0

            return allowed, retry_after

    def cleanup(self, max_age_seconds: int = 3600):
        """Очищает старые bucket'ы"""
        if not self.enabled:
            return

        with self.lock:
            now = time.time()
            to_delete = []
            for ip, bucket in self.buckets.items():
                if hasattr(bucket, 'last_refill'):
                    if now - bucket.last_refill > max_age_seconds:
                        to_delete.append(ip)

            for ip in to_delete:
                del self.buckets[ip]