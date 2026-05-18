from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import threading


class CTLog:
    """Certificate Transparency симуляция (append-only log)"""

    def __init__(self, log_dir: Path):
        self.log_file = log_dir / "ct.log"
        self.lock = threading.Lock()
        self._ensure_file()

    def _ensure_file(self):
        """Создаёт файл если не существует"""
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_file.exists():
            self.log_file.touch()
            try:
                self.log_file.chmod(0o644)
            except Exception:
                pass

    def add_entry(self, serial: str, subject: str, cert_pem: str, issuer: Optional[str] = None) -> None:
        """
        Добавляет запись в CT лог
        """
        # Вычисляем SHA-256 fingerprint
        fingerprint = hashlib.sha256(cert_pem.encode()).hexdigest()

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec='microseconds'),
            "serial": serial.upper(),
            "subject": subject,
            "fingerprint": fingerprint,
            "issuer": issuer or ""
        }

        with self.lock:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(
                    f"{entry['timestamp']} | {entry['serial']} | {entry['subject']} | {entry['fingerprint']} | {entry['issuer']}\n")
                f.flush()

    def verify_inclusion(self, serial: str) -> bool:
        """
        Проверяет, содержится ли сертификат в логе
        """
        if not self.log_file.exists():
            return False

        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                if serial.upper() in line:
                    return True
        return False

    def get_all_entries(self) -> list[str]:
        """Возвращает все записи"""
        if not self.log_file.exists():
            return []

        with open(self.log_file, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]