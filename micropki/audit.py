from __future__ import annotations

import json
import hashlib
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import logging

# Глобальный лок для потокобезопасной записи
_audit_lock = threading.Lock()
_audit_logger = None


class AuditLogger:
    """Аудитный логгер с хэш-цепочкой integrity"""

    def __init__(self, log_dir: Path, logger: logging.Logger):
        self.log_dir = Path(log_dir)
        self.log_file = self.log_dir / "audit.log"
        self.chain_file = self.log_dir / "chain.dat"
        self.logger = logger
        self._ensure_directory()
        self._init_chain()

    def _ensure_directory(self):
        """Создаёт директорию для логов"""
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _init_chain(self):
        """Инициализирует chain.dat если он не существует"""
        if not self.chain_file.exists():
            # Начальное значение для первого лога
            self.chain_file.write_text("0" * 64)

    def _get_last_hash(self) -> str:
        """Получает последний хэш из chain.dat"""
        return self.chain_file.read_text().strip()

    def _update_last_hash(self, new_hash: str):
        """Обновляет последний хэш в chain.dat"""
        self.chain_file.write_text(new_hash)

    def _calculate_hash(self, entry_dict: Dict[str, Any], prev_hash: str) -> str:
        """
        Вычисляет SHA-256 хэш для записи (исключая поле integrity.hash)
        """
        # Создаём копию для вычисления хэша
        entry_copy = entry_dict.copy()

        # Убираем integrity.hash если он есть
        if "integrity" in entry_copy and "hash" in entry_copy["integrity"]:
            del entry_copy["integrity"]["hash"]

        # Сортируем ключи для детерминированного JSON
        json_str = json.dumps(entry_copy, sort_keys=True, separators=(',', ':'))

        # Вычисляем хэш
        return hashlib.sha256(json_str.encode()).hexdigest()

    def log(self, level: str, operation: str, status: str, message: str,
            metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Добавляет запись в аудит лог
        """
        with _audit_lock:
            # Получаем предыдущий хэш
            prev_hash = self._get_last_hash()

            # Создаём запись
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(timespec='microseconds'),
                "level": level.upper(),
                "operation": operation,
                "status": status,
                "message": message,
                "metadata": metadata or {},
                "integrity": {
                    "prev_hash": prev_hash,
                    "hash": ""  # Временное значение
                }
            }

            # Вычисляем хэш
            current_hash = self._calculate_hash(entry, prev_hash)
            entry["integrity"]["hash"] = current_hash

            # Записываем в файл
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())

            # Обновляем chain.dat
            self._update_last_hash(current_hash)

            # Также пишем в обычный лог
            self.logger.info(f"AUDIT: {operation} [{status}] - {message}")

    def verify_integrity(self) -> tuple[bool, Optional[int], Optional[str]]:
        """
        Проверяет целостность всего аудит лога.
        Возвращает (is_valid, first_corrupted_line, error_message)
        """
        if not self.log_file.exists():
            return True, None, None

        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        prev_hash = "0" * 64
        line_num = 0

        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)

                # Проверяем prev_hash
                if entry.get("integrity", {}).get("prev_hash") != prev_hash:
                    return False, i, f"Invalid prev_hash at line {i}"

                # Вычисляем хэш
                stored_hash = entry.get("integrity", {}).get("hash")
                if not stored_hash:
                    return False, i, f"Missing hash at line {i}"

                computed_hash = self._calculate_hash(entry, prev_hash)

                if computed_hash != stored_hash:
                    return False, i, f"Hash mismatch at line {i}"

                prev_hash = stored_hash
                line_num = i

            except json.JSONDecodeError as e:
                return False, i, f"Invalid JSON at line {i}: {e}"

        # Проверяем с chain.dat
        stored_last_hash = self._get_last_hash()
        if stored_last_hash != prev_hash:
            return False, line_num + 1, f"Chain file mismatch: expected {prev_hash}, got {stored_last_hash}"

        return True, None, None

    def query_logs(self, from_time: Optional[str] = None, to_time: Optional[str] = None,
                   level: Optional[str] = None, operation: Optional[str] = None,
                   serial: Optional[str] = None) -> list[Dict[str, Any]]:
        """
        Запрашивает логи с фильтрацией
        """
        if not self.log_file.exists():
            return []

        results = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)

                    # Фильтр по времени
                    if from_time:
                        if entry["timestamp"] < from_time:
                            continue
                    if to_time:
                        if entry["timestamp"] > to_time:
                            continue

                    # Фильтр по уровню
                    if level and entry["level"].upper() != level.upper():
                        continue

                    # Фильтр по операции
                    if operation and entry["operation"] != operation:
                        continue

                    # Фильтр по серийному номеру
                    if serial:
                        metadata_serial = entry.get("metadata", {}).get("serial", "")
                        if serial.upper() != metadata_serial.upper():
                            continue

                    results.append(entry)

                except json.JSONDecodeError:
                    continue

        return results


# Глобальный экземпляр
_audit_instance: Optional[AuditLogger] = None


def init_audit_logger(log_dir: Path, logger: logging.Logger) -> AuditLogger:
    """Инициализирует глобальный аудит логгер"""
    global _audit_instance
    _audit_instance = AuditLogger(log_dir, logger)
    return _audit_instance


def get_audit_logger() -> AuditLogger:
    """Возвращает глобальный аудит логгер"""
    global _audit_instance
    if _audit_instance is None:
        raise RuntimeError("Audit logger not initialized")
    return _audit_instance


def audit_log(level: str, operation: str, status: str, message: str,
              metadata: Optional[Dict[str, Any]] = None) -> None:
    """Упрощённая функция для записи аудит логов"""
    logger = get_audit_logger()
    logger.log(level, operation, status, message, metadata)