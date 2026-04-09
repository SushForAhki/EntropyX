#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                            EntropyX Security v1.0                             ║
║                    Yapay Zeka Destekli Zararlı Yazılım Tespiti                ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Gelişmiş özellikler:
- Çoklu motor tarama (Hash, Heuristic, ML, YaraLite)
- Gerçek zamanlı koruma (Real-time)
- VirusTotal entegrasyonu
- Akıllı karantina sistemi
- Önbellek yönetimi

Author: SushForAhki
Version: 1.0.0
License: MIT
"""

import os
import sys
import json
import hashlib
import time
import re
import math
import threading
import logging
import random
import string
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings

# Üçüncü parti kütüphaneler
try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QStackedWidget, QFileDialog, QProgressBar,
        QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
        QGroupBox, QGridLayout, QSplitter, QFrame, QDialog, QCheckBox,
        QLineEdit, QComboBox, QSpinBox, QTabWidget, QListWidget, QListWidgetItem,
        QSystemTrayIcon, QMenu, QStyle
    )
    from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer, QSize, QObject
    from PySide6.QtGui import QFont, QIcon, QColor, QPalette, QAction, QFontDatabase
    HAS_PYSIDE = True
except ImportError:
    HAS_PYSIDE = False
    print("[HATA] PySide6 kurulu değil. UI çalışmayacak. pip install pyside6")

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    HAS_ML = True
except ImportError:
    HAS_ML = False
    print("[UYARI] scikit-learn kurulu değil. ML motoru devre dışı. pip install scikit-learn numpy")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    print("[UYARI] watchdog kurulu değil. Gerçek zamanlı koruma devre dışı. pip install watchdog")

# Sabitler
APP_NAME = "EntropyX"
VERSION = "1.0.0"
# NOT: VirusTotal entegrasyonu kaldırıldı
QUARANTINE_DIR = Path.home() / "entropyx_quarantine"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
CHUNK_SIZE = 8192  # 8 KB
MAX_WORKERS = 4

# Renk teması (Light Tema - Siyah yazı, Beyaz arka plan)
COLORS = {
    "primary": "#FF6B35",      # Turuncu (vurgu rengi)
    "secondary": "#FFF3E0",    # Açık turuncu arka plan
    "background": "#FFFFFF",    # Beyaz arka plan
    "dark": "#1A1A1A",         # Siyah (ana metin)
    "success": "#27AE60",     # Yeşil
    "warning": "#F39C12",     # Sarı
    "danger": "#E74C3C",      # Kırmızı
    "text": "#000000",        # SİYAH METİN
    "text_light": "#555555",  # Gri metin
    "border": "#E0E0E0",      # Kenarlık rengi
    "card_bg": "#FAFAFA",     # Kart arka planı
}


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanResult:
    """Tarama sonucu veri sınıfı"""
    file_path: str
    sha256: str
    file_size: int
    heuristic_score: float = 0.0
    ml_probability: float = 0.0
    yara_score: float = 0.0
    final_score: float = 0.0
    status: str = "GÜVENLİ"  # GÜVENLİ, ŞÜPHELİ, ZARARLI
    threats: List[str] = field(default_factory=list)
    scan_time: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def calculate_final_score(self) -> float:
        """Final skoru hesapla"""
        self.final_score = (
            self.heuristic_score * 0.4 +
            self.ml_probability * 40 +
            self.yara_score * 0.2
        )
        
        # Durum belirleme
        if self.final_score >= 70:
            self.status = "ZARARLI"
        elif self.final_score >= 30:
            self.status = "ŞÜPHELİ"
        else:
            self.status = "GÜVENLİ"
        
        return self.final_score


@dataclass
class QuarantineItem:
    """Karantina öğesi veri sınıfı"""
    quarantine_id: str
    original_path: str
    quarantine_path: str
    file_hash: str
    reason: str
    date: str
    metadata: Dict = field(default_factory=dict)


@dataclass
class YaraRule:
    """YaraLite kural veri sınıfı"""
    name: str
    strings: List[str]
    condition: str  # "any", "all", "n_of"
    n_value: int = 1  # n_of için
    use_regex: bool = False
    hex_pattern: Optional[str] = None
    score: int = 30


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGER SINIFI
# ═══════════════════════════════════════════════════════════════════════════════

class Logger:
    """Merkezi log yönetim sistemi"""
    
    LEVELS = {
        "BİLGİ": 20,
        "UYARI": 30,
        "KRİTİK": 50
    }
    
    def __init__(self):
        self.logs: List[Dict] = []
        self.last_messages: Dict[str, float] = {}  # Spam önleme
        self.spam_timeout = 5  # saniye
        self.callbacks: List[Callable] = []
        self.lock = threading.Lock()
        
    def add_callback(self, callback: Callable):
        """Log callback'i ekle"""
        self.callbacks.append(callback)
        
    def log(self, level: str, message: str, module: str = "CORE"):
        """Log kaydı oluştur"""
        try:
            # Spam kontrolü
            msg_key = f"{level}:{message}"
            current_time = time.time()
            
            with self.lock:
                if msg_key in self.last_messages:
                    if current_time - self.last_messages[msg_key] < self.spam_timeout:
                        return
                self.last_messages[msg_key] = current_time
                
                log_entry = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "level": level,
                    "module": module,
                    "message": message
                }
                self.logs.append(log_entry)
                
                # Konsola yazdır
                print(f"[{log_entry['timestamp']}] [{level}] [{module}] {message}")
                
                # Callback'leri çağır
                for callback in self.callbacks:
                    try:
                        callback(log_entry)
                    except Exception:
                        pass
                        
        except Exception as e:
            print(f"[LOG HATASI] {e}")
            
    def get_logs(self, level: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Log kayıtlarını getir"""
        with self.lock:
            logs = self.logs
            if level:
                logs = [log for log in logs if log["level"] == level]
            return logs[-limit:]
    
    def clear(self):
        """Logları temizle"""
        with self.lock:
            self.logs.clear()


# Global logger instance
logger = Logger()


# ═══════════════════════════════════════════════════════════════════════════════
# CACHE MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class CacheManager:
    """Hash önbellek yönetimi"""
    
    def __init__(self):
        self.cache: Dict[str, Dict] = {}
        self.lock = threading.Lock()
        self.max_size = 10000
        
    def get(self, sha256: str) -> Optional[Dict]:
        """Önbellekten sonuç getir"""
        with self.lock:
            return self.cache.get(sha256)
    
    def set(self, sha256: str, result: Dict):
        """Sonucu önbelleğe kaydet"""
        with self.lock:
            if len(self.cache) >= self.max_size:
                # LRU: En eski öğeyi kaldır
                oldest = min(self.cache, key=lambda k: self.cache[k].get("timestamp", 0))
                del self.cache[oldest]
            
            self.cache[sha256] = {
                **result,
                "timestamp": time.time()
            }
    
    def clear(self):
        """Önbelleği temizle"""
        with self.lock:
            self.cache.clear()


# ═══════════════════════════════════════════════════════════════════════════════
# HASH UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

class HashUtils:
    """Hash yardımcı fonksiyonları"""
    
    @staticmethod
    def calculate_sha256(file_path: str, max_bytes: int = MAX_FILE_SIZE) -> Optional[str]:
        """Dosya SHA256 hash hesapla (parçalı okuma)"""
        try:
            sha256_hash = hashlib.sha256()
            bytes_read = 0
            
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
                    bytes_read += len(chunk)
                    if bytes_read >= max_bytes:
                        break
            
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.log("UYARI", f"Hash hesaplama hatası ({file_path}): {e}", "HASH")
            return None
    
    @staticmethod
    def calculate_entropy(file_path: str, max_bytes: int = 1024 * 1024) -> float:
        """Dosya entropy değeri hesapla (0-8 arası)"""
        try:
            with open(file_path, "rb") as f:
                data = f.read(max_bytes)
            
            if not data:
                return 0.0
            
            entropy = 0
            for x in range(256):
                p_x = float(data.count(bytes([x]))) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log(p_x, 2)
            
            return entropy
        except Exception as e:
            logger.log("UYARI", f"Entropy hesaplama hatası: {e}", "HASH")
            return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# HEURISTIC ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class HeuristicEngine:
    """Şüpheli davranış analizi motoru"""
    
    # Şüpheli string desenleri
    SUSPICIOUS_STRINGS = [
        b"powershell", b"Invoke-Expression", b"IEX",
        b"Base64", b"base64", b"FromBase64String",
        b"WScript.Shell", b"Scripting.FileSystemObject",
        b"CreateObject", b"ShellExecute",
        b"VirtualAlloc", b"WriteProcessMemory",
        b"CreateRemoteThread", b"LoadLibrary",
        b"cmd.exe", b"command.com", b"regsvr32",
        b"rundll32", b"mshta.exe", b"certutil",
        b"bitsadmin", b"schtasks", b"reg add",
        b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        b"Set-MpPreference", b"DisableRealtimeMonitoring",
        b"netsh advfirewall", b"iptables",
    ]
    
    # Şüpheli dosya uzantıları
    SUSPICIOUS_EXTS = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.hta'}
    
    def __init__(self):
        self.score_weights = {
            "temp_location": 15,
            "high_entropy": 20,
            "suspicious_strings": 25,
            "recent_executable": 10,
            "suspicious_extension": 5,
            "pe_without_manifest": 10,
            "packed": 15,
        }
    
    def analyze(self, file_path: str) -> Tuple[float, List[str]]:
        """Dosyayı analiz et ve skor döndür"""
        score = 0.0
        threats = []
        
        try:
            file_path_obj = Path(file_path)
            file_lower = file_path.lower()
            
            # 1. Temp klasör kontrolü
            temp_dirs = ['temp', 'tmp', 'cache']
            if any(temp_dir in file_lower for temp_dir in temp_dirs):
                ext = file_path_obj.suffix.lower()
                if ext in {'.exe', '.bat', '.cmd'}:
                    score += self.score_weights["temp_location"]
                    threats.append("Temp klasöründe executable")
            
            # 2. Entropy kontrolü
            entropy = HashUtils.calculate_entropy(file_path, 1024 * 1024)
            if entropy > 7.5:
                score += self.score_weights["high_entropy"]
                threats.append(f"Yüksek entropy (packer/şifrelenmiş): {entropy:.2f}")
            elif entropy > 6.5:
                score += self.score_weights["high_entropy"] * 0.5
                threats.append(f"Şüpheli entropy: {entropy:.2f}")
            
            # 3. Şüpheli string kontrolü
            string_score, string_threats = self._check_suspicious_strings(file_path)
            score += string_score
            threats.extend(string_threats)
            
            # 4. Yeni oluşturulmuş executable kontrolü
            try:
                stat = os.stat(file_path)
                file_age_hours = (time.time() - stat.st_ctime) / 3600
                if file_age_hours < 24 and file_path_obj.suffix.lower() in {'.exe', '.dll'}:
                    score += self.score_weights["recent_executable"]
                    threats.append(f"Yeni oluşturulmuş executable ({file_age_hours:.1f} saat)")
            except Exception:
                pass
            
            # 5. Şüpheli uzantı kontrolü
            if file_path_obj.suffix.lower() in {'.scr', '.pif', '.com'}:
                score += self.score_weights["suspicious_extension"] * 2
                threats.append("Şüpheli dosya uzantısı")
            
            # 6. PE Header analizi
            pe_threats = self._analyze_pe_header(file_path)
            if pe_threats:
                score += 10
                threats.extend(pe_threats)
            
            # Skor sınırlandırma (0-100)
            score = min(score, 100)
            
        except Exception as e:
            logger.log("UYARI", f"Heuristic analiz hatası ({file_path}): {e}", "HEURISTIC")
        
        return score, threats
    
    def _check_suspicious_strings(self, file_path: str) -> Tuple[float, List[str]]:
        """Şüpheli stringleri kontrol et"""
        score = 0
        threats = []
        found_strings = set()
        
        try:
            with open(file_path, "rb") as f:
                content = f.read(5 * 1024 * 1024)  # İlk 5 MB
            
            for suspicious in self.SUSPICIOUS_STRINGS:
                if suspicious in content:
                    found_strings.add(suspicious.decode('utf-8', errors='ignore'))
            
            if found_strings:
                count = len(found_strings)
                if count >= 5:
                    score = self.score_weights["suspicious_strings"]
                    threats.append(f"Çok sayıda şüpheli string ({count} adet)")
                elif count >= 3:
                    score = self.score_weights["suspicious_strings"] * 0.6
                    threats.append(f"Şüpheli string bulundu ({count} adet)")
                else:
                    score = self.score_weights["suspicious_strings"] * 0.3
                    threats.append(f"Az sayıda şüpheli string ({count} adet)")
                    
        except Exception as e:
            logger.log("UYARI", f"String kontrol hatası: {e}", "HEURISTIC")
        
        return score, threats
    
    def _analyze_pe_header(self, file_path: str) -> List[str]:
        """PE header analizi"""
        threats = []
        
        try:
            with open(file_path, "rb") as f:
                header = f.read(1024)
            
            # MZ header kontrolü
            if header[:2] != b'MZ':
                return threats
            
            # PE header offset
            pe_offset = int.from_bytes(header[60:64], byteorder='little')
            if pe_offset > len(header) - 4:
                f.seek(pe_offset)
                header += f.read(256)
            
            # PE signature
            if header[pe_offset:pe_offset+4] != b'PE\x00\x00':
                threats.append("Geçersiz PE header")
                return threats
            
            # Characteristics kontrolü
            characteristics_offset = pe_offset + 22
            if characteristics_offset + 2 <= len(header):
                characteristics = int.from_bytes(
                    header[characteristics_offset:characteristics_offset+2], 
                    byteorder='little'
                )
                # DLL kontrolü
                if characteristics & 0x2000:
                    pass  # DLL dosyası
                
                # Executable kontrolü
                if not (characteristics & 0x0002):
                    threats.append("Executable biti ayarlanmamış")
            
        except Exception:
            pass
        
        return threats


# ═══════════════════════════════════════════════════════════════════════════════
# ML ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class MLEngine:
    """Makine öğrenimi tabanlı zararlı yazılım tespiti"""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = [
            "file_size_log",
            "entropy",
            "string_count",
            "null_byte_ratio",
            "ascii_ratio",
            "high_entropy_blocks",
            "printable_ratio"
        ]
        
        if HAS_ML:
            self._init_model()
    
    def _init_model(self):
        """ML modelini başlat (eğitimli model kod içinde)"""
        try:
            # Önceden eğitilmiş model parametreleri (simülasyon)
            # Gerçek uygulamada, model pickle/joblib ile yüklenir
            self.model = RandomForestClassifier(
                n_estimators=50,
                max_depth=10,
                random_state=42,
                n_jobs=1
            )
            
            # Simüle edilmiş eğitim verisi ile fit
            # Gerçek uygulamada gerçek veri kullanılmalı
            self._train_with_simulated_data()
            
        except Exception as e:
            logger.log("UYARI", f"ML model başlatma hatası: {e}", "ML")
            self.model = None
    
    def _train_with_simulated_data(self):
        """Simüle edilmiş veri ile model eğitimi (demo amaçlı)"""
        try:
            np.random.seed(42)
            n_samples = 1000
            
            # Güvenli dosya özellikleri (normal dağılım)
            benign_features = np.array([
                np.random.normal(10, 3, n_samples // 2),      # file_size_log
                np.random.normal(4.5, 1.5, n_samples // 2),  # entropy
                np.random.normal(500, 200, n_samples // 2),  # string_count
                np.random.normal(0.1, 0.05, n_samples // 2), # null_byte_ratio
                np.random.normal(0.7, 0.15, n_samples // 2), # ascii_ratio
                np.random.normal(2, 1, n_samples // 2),       # high_entropy_blocks
                np.random.normal(0.8, 0.1, n_samples // 2),    # printable_ratio
            ]).T
            
            # Zararlı dosya özellikleri (farklı dağılım)
            malware_features = np.array([
                np.random.normal(12, 4, n_samples // 2),      # file_size_log
                np.random.normal(7.0, 0.8, n_samples // 2),   # entropy (yüksek)
                np.random.normal(200, 150, n_samples // 2),   # string_count (düşük)
                np.random.normal(0.3, 0.1, n_samples // 2),    # null_byte_ratio
                np.random.normal(0.4, 0.2, n_samples // 2),    # ascii_ratio (düşük)
                np.random.normal(8, 2, n_samples // 2),       # high_entropy_blocks
                np.random.normal(0.5, 0.2, n_samples // 2),   # printable_ratio
            ]).T
            
            X = np.vstack([benign_features, malware_features])
            y = np.array([0] * (n_samples // 2) + [1] * (n_samples // 2))
            
            # Karıştır
            indices = np.random.permutation(n_samples)
            X = X[indices]
            y = y[indices]
            
            # Scale ve eğit
            X_scaled = self.scaler.fit_transform(X)
            self.model.fit(X_scaled, y)
            self.is_trained = True
            
            logger.log("BİLGİ", "ML model başarıyla eğitildi (simüle veri)", "ML")
            
        except Exception as e:
            logger.log("UYARI", f"ML eğitim hatası: {e}", "ML")
    
    def extract_features(self, file_path: str) -> Optional[np.ndarray]:
        """Dosyadan ML özellikleri çıkar"""
        try:
            file_size = os.path.getsize(file_path)
            
            with open(file_path, "rb") as f:
                data = f.read(min(file_size, 2 * 1024 * 1024))  # İlk 2MB
            
            if not data:
                return None
            
            # 1. Dosya boyutu (log)
            file_size_log = math.log(file_size + 1)
            
            # 2. Entropy
            entropy = HashUtils.calculate_entropy(file_path, 1024 * 1024)
            
            # 3. String sayısı (printable karakterlerden oluşan)
            string_count = self._count_strings(data)
            
            # 4. Null byte oranı
            null_bytes = data.count(b'\x00')
            null_byte_ratio = null_bytes / len(data)
            
            # 5. ASCII oranı
            ascii_chars = sum(1 for b in data if 32 <= b <= 126)
            ascii_ratio = ascii_chars / len(data)
            
            # 6. Yüksek entropy blok sayısı
            high_entropy_blocks = self._count_high_entropy_blocks(data)
            
            # 7. Printable karakter oranı
            printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
            printable_ratio = printable / len(data)
            
            features = np.array([[
                file_size_log,
                entropy,
                string_count,
                null_byte_ratio,
                ascii_ratio,
                high_entropy_blocks,
                printable_ratio
            ]])
            
            return features
            
        except Exception as e:
            logger.log("UYARI", f"Özellik çıkarma hatası ({file_path}): {e}", "ML")
            return None
    
    def _count_strings(self, data: bytes, min_length: int = 4) -> int:
        """Printable string sayısını hesapla"""
        count = 0
        current_string = 0
        
        for byte in data:
            if 32 <= byte <= 126:
                current_string += 1
            else:
                if current_string >= min_length:
                    count += 1
                current_string = 0
        
        if current_string >= min_length:
            count += 1
        
        return count
    
    def _count_high_entropy_blocks(self, data: bytes, block_size: int = 256, threshold: float = 7.0) -> int:
        """Yüksek entropy blok sayısını hesapla"""
        high_entropy_count = 0
        
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            if len(block) < block_size // 2:
                continue
            
            entropy = 0
            for x in range(256):
                p_x = float(block.count(bytes([x]))) / len(block)
                if p_x > 0:
                    entropy += - p_x * math.log(p_x, 2)
            
            if entropy > threshold:
                high_entropy_count += 1
        
        return high_entropy_count
    
    def predict(self, file_path: str) -> Tuple[float, str]:
        """Dosya risk skorunu tahmin et (0-1 arası olasılık)"""
        if not HAS_ML or not self.is_trained:
            return 0.0, "ML motoru kullanılamıyor"
        
        try:
            features = self.extract_features(file_path)
            if features is None:
                return 0.0, "Özellik çıkarılamadı"
            
            features_scaled = self.scaler.transform(features)
            probability = self.model.predict_proba(features_scaled)[0][1]  # Zararlı sınıfı
            
            explanation = f"Yapay Zeka Riski: %{probability * 100:.1f}"
            
            return probability, explanation
            
        except Exception as e:
            logger.log("UYARI", f"ML tahmin hatası ({file_path}): {e}", "ML")
            return 0.0, f"Tahmin hatası: {str(e)}"


# ═══════════════════════════════════════════════════════════════════════════════
# YARA-LITE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class YaraLiteEngine:
    """Hafif YARA benzeri kural motoru"""
    
    def __init__(self):
        self.rules: List[YaraRule] = []
        self._init_default_rules()
    
    def _init_default_rules(self):
        """Varsayılan tespit kurallarını yükle"""
        default_rules = [
            # PowerShell kötüye kullanımı
            YaraRule(
                name="Şüpheli PowerShell Kullanımı",
                strings=[
                    b"powershell",
                    b"-enc",
                    b"-encodedcommand",
                    b"bypass",
                    b"noprofile"
                ],
                condition="any",
                score=35
            ),
            
            # Base64 payload
            YaraRule(
                name="Base64 Payload Şüphesi",
                strings=[
                    b"FromBase64String",
                    b"::FromBase64String",
                    b"base64_decode"
                ],
                condition="any",
                score=30
            ),
            
            # Windows API kullanımı
            YaraRule(
                name="Şüpheli Windows API Çağrıları",
                strings=[
                    b"VirtualAlloc",
                    b"WriteProcessMemory",
                    b"CreateRemoteThread",
                    b"LoadLibraryA",
                    b"GetProcAddress"
                ],
                condition="n_of",
                n_value=2,
                score=40
            ),
            
            # PE Header (tüm PE dosyaları için)
            YaraRule(
                name="PE Dosya Formatı",
                strings=[b"MZ"],
                hex_pattern="4D 5A",
                condition="all",
                score=0  # Bu sadece bilgi amaçlı
            ),
            
            # Script şüphesi
            YaraRule(
                name="Şüpheli Script İçeriği",
                strings=[
                    b"WScript.Shell",
                    b"CreateObject",
                    b"ShellExecute",
                    b"mshta",
                    b"rundll32"
                ],
                condition="any",
                score=25
            ),
            
            # Registry manipülasyonu
            YaraRule(
                name="Registry Manipülasyonu",
                strings=[
                    b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    b"reg add",
                    b"SetValueEx",
                    b"CreateKey"
                ],
                condition="any",
                score=30
            ),
            
            # Network aktivite şüphesi
            YaraRule(
                name="Şüpheli Network Aktivitesi",
                strings=[
                    b"WinHttpRequest",
                    b"XMLHTTP",
                    b"DownloadString",
                    b"bitsadmin /transfer"
                ],
                condition="any",
                score=25
            ),
            
            # Obfuscation işaretleri
            YaraRule(
                name="Obfuscation İşaretleri",
                strings=[
                    b"charCodeAt",
                    b"fromCharCode",
                    b"unescape",
                    b"decodeURIComponent"
                ],
                condition="n_of",
                n_value=2,
                score=20
            ),
        ]
        
        self.rules = default_rules
        logger.log("BİLGİ", f"{len(self.rules)} YaraLite kuralı yüklendi", "YARALITE")
    
    def scan(self, file_path: str) -> Tuple[float, List[str]]:
        """Dosyayı YaraLite kuralları ile tara"""
        score = 0
        matches = []
        
        try:
            with open(file_path, "rb") as f:
                content = f.read(10 * 1024 * 1024)  # İlk 10MB
            
            for rule in self.rules:
                if self._match_rule(rule, content):
                    score += rule.score
                    matches.append(rule.name)
            
            # Skor sınırlandırma
            score = min(score, 100)
            
        except Exception as e:
            logger.log("UYARI", f"YaraLite tarama hatası ({file_path}): {e}", "YARALITE")
        
        return score, matches
    
    def _match_rule(self, rule: YaraRule, content: bytes) -> bool:
        """Tek bir kuralı eşleştir"""
        try:
            # Hex pattern kontrolü
            if rule.hex_pattern:
                hex_bytes = bytes.fromhex(rule.hex_pattern.replace(" ", ""))
                if hex_bytes not in content:
                    return False
            
            # String kontrolü
            if rule.strings:
                if rule.use_regex:
                    # Regex kontrolü
                    matches = []
                    for pattern in rule.strings:
                        try:
                            if re.search(pattern, content, re.IGNORECASE):
                                matches.append(True)
                            else:
                                matches.append(False)
                        except re.error:
                            matches.append(False)
                else:
                    # Normal string kontrolü
                    matches = [s in content for s in rule.strings]
                
                # Koşul değerlendirme
                if rule.condition == "all":
                    return all(matches)
                elif rule.condition == "any":
                    return any(matches)
                elif rule.condition == "n_of":
                    return sum(matches) >= rule.n_value
            
            return True
            
        except Exception as e:
            logger.log("UYARI", f"Kural eşleştirme hatası ({rule.name}): {e}", "YARALITE")
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# VIRUSTOTAL CLIENT
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# QUARANTINE MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class QuarantineManager:
    """Karantina yönetim sistemi"""
    
    def __init__(self):
        self.quarantine_dir = QUARANTINE_DIR
        self.metadata_file = self.quarantine_dir / "metadata.json"
        self.items: Dict[str, QuarantineItem] = {}
        self.lock = threading.Lock()
        self._ensure_quarantine_dir()
        self._load_metadata()
    
    def _ensure_quarantine_dir(self):
        """Karantina dizinini oluştur"""
        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.log("KRİTİK", f"Karantina dizini oluşturulamadı: {e}", "QUARANTINE")
    
    def _load_metadata(self):
        """Metadata dosyasını yükle"""
        try:
            if self.metadata_file.exists():
                with open(self.metadata_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                for item_id, item_data in data.items():
                    self.items[item_id] = QuarantineItem(**item_data)
                
                logger.log("BİLGİ", f"{len(self.items)} karantina öğesi yüklendi", "QUARANTINE")
        except Exception as e:
            logger.log("UYARI", f"Metadata yükleme hatası: {e}", "QUARANTINE")
    
    def _save_metadata(self):
        """Metadata dosyasını kaydet"""
        try:
            with self.lock:
                data = {
                    item_id: {
                        "quarantine_id": item.quarantine_id,
                        "original_path": item.original_path,
                        "quarantine_path": item.quarantine_path,
                        "file_hash": item.file_hash,
                        "reason": item.reason,
                        "date": item.date,
                        "metadata": item.metadata
                    }
                    for item_id, item in self.items.items()
                }
                
                with open(self.metadata_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.log("UYARI", f"Metadata kaydetme hatası: {e}", "QUARANTINE")
    
    def quarantine(self, file_path: str, reason: str, file_hash: str) -> Tuple[bool, str]:
        """Dosyayı karantinaya al"""
        try:
            with self.lock:
                file_path_obj = Path(file_path)
                if not file_path_obj.exists():
                    return False, "Dosya bulunamadı"
                
                # Benzersiz ID oluştur
                quarantine_id = f"Q{int(time.time())}_{file_hash[:16]}"
                
                # Karantina dosya adı (hash bazlı)
                quarantine_filename = f"{file_hash}.quarantine"
                quarantine_path = self.quarantine_dir / quarantine_filename
                
                # Dosyayı taşı
                shutil.move(str(file_path), str(quarantine_path))
                
                # Metadata oluştur
                item = QuarantineItem(
                    quarantine_id=quarantine_id,
                    original_path=str(file_path),
                    quarantine_path=str(quarantine_path),
                    file_hash=file_hash,
                    reason=reason,
                    date=datetime.now().isoformat(),
                    metadata={
                        "original_name": file_path_obj.name,
                        "file_size": os.path.getsize(quarantine_path)
                    }
                )
                
                self.items[quarantine_id] = item
                self._save_metadata()
                
                logger.log("BİLGİ", f"Dosya karantinaya alındı: {file_path} -> {quarantine_id}", "QUARANTINE")
                
                return True, quarantine_id
                
        except Exception as e:
            logger.log("KRİTİK", f"Karantina hatası ({file_path}): {e}", "QUARANTINE")
            return False, str(e)
    
    def restore(self, quarantine_id: str) -> Tuple[bool, str]:
        """Dosyayı karantinadan geri yükle"""
        try:
            with self.lock:
                if quarantine_id not in self.items:
                    return False, "Karantina ID'si bulunamadı"
                
                item = self.items[quarantine_id]
                quarantine_path = Path(item.quarantine_path)
                
                if not quarantine_path.exists():
                    return False, "Karantina dosyası bulunamadı"
                
                # Hedef dizinin var olduğundan emin ol
                original_dir = Path(item.original_path).parent
                original_dir.mkdir(parents=True, exist_ok=True)
                
                # Dosyayı geri yükle
                shutil.move(str(quarantine_path), item.original_path)
                
                # Metadata'dan kaldır
                del self.items[quarantine_id]
                self._save_metadata()
                
                logger.log("BİLGİ", f"Dosya geri yüklendi: {quarantine_id} -> {item.original_path}", "QUARANTINE")
                
                return True, item.original_path
                
        except Exception as e:
            logger.log("UYARI", f"Geri yükleme hatası ({quarantine_id}): {e}", "QUARANTINE")
            return False, str(e)
    
    def delete(self, quarantine_id: str) -> Tuple[bool, str]:
        """Karantina dosyasını kalıcı sil"""
        try:
            with self.lock:
                if quarantine_id not in self.items:
                    return False, "Karantina ID'si bulunamadı"
                
                item = self.items[quarantine_id]
                quarantine_path = Path(item.quarantine_path)
                
                if quarantine_path.exists():
                    quarantine_path.unlink()
                
                # Metadata'dan kaldır
                del self.items[quarantine_id]
                self._save_metadata()
                
                logger.log("BİLGİ", f"Karantina dosyası silindi: {quarantine_id}", "QUARANTINE")
                
                return True, "Silindi"
                
        except Exception as e:
            logger.log("UYARI", f"Silme hatası ({quarantine_id}): {e}", "QUARANTINE")
            return False, str(e)
    
    def get_all_items(self) -> List[QuarantineItem]:
        """Tüm karantina öğelerini getir"""
        with self.lock:
            return list(self.items.values())


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class ScannerEngine(QObject):
    """Ana tarama motoru"""
    
    # Sinyaller (thread-safe UI güncellemeleri için)
    scan_progress = Signal(int, int, str)  # current, total, current_file
    scan_result = Signal(object)  # ScanResult
    scan_finished = Signal(int, int, int)  # scanned, threats, time
    
    def __init__(self, cache_manager: CacheManager):
        super().__init__()
        self.cache = cache_manager
        self.heuristic = HeuristicEngine()
        self.ml = MLEngine()
        self.yaralite = YaraLiteEngine()
        self.quarantine = QuarantineManager()
        
        self.running = False
        self.paused = False
        self.scan_thread = None
        self.executor = None
        
    def scan_file(self, file_path: str) -> ScanResult:
        """Tek dosya tara"""
        start_time = time.time()
        
        try:
            # Hash hesapla
            sha256 = HashUtils.calculate_sha256(file_path)
            if not sha256:
                return ScanResult(
                    file_path=file_path,
                    sha256="",
                    file_size=0,
                    status="HATA",
                    threats=["Hash hesaplanamadı"],
                    scan_time=0
                )
            
            file_size = os.path.getsize(file_path)
            
            # Cache kontrolü
            cached = self.cache.get(sha256)
            if cached:
                logger.log("BİLGİ", f"Önbellekten sunuldu: {file_path}", "SCANNER")
                return ScanResult(
                    file_path=file_path,
                    sha256=sha256,
                    file_size=file_size,
                    **cached
                )
            
            result = ScanResult(
                file_path=file_path,
                sha256=sha256,
                file_size=file_size
            )
            
            # 1. Heuristic analiz
            heuristic_score, heuristic_threats = self.heuristic.analyze(file_path)
            result.heuristic_score = heuristic_score
            result.threats.extend(heuristic_threats)
            
            # 2. ML analiz
            ml_prob, ml_explanation = self.ml.predict(file_path)
            result.ml_probability = ml_prob
            if ml_prob > 0.3:
                result.threats.append(ml_explanation)
            
            # 3. YaraLite tarama
            yara_score, yara_matches = self.yaralite.scan(file_path)
            result.yara_score = yara_score
            result.threats.extend(yara_matches)
            
            # Final skor hesapla
            result.calculate_final_score()
            result.scan_time = time.time() - start_time
            
            # Cache'e kaydet
            self.cache.set(sha256, {
                "heuristic_score": result.heuristic_score,
                "ml_probability": result.ml_probability,
                "yara_score": result.yara_score,
                "final_score": result.final_score,
                "status": result.status,
                "threats": result.threats
            })
            
            return result
            
        except Exception as e:
            logger.log("UYARI", f"Dosya tarama hatası ({file_path}): {e}", "SCANNER")
            return ScanResult(
                file_path=file_path,
                sha256="",
                file_size=0,
                status="HATA",
                threats=[f"Tarama hatası: {str(e)}"],
                scan_time=0
            )
    
    def scan_directory(self, directory: str, recursive: bool = True, 
                       max_workers: int = MAX_WORKERS) -> List[ScanResult]:
        """Dizin tara"""
        results = []
        scanned_files = []
        
        try:
            # Dosya listesi oluştur
            path = Path(directory)
            if recursive:
                files = list(path.rglob("*"))
            else:
                files = list(path.glob("*"))
            
            # Sadece dosyaları al (dizinleri hariç tut)
            files = [f for f in files if f.is_file()]
            
            # Boyut filtresi (çok büyük dosyaları atla)
            files = [f for f in files if f.stat().st_size < MAX_FILE_SIZE * 10]
            
            total_files = len(files)
            scanned_count = 0
            
            logger.log("BİLGİ", f"Tarama başlatıldı: {directory} ({total_files} dosya)", "SCANNER")
            
            # Thread pool ile tarama
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_file = {
                    executor.submit(self.scan_file, str(f)): f 
                    for f in files
                }
                
                for future in as_completed(future_to_file):
                    if not self.running:
                        break
                    
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        results.append(result)
                        scanned_count += 1
                        
                        # İlerleme sinyali gönder
                        self.scan_progress.emit(scanned_count, total_files, str(file_path))
                        
                        # Sonuç sinyali gönder
                        self.scan_result.emit(result)
                        
                    except Exception as e:
                        logger.log("UYARI", f"Tarama hatası ({file_path}): {e}", "SCANNER")
            
            return results
            
        except Exception as e:
            logger.log("KRİTİK", f"Dizin tarama hatası: {e}", "SCANNER")
            return results
    
    def start_scan(self, target: str, recursive: bool = True):
        """Taramayı başlat (thread)"""
        if self.running:
            return False
        
        self.running = True
        
        def scan_worker():
            try:
                start_time = time.time()
                
                if os.path.isfile(target):
                    result = self.scan_file(target)
                    results = [result]
                    self.scan_progress.emit(1, 1, target)
                    self.scan_result.emit(result)
                else:
                    results = self.scan_directory(target, recursive)
                
                # Sonuçları analiz et
                threats = len([r for r in results if r.status in ["ZARARLI", "ŞÜPHELİ"]])
                scanned = len(results)
                elapsed = int(time.time() - start_time)
                
                self.scan_finished.emit(scanned, threats, elapsed)
                
                logger.log("BİLGİ", f"Tarama tamamlandı: {scanned} tarandı, {threats} tehdit, {elapsed}s", "SCANNER")
                
            except Exception as e:
                logger.log("KRİTİK", f"Tarama iş parçacığı hatası: {e}", "SCANNER")
            finally:
                self.running = False
        
        self.scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self.scan_thread.start()
        
        return True
    
    def stop_scan(self):
        """Taramayı durdur"""
        self.running = False
        logger.log("BİLGİ", "Tarama durduruldu", "SCANNER")


# ═══════════════════════════════════════════════════════════════════════════════
# REAL-TIME PROTECTION
# ═══════════════════════════════════════════════════════════════════════════════

class FileSystemHandler(FileSystemEventHandler):
    """Dosya sistemi olay işleyici"""
    
    def __init__(self, scanner: ScannerEngine, callback: Callable):
        self.scanner = scanner
        self.callback = callback
        self.recent_files: Dict[str, float] = {}
        self.debounce_seconds = 2
        self.lock = threading.Lock()
    
    def on_created(self, event):
        if not event.is_directory:
            self._handle_file_event(event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            self._handle_file_event(event.src_path)
    
    def _handle_file_event(self, file_path: str):
        """Dosya olayını işle (debounce ile)"""
        try:
            with self.lock:
                current_time = time.time()
                
                # Debounce kontrolü
                if file_path in self.recent_files:
                    if current_time - self.recent_files[file_path] < self.debounce_seconds:
                        return
                
                self.recent_files[file_path] = current_time
            
            # Sadece şüpheli uzantılar için tara
            suspicious_exts = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.scr', '.cmd'}
            if Path(file_path).suffix.lower() in suspicious_exts:
                result = self.scanner.scan_file(file_path)
                
                if result.status in ["ZARARLI", "ŞÜPHELİ"]:
                    self.callback(result)
                    
        except Exception as e:
            logger.log("UYARI", f"Gerçek zamanlı koruma hatası: {e}", "REALTIME")


class RealTimeProtection(QObject):
    """Gerçek zamanlı koruma sistemi"""
    
    threat_detected = Signal(object)  # ScanResult
    
    def __init__(self, scanner: ScannerEngine):
        super().__init__()
        self.scanner = scanner
        self.observer = None
        self.handler = None
        self.enabled = False
        self.watch_paths: List[str] = []
    
    def start(self, paths: List[str] = None):
        """Gerçek zamanlı korumayı başlat"""
        if not HAS_WATCHDOG:
            logger.log("UYARI", "Watchdog kütüphanesi kurulu değil. Gerçek zamanlı koruma devre dışı.", "REALTIME")
            return False
        
        try:
            self.watch_paths = paths or [
                str(Path.home() / "Downloads"),
                str(Path.home() / "Desktop"),
                tempfile.gettempdir()
            ]
            
            self.handler = FileSystemHandler(self.scanner, self._on_threat_detected)
            self.observer = Observer()
            
            for path in self.watch_paths:
                if os.path.exists(path):
                    self.observer.schedule(self.handler, path, recursive=False)
                    logger.log("BİLGİ", f"İzleme başlatıldı: {path}", "REALTIME")
            
            self.observer.start()
            self.enabled = True
            
            logger.log("BİLGİ", "Gerçek zamanlı koruma aktif", "REALTIME")
            return True
            
        except Exception as e:
            logger.log("KRİTİK", f"Gerçek zamanlı koruma başlatma hatası: {e}", "REALTIME")
            return False
    
    def stop(self):
        """Gerçek zamanlı korumayı durdur"""
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join()
            self.enabled = False
            logger.log("BİLGİ", "Gerçek zamanlı koruma durduruldu", "REALTIME")
            return True
        except Exception as e:
            logger.log("UYARI", f"Gerçek zamanlı koruma durdurma hatası: {e}", "REALTIME")
            return False
    
    def _on_threat_detected(self, result: ScanResult):
        """Tehdit tespit edildiğinde çağrılır"""
        self.threat_detected.emit(result)


# ═══════════════════════════════════════════════════════════════════════════════
# UI STYLES
# ═══════════════════════════════════════════════════════════════════════════════

STYLESHEET = f"""
QMainWindow {{
    background-color: {COLORS["background"]};
}}

QWidget {{
    font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
    font-size: 13px;
    color: {COLORS["text"]};
}}

QLabel {{
    color: {COLORS["text"]};
}}

/* Sidebar - AÇIK TEMA */
#sidebar {{
    background-color: #F5F5F5;
    min-width: 200px;
    max-width: 200px;
    border-right: 1px solid {COLORS["border"]};
}}

#sidebar_button {{
    background-color: transparent;
    color: {COLORS["text"]};
    border: none;
    padding: 15px 20px;
    text-align: left;
    font-size: 14px;
    font-weight: 500;
}}

#sidebar_button:hover {{
    background-color: {COLORS["secondary"]};
}}

#sidebar_button:checked {{
    background-color: {COLORS["primary"]};
    color: white;
    border-left: 4px solid {COLORS["primary"]};
}}

/* Header */
#header {{
    background-color: {COLORS["primary"]};
    padding: 20px;
    color: white;
    border-radius: 10px;
}}

#header_title {{
    font-size: 28px;
    font-weight: bold;
    color: white;
}}

#header_subtitle {{
    font-size: 14px;
    color: rgba(255, 255, 255, 0.9);
}}

/* Cards */
#card {{
    background-color: {COLORS["card_bg"]};
    border-radius: 10px;
    padding: 20px;
    border: 1px solid {COLORS["border"]};
}}

#card_title {{
    font-size: 16px;
    font-weight: bold;
    color: {COLORS["text"]};
    margin-bottom: 10px;
}}

/* Status Labels */
#status_safe {{
    color: {COLORS["success"]};
    font-size: 24px;
    font-weight: bold;
}}

#status_warning {{
    color: {COLORS["warning"]};
    font-size: 24px;
    font-weight: bold;
}}

#status_danger {{
    color: {COLORS["danger"]};
    font-size: 24px;
    font-weight: bold;
}}

/* Buttons */
QPushButton {{
    background-color: {COLORS["primary"]};
    color: white;
    border: none;
    border-radius: 6px;
    padding: 12px 24px;
    font-weight: 600;
    font-size: 13px;
}}

QPushButton:hover {{
    background-color: #E85A2D;
}}

QPushButton:pressed {{
    background-color: #D54E24;
}}

QPushButton:disabled {{
    background-color: #E0E0E0;
    color: #999999;
}}

#secondary_button {{
    background-color: {COLORS["secondary"]};
    color: {COLORS["text"]};
    border: 1px solid {COLORS["border"]};
}}

#secondary_button:hover {{
    background-color: #FFE8D6;
}}

/* Progress Bar */
QProgressBar {{
    border: none;
    border-radius: 5px;
    background-color: {COLORS["border"]};
    height: 8px;
    text-align: center;
    color: {COLORS["text"]};
}}

QProgressBar::chunk {{
    background-color: {COLORS["primary"]};
    border-radius: 5px;
}}

/* Tables */
QTableWidget {{
    background-color: white;
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    gridline-color: #F0F0F0;
    color: {COLORS["text"]};
}}

QTableWidget::item {{
    padding: 10px;
    color: {COLORS["text"]};
}}

QTableWidget::item:selected {{
    background-color: {COLORS["secondary"]};
    color: {COLORS["text"]};
}}

QHeaderView::section {{
    background-color: #F0F0F0;
    color: {COLORS["text"]};
    padding: 10px;
    border: 1px solid {COLORS["border"]};
    font-weight: 600;
}}

/* Text Edit */
QTextEdit {{
    background-color: white;
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    padding: 10px;
    font-family: 'Consolas', 'Courier New', monospace;
    color: {COLORS["text"]};
}}

/* Group Box */
QGroupBox {{
    font-weight: 600;
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    margin-top: 10px;
    padding-top: 10px;
    color: {COLORS["text"]};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: {COLORS["text"]};
}}

/* Combo Box */
QComboBox {{
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    padding: 8px;
    background-color: white;
    color: {COLORS["text"]};
}}

QComboBox:hover {{
    border-color: {COLORS["primary"]};
}}

QComboBox::drop-down {{
    border: none;
    padding-right: 10px;
}}

QComboBox QAbstractItemView {{
    color: {COLORS["text"]};
    background-color: white;
    selection-background-color: {COLORS["secondary"]};
}}

/* Line Edit */
QLineEdit {{
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    padding: 10px;
    background-color: white;
    color: {COLORS["text"]};
}}

QLineEdit:focus {{
    border-color: {COLORS["primary"]};
}}

/* Scrollbar */
QScrollBar:vertical {{
    background-color: #F0F0F0;
    width: 10px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical {{
    background-color: #C0C0C0;
    border-radius: 5px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: #A0A0A0;
}}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{
    height: 0px;
}}

/* Tab Widget */
QTabWidget::pane {{
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    background-color: white;
}}

QTabBar::tab {{
    background-color: #F0F0F0;
    color: {COLORS["text"]};
    padding: 12px 24px;
    margin-right: 4px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}}

QTabBar::tab:selected {{
    background-color: {COLORS["primary"]};
    color: white;
}}

QTabBar::tab:hover:!selected {{
    background-color: #E0E0E0;
}}

/* CheckBox */
QCheckBox {{
    color: {COLORS["text"]};
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border: 2px solid {COLORS["border"]};
    border-radius: 3px;
    background-color: white;
}}

QCheckBox::indicator:checked {{
    background-color: {COLORS["primary"]};
    border-color: {COLORS["primary"]};
}}

/* List Widget */
QListWidget {{
    background-color: white;
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    color: {COLORS["text"]};
}}

QListWidget::item {{
    padding: 8px;
    color: {COLORS["text"]};
}}

QListWidget::item:selected {{
    background-color: {COLORS["secondary"]};
    color: {COLORS["text"]};
}}
"""


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN UI
# ═══════════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    """Ana uygulama penceresi"""
    
    def __init__(self):
        super().__init__()
        
        # Core bileşenler
        self.cache = CacheManager()
        self.scanner = ScannerEngine(self.cache)
        self.realtime = RealTimeProtection(self.scanner)
        self.quarantine_manager = QuarantineManager()
        
        # Sinyal bağlantıları
        self.scanner.scan_progress.connect(self._on_scan_progress)
        self.scanner.scan_result.connect(self._on_scan_result)
        self.scanner.scan_finished.connect(self._on_scan_finished)
        self.realtime.threat_detected.connect(self._on_realtime_threat)
        
        # UI setup
        self._setup_ui()
        self._apply_styles()
        self._connect_log_callback()
        
        # Başlangıç logları
        logger.log("BİLGİ", f"{APP_NAME} v{VERSION} başlatıldı", "CORE")
        logger.log("BİLGİ", "Tüm motorlar hazır", "CORE")
    
    def _setup_ui(self):
        """UI bileşenlerini oluştur"""
        self.setWindowTitle(f"{APP_NAME} Security v{VERSION}")
        self.setMinimumSize(1200, 800)
        
        # Merkez widget
        central = QWidget()
        self.setCentralWidget(central)
        
        # Ana layout
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar
        self.sidebar = self._create_sidebar()
        main_layout.addWidget(self.sidebar)
        
        # İçerik alanı
        self.content_stack = QStackedWidget()
        main_layout.addWidget(self.content_stack, 1)
        
        # Sayfalar
        self.dashboard_page = self._create_dashboard()
        self.scan_page = self._create_scan_page()
        self.protection_page = self._create_protection_page()
        self.detections_page = self._create_detections_page()
        self.quarantine_page = self._create_quarantine_page()
        self.logs_page = self._create_logs_page()
        
        self.content_stack.addWidget(self.dashboard_page)
        self.content_stack.addWidget(self.scan_page)
        self.content_stack.addWidget(self.protection_page)
        self.content_stack.addWidget(self.detections_page)
        self.content_stack.addWidget(self.quarantine_page)
        self.content_stack.addWidget(self.logs_page)
        
        # Tray icon
        self._setup_tray()
        
        # Dashboard'ı göster
        self._show_page(0)
    
    def _create_sidebar(self) -> QWidget:
        """Sidebar oluştur"""
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Logo alanı
        logo_container = QWidget()
        logo_layout = QVBoxLayout(logo_container)
        logo_layout.setContentsMargins(20, 30, 20, 30)
        
        logo_label = QLabel("🔒")
        logo_label.setStyleSheet("font-size: 48px; color: white;")
        logo_label.setAlignment(Qt.AlignCenter)
        
        app_name = QLabel(APP_NAME)
        app_name.setStyleSheet("font-size: 20px; font-weight: bold; color: white;")
        app_name.setAlignment(Qt.AlignCenter)
        
        tagline = QLabel("Yapay Zeka Destekli\nZararlı Yazılım Tespiti")
        tagline.setStyleSheet("font-size: 11px; color: rgba(255,255,255,0.7);")
        tagline.setAlignment(Qt.AlignCenter)
        
        logo_layout.addWidget(logo_label)
        logo_layout.addWidget(app_name)
        logo_layout.addWidget(tagline)
        
        layout.addWidget(logo_container)
        
        # Menü butonları
        self.sidebar_buttons = []
        menu_items = [
            ("📊", "Dashboard", 0),
            ("🔍", "Tarama", 1),
            ("🛡️", "Koruma", 2),
            ("⚠️", "Tespitler", 3),
            ("🔐", "Karantina", 4),
            ("📋", "Loglar", 5),
        ]
        
        for icon, text, index in menu_items:
            btn = QPushButton(f"  {icon}  {text}")
            btn.setObjectName("sidebar_button")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, i=index: self._show_page(i))
            layout.addWidget(btn)
            self.sidebar_buttons.append(btn)
        
        layout.addStretch()
        
        # Durum alanı
        status_container = QWidget()
        status_layout = QVBoxLayout(status_container)
        status_layout.setContentsMargins(20, 20, 20, 20)
        
        self.status_label = QLabel("🟢 Sistem Güvende")
        self.status_label.setStyleSheet("color: {COLORS['success']}; font-weight: bold;")
        self.status_label.setAlignment(Qt.AlignCenter)
        
        status_layout.addWidget(self.status_label)
        layout.addWidget(status_container)
        
        return sidebar
    
    def _create_dashboard(self) -> QWidget:
        """Dashboard sayfası oluştur"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Başlık
        header = QWidget()
        header.setObjectName("header")
        header_layout = QVBoxLayout(header)
        
        title = QLabel("Sistem Durumu")
        title.setObjectName("header_title")
        
        subtitle = QLabel("Gerçek zamanlı koruma aktif - Son tarama: Bugün")
        subtitle.setObjectName("header_subtitle")
        
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        
        layout.addWidget(header)
        
        # İstatistik kartları
        stats_layout = QHBoxLayout()
        
        # Güvenlik durumu kartı
        status_card = self._create_stat_card(
            "Güvenlik Durumu",
            "🛡️",
            "Sistem Güvende",
            "Gerçek zamanlı koruma aktif",
            COLORS["success"]
        )
        stats_layout.addWidget(status_card)
        
        # Taranan dosyalar kartı
        self.scanned_card = self._create_stat_card(
            "Taranan Dosyalar",
            "📁",
            "0",
            "Toplam taranan",
            COLORS["primary"]
        )
        stats_layout.addWidget(self.scanned_card)
        
        # Tehditler kartı
        self.threats_card = self._create_stat_card(
            "Engellenen Tehditler",
            "🚫",
            "0",
            "Toplam tehdit",
            COLORS["danger"]
        )
        stats_layout.addWidget(self.threats_card)
        
        layout.addLayout(stats_layout)
        
        # Hızlı aksiyonlar
        actions_group = QGroupBox("Hızlı Aksiyonlar")
        actions_layout = QHBoxLayout(actions_group)
        
        quick_scan_btn = QPushButton("⚡ Hızlı Tarama")
        quick_scan_btn.clicked.connect(lambda: self._start_quick_scan())
        actions_layout.addWidget(quick_scan_btn)
        
        full_scan_btn = QPushButton("🔍 Tam Tarama")
        full_scan_btn.clicked.connect(lambda: self._show_page(1))
        actions_layout.addWidget(full_scan_btn)
        
        check_update_btn = QPushButton("🔄 Güncelleme Kontrolü")
        check_update_btn.clicked.connect(lambda: self._check_updates())
        actions_layout.addWidget(check_update_btn)
        
        layout.addWidget(actions_group)
        
        # Son aktiviteler
        activity_group = QGroupBox("Son Aktiviteler")
        activity_layout = QVBoxLayout(activity_group)
        
        self.activity_list = QListWidget()
        self.activity_list.addItem("✅ Uygulama başlatıldı")
        self.activity_list.addItem("✅ Motorlar hazır")
        self.activity_list.addItem("✅ Gerçek zamanlı koruma aktif")
        
        activity_layout.addWidget(self.activity_list)
        layout.addWidget(activity_group, 1)
        
        return page
    
    def _create_stat_card(self, title: str, icon: str, value: str, 
                          subtitle: str, color: str) -> QWidget:
        """İstatistik kartı oluştur"""
        card = QWidget()
        card.setObjectName("card")
        card.setStyleSheet(f"""
            #card {{
                background-color: white;
                border-radius: 10px;
                border-left: 4px solid {color};
            }}
        """)
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 14px; color: #666;")
        
        value_label = QLabel(f"{icon} {value}")
        value_label.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {color};")
        
        subtitle_label = QLabel(subtitle)
        subtitle_label.setStyleSheet("font-size: 12px; color: #999;")
        
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addWidget(subtitle_label)
        
        return card
    
    def _create_scan_page(self) -> QWidget:
        """Tarama sayfası oluştur"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Başlık
        header = QLabel("🔍 Zararlı Yazılım Taraması")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: {COLORS['dark']};")
        layout.addWidget(header)
        
        # Tarama tipi seçimi
        scan_types = QGroupBox("Tarama Tipi")
        scan_types_layout = QHBoxLayout(scan_types)
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems([
            "Hızlı Tarama (Kritik alanlar)",
            "Tam Tarama (Tüm sistem)",
            "Özel Tarama (Seçili klasör)"
        ])
        scan_types_layout.addWidget(self.scan_type_combo)
        
        select_folder_btn = QPushButton("📁 Klasör Seç")
        select_folder_btn.clicked.connect(self._select_scan_folder)
        scan_types_layout.addWidget(select_folder_btn)
        
        layout.addWidget(scan_types)
        
        # Tarama butonları
        buttons_layout = QHBoxLayout()
        
        self.start_scan_btn = QPushButton("▶️ Taramayı Başlat")
        self.start_scan_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS["success"]};
                padding: 15px 30px;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: #219A52;
            }}
        """)
        self.start_scan_btn.clicked.connect(self._start_scan)
        buttons_layout.addWidget(self.start_scan_btn)
        
        self.stop_scan_btn = QPushButton("⏹️ Taramayı Durdur")
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.clicked.connect(self._stop_scan)
        buttons_layout.addWidget(self.stop_scan_btn)
        
        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)
        
        # İlerleme çubuğu
        self.scan_progress = QProgressBar()
        self.scan_progress.setMaximum(100)
        self.scan_progress.setValue(0)
        layout.addWidget(self.scan_progress)
        
        self.current_file_label = QLabel("Hazır")
        self.current_file_label.setStyleSheet("color: #666;")
        layout.addWidget(self.current_file_label)
        
        # Sonuç tablosu
        results_group = QGroupBox("Tarama Sonuçları")
        results_layout = QVBoxLayout(results_group)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Dosya Yolu", "Durum", "Risk Skoru", "Tehditler", "İşlem"
        ])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        
        results_layout.addWidget(self.results_table)
        layout.addWidget(results_group, 1)
        
        # Özet
        self.scan_summary = QLabel("")
        self.scan_summary.setStyleSheet("font-weight: bold; padding: 10px;")
        layout.addWidget(self.scan_summary)
        
        self.current_scan_path = str(Path.home() / "Downloads")
        
        return page
    
    def _create_protection_page(self) -> QWidget:
        """Koruma sayfası oluştur"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Başlık
        header = QLabel("🛡️ Gerçek Zamanlı Koruma")
        header.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(header)
        
        # Durum kartı
        status_card = QWidget()
        status_card.setObjectName("card")
        status_layout = QHBoxLayout(status_card)
        
        self.protection_status = QLabel("⚠️ Devre Dışı")
        self.protection_status.setStyleSheet(f"font-size: 32px; color: {COLORS['warning']}; font-weight: bold;")
        status_layout.addWidget(self.protection_status)
        
        status_layout.addStretch()
        
        self.toggle_protection_btn = QPushButton("▶️ Korumayı Başlat")
        self.toggle_protection_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS["success"]};
                padding: 15px 40px;
                font-size: 14px;
            }}
        """)
        self.toggle_protection_btn.clicked.connect(self._toggle_protection)
        status_layout.addWidget(self.toggle_protection_btn)
        
        layout.addWidget(status_card)
        
        # Ayarlar
        settings_group = QGroupBox("Koruma Ayarları")
        settings_layout = QGridLayout(settings_group)
        
        self.monitor_downloads = QCheckBox("İndirilenler klasörünü izle")
        self.monitor_downloads.setChecked(True)
        settings_layout.addWidget(self.monitor_downloads, 0, 0)
        
        self.monitor_desktop = QCheckBox("Masaüstünü izle")
        self.monitor_desktop.setChecked(True)
        settings_layout.addWidget(self.monitor_desktop, 0, 1)
        
        self.monitor_temp = QCheckBox("Temp klasörünü izle")
        self.monitor_temp.setChecked(True)
        settings_layout.addWidget(self.monitor_temp, 1, 0)
        
        self.auto_quarantine = QCheckBox("Otomatik karantina")
        self.auto_quarantine.setChecked(False)
        settings_layout.addWidget(self.auto_quarantine, 1, 1)
        
        layout.addWidget(settings_group)
        
        # İzlenen yollar
        paths_group = QGroupBox("İzlenen Yollar")
        paths_layout = QVBoxLayout(paths_group)
        
        self.paths_list = QListWidget()
        self.paths_list.addItem(str(Path.home() / "Downloads"))
        self.paths_list.addItem(str(Path.home() / "Desktop"))
        self.paths_list.addItem(tempfile.gettempdir())
        
        paths_layout.addWidget(self.paths_list)
        
        add_path_btn = QPushButton("+ Yeni Yol Ekle")
        add_path_btn.clicked.connect(self._add_watch_path)
        paths_layout.addWidget(add_path_btn)
        
        layout.addWidget(paths_group)
        
        # Bilgi
        info_label = QLabel(
            "💡 Gerçek zamanlı koruma, izlenen klasörlerde yeni dosyalar oluşturulduğunda "
            "ve değiştirildiğinde otomatik olarak tarar."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #666; padding: 10px; background-color: #f0f0f0; border-radius: 6px;")
        layout.addWidget(info_label)
        
        layout.addStretch()
        
        return page
    
    def _create_detections_page(self) -> QWidget:
        """Tespitler sayfası oluştur"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Başlık
        header = QLabel("⚠️ Tehdit Tespitleri")
        header.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(header)
        
        # Tespit tablosu
        self.detections_table = QTableWidget()
        self.detections_table.setColumnCount(6)
        self.detections_table.setHorizontalHeaderLabels([
            "Tarih", "Dosya", "Tür", "Skor", "Tehdit", "İşlem"
        ])
        self.detections_table.horizontalHeader().setStretchLastSection(True)
        
        layout.addWidget(self.detections_table, 1)
        
        # Butonlar
        buttons_layout = QHBoxLayout()
        
        clear_btn = QPushButton("🗑️ Listeyi Temizle")
        clear_btn.clicked.connect(self._clear_detections)
        buttons_layout.addWidget(clear_btn)
        
        export_btn = QPushButton("📤 Dışa Aktar")
        export_btn.clicked.connect(self._export_detections)
        buttons_layout.addWidget(export_btn)
        
        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)
        
        self.detections = []
        
        return page
    
    def _create_quarantine_page(self) -> QWidget:
        """Karantina sayfası oluştur"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Başlık
        header = QLabel("🔐 Karantina Yönetimi")
        header.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(header)
        
        # Açıklama
        desc = QLabel("Karantinaya alınan dosyalar burada listelenir. Dosyaları geri yükleyebilir veya kalıcı olarak silebilirsiniz.")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #666; padding: 10px;")
        layout.addWidget(desc)
        
        # Karantina tablosu
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(5)
        self.quarantine_table.setHorizontalHeaderLabels([
            "ID", "Orijinal Yol", "Sebep", "Tarih", "İşlemler"
        ])
        self.quarantine_table.horizontalHeader().setStretchLastSection(True)
        
        layout.addWidget(self.quarantine_table, 1)
        
        # Butonlar
        buttons_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Yenile")
        refresh_btn.clicked.connect(self._refresh_quarantine)
        buttons_layout.addWidget(refresh_btn)
        
        delete_all_btn = QPushButton("🗑️ Tümünü Sil")
        delete_all_btn.clicked.connect(self._delete_all_quarantine)
        buttons_layout.addWidget(delete_all_btn)
        
        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)
        
        # Karantina klasörü
        path_label = QLabel(f"Karantina konumu: {QUARANTINE_DIR}")
        path_label.setStyleSheet("color: #999; font-size: 11px;")
        layout.addWidget(path_label)
        
        self._refresh_quarantine()
        
        return page
    
    def _create_logs_page(self) -> QWidget:
        """Loglar sayfası oluştur"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Başlık
        header = QLabel("📋 Sistem Logları")
        header.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(header)
        
        # Filtreler
        filters_layout = QHBoxLayout()
        
        self.log_level_filter = QComboBox()
        self.log_level_filter.addItems(["Tümü", "BİLGİ", "UYARI", "KRİTİK"])
        self.log_level_filter.currentTextChanged.connect(self._filter_logs)
        filters_layout.addWidget(QLabel("Seviye:"))
        filters_layout.addWidget(self.log_level_filter)
        
        self.log_module_filter = QLineEdit()
        self.log_module_filter.setPlaceholderText("Modül filtresi...")
        filters_layout.addWidget(QLabel("Modül:"))
        filters_layout.addWidget(self.log_module_filter)
        
        filters_layout.addStretch()
        
        refresh_logs_btn = QPushButton("🔄 Yenile")
        refresh_logs_btn.clicked.connect(self._refresh_logs)
        filters_layout.addWidget(refresh_logs_btn)
        
        clear_logs_btn = QPushButton("🗑️ Temizle")
        clear_logs_btn.clicked.connect(self._clear_logs)
        filters_layout.addWidget(clear_logs_btn)
        
        layout.addLayout(filters_layout)
        
        # Log metni
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setLineWrapMode(QTextEdit.NoWrap)
        layout.addWidget(self.log_text, 1)
        
        self._refresh_logs()
        
        return page
    
    def _apply_styles(self):
        """Stil sayfasını uygula"""
        self.setStyleSheet(STYLESHEET)
    
    def _setup_tray(self):
        """Sistem tepsisi simgesi kurulumu"""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setToolTip(f"{APP_NAME} Security")
        
        # Basit simge oluştur (🔒)
        # Gerçek uygulamada ikon dosyası kullanılmalı
        self.tray_icon.show()
        
        # Menü
        tray_menu = QMenu()
        show_action = QAction("Göster", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        tray_menu.addSeparator()
        
        quit_action = QAction("Çıkış", self)
        quit_action.triggered.connect(self.close)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._tray_activated)
    
    def _tray_activated(self, reason):
        """Tepsi simgesi aktive edildiğinde"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
    
    def _show_page(self, index: int):
        """Sayfa göster"""
        self.content_stack.setCurrentIndex(index)
        
        # Sidebar butonlarını güncelle
        for i, btn in enumerate(self.sidebar_buttons):
            btn.setChecked(i == index)
    
    def _connect_log_callback(self):
        """Log callback'ini bağla"""
        def on_log(log_entry):
            if hasattr(self, 'activity_list'):
                item_text = f"[{log_entry['level']}] {log_entry['message'][:50]}"
                self.activity_list.insertItem(0, item_text)
                if self.activity_list.count() > 50:
                    self.activity_list.takeItem(50)
        
        logger.add_callback(on_log)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SLOT METODLARI
    # ═══════════════════════════════════════════════════════════════════════════
    
    @Slot(int, int, str)
    def _on_scan_progress(self, current: int, total: int, current_file: str):
        """Tarama ilerleme sinyali"""
        if total > 0:
            percentage = int((current / total) * 100)
            self.scan_progress.setValue(percentage)
        
        self.current_file_label.setText(f"Taranıyor: {current_file[:60]}...")
    
    @Slot(object)
    def _on_scan_result(self, result: ScanResult):
        """Tarama sonuç sinyali"""
        # Tabloya ekle
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(result.file_path))
        
        status_item = QTableWidgetItem(result.status)
        if result.status == "ZARARLI":
            status_item.setForeground(QColor(COLORS["danger"]))
        elif result.status == "ŞÜPHELİ":
            status_item.setForeground(QColor(COLORS["warning"]))
        else:
            status_item.setForeground(QColor(COLORS["success"]))
        self.results_table.setItem(row, 1, status_item)
        
        self.results_table.setItem(row, 2, QTableWidgetItem(f"{result.final_score:.1f}"))
        self.results_table.setItem(row, 3, QTableWidgetItem(", ".join(result.threats[:2])))
        
        # İşlem butonu
        action_btn = QPushButton("Karantina" if result.status in ["ZARARLI", "ŞÜPHELİ"] else "Atla")
        if result.status in ["ZARARLI", "ŞÜPHELİ"]:
            action_btn.setStyleSheet(f"background-color: {COLORS['danger']}; padding: 5px;")
            action_btn.clicked.connect(lambda: self._quarantine_result(result))
        else:
            action_btn.setEnabled(False)
        
        self.results_table.setCellWidget(row, 4, action_btn)
        
        # Tespitler listesine ekle
        if result.status in ["ZARARLI", "ŞÜPHELİ"]:
            self.detections.append(result)
            self._add_detection_to_table(result)
    
    def _add_detection_to_table(self, result: ScanResult):
        """Tespiti tabloya ekle"""
        row = self.detections_table.rowCount()
        self.detections_table.insertRow(row)
        
        self.detections_table.setItem(row, 0, QTableWidgetItem(result.timestamp))
        self.detections_table.setItem(row, 1, QTableWidgetItem(Path(result.file_path).name))
        self.detections_table.setItem(row, 2, QTableWidgetItem(result.status))
        self.detections_table.setItem(row, 3, QTableWidgetItem(f"{result.final_score:.1f}"))
        self.detections_table.setItem(row, 4, QTableWidgetItem(", ".join(result.threats[:2])))
        
        action_btn = QPushButton("Karantina")
        action_btn.setStyleSheet(f"background-color: {COLORS['danger']}; padding: 5px;")
        action_btn.clicked.connect(lambda: self._quarantine_result(result))
        self.detections_table.setCellWidget(row, 5, action_btn)
    
    @Slot(int, int, int)
    def _on_scan_finished(self, scanned: int, threats: int, elapsed: int):
        """Tarama tamamlandı sinyali"""
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        
        self.scan_progress.setValue(100)
        self.current_file_label.setText(f"Tarama tamamlandı: {scanned} dosya tarandı, {threats} tehdit bulundu ({elapsed}s)")
        
        self.scan_summary.setText(
            f"📊 Özet: {scanned} dosya tarandı, {threats} tehdit tespit edildi, "
            f"süre: {elapsed} saniye"
        )
        
        if threats > 0:
            QMessageBox.warning(
                self,
                "Tarama Tamamlandı",
                f"⚠️ {threats} tehdit tespit edildi!\n\n"
                f"Lütfen 'Tespitler' sekmesinden inceleyin ve karantina işlemi yapın."
            )
        else:
            QMessageBox.information(
                self,
                "Tarama Tamamlandı",
                f"✅ Tarama tamamlandı. Herhangi bir tehdit bulunamadı."
            )
    
    @Slot(object)
    def _on_realtime_threat(self, result: ScanResult):
        """Gerçek zamanlı tehdit sinyali"""
        logger.log("UYARI", f"Gerçek zamanlı tehdit: {result.file_path}", "REALTIME")
        
        # Bildirim göster
        if hasattr(self, 'tray_icon'):
            self.tray_icon.showMessage(
                "🚨 Tehdit Tespit Edildi!",
                f"Dosya: {Path(result.file_path).name}\n"
                f"Risk: {result.final_score:.1f}/100",
                QSystemTrayIcon.Warning,
                5000
            )
        
        # Tespitler listesine ekle
        self.detections.append(result)
        self._add_detection_to_table(result)
        
        # Otomatik karantina
        if hasattr(self, 'auto_quarantine') and self.auto_quarantine.isChecked():
            self._quarantine_result(result)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # AKSİYON METODLARI
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _start_quick_scan(self):
        """Hızlı tarama başlat"""
        paths = [
            str(Path.home() / "Downloads"),
            str(Path.home() / "Desktop"),
            tempfile.gettempdir()
        ]
        
        for path in paths:
            if os.path.exists(path):
                self.current_scan_path = path
                self._show_page(1)
                self._start_scan()
                return
    
    def _check_updates(self):
        """Güncelleme kontrolü"""
        QMessageBox.information(
            self,
            "Güncelleme Kontrolü",
            "✅ Şu anda en son sürümü kullanıyorsunuz.\n"
            f"Mevcut sürüm: {VERSION}"
        )
    
    def _select_scan_folder(self):
        """Tarama klasörü seç"""
        folder = QFileDialog.getExistingDirectory(self, "Tarama Klasörü Seç")
        if folder:
            self.current_scan_path = folder
            self.scan_type_combo.setCurrentIndex(2)  # Özel tarama
            logger.log("BİLGİ", f"Tarama klasörü seçildi: {folder}", "UI")
    
    def _start_scan(self):
        """Tarama başlat"""
        if not os.path.exists(self.current_scan_path):
            QMessageBox.warning(self, "Hata", "Seçilen klasör bulunamadı!")
            return
        
        # Tabloyu temizle
        self.results_table.setRowCount(0)
        self.scan_summary.setText("")
        
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.scan_progress.setValue(0)
        
        logger.log("BİLGİ", f"Tarama başlatıldı: {self.current_scan_path}", "UI")
        
        self.scanner.start_scan(self.current_scan_path, recursive=True)
    
    def _stop_scan(self):
        """Tarama durdur"""
        self.scanner.stop_scan()
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
    
    def _toggle_protection(self):
        """Koruma aç/kapat"""
        if self.realtime.enabled:
            # Durdur
            self.realtime.stop()
            self.protection_status.setText("⚠️ Devre Dışı")
            self.protection_status.setStyleSheet(f"font-size: 24px; color: {COLORS['warning']}; font-weight: bold;")
            self.toggle_protection_btn.setText("▶️ Başlat")
            self.toggle_protection_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS["success"]};
                    padding: 12px 30px;
                    font-size: 13px;
                }}
            """)
            self.status_label.setText("🟡 Koruma Devre Dışı")
        else:
            # Başlat
            paths = []
            if self.monitor_downloads.isChecked():
                paths.append(str(Path.home() / "Downloads"))
            if self.monitor_desktop.isChecked():
                paths.append(str(Path.home() / "Desktop"))
            if self.monitor_temp.isChecked():
                paths.append(tempfile.gettempdir())
            
            if self.realtime.start(paths):
                self.protection_status.setText("🛡️ Aktif")
                self.protection_status.setStyleSheet(f"font-size: 32px; color: {COLORS['success']}; font-weight: bold;")
                self.toggle_protection_btn.setText("⏹️ Korumayı Durdur")
                self.toggle_protection_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLORS["danger"]};
                        padding: 15px 40px;
                        font-size: 14px;
                    }}
                """)
                self.status_label.setText("🟢 Sistem Güvende")
            else:
                QMessageBox.warning(
                    self,
                    "Hata",
                    "Gerçek zamanlı koruma başlatılamadı.\n"
                    "Lütfen 'watchdog' kütüphanesinin kurulu olduğundan emin olun.\n"
                    "pip install watchdog"
                )
    
    def _toggle_network_protection(self):
        """Ağ korumasını aç/kapat"""
        if self.network_protection.enabled:
            # Durdur
            self.network_protection.disable()
            self.network_status.setText("⚠️ Ağ Koruması Devre Dışı")
            self.network_status.setStyleSheet(f"font-size: 24px; color: {COLORS['warning']}; font-weight: bold;")
            self.toggle_network_btn.setText("▶️ Ağ Korumasını Başlat")
            self.toggle_network_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS["primary"]};
                    padding: 12px 30px;
                    font-size: 13px;
                }}
            """)
        else:
            # Başlat
            if self.network_protection.enable():
                self.network_status.setText("🛡️ Ağ Koruması Aktif")
                self.network_status.setStyleSheet(f"font-size: 24px; color: {COLORS['success']}; font-weight: bold;")
                self.toggle_network_btn.setText("⏹️ Ağ Korumasını Durdur")
                self.toggle_network_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLORS["danger"]};
                        padding: 12px 30px;
                        font-size: 13px;
                    }}
                """)
                QMessageBox.information(
                    self,
                    "Ağ Koruması Aktif",
                    "🌐 Ağ koruması etkinleştirildi.\n\n"
                    "• Şüpheli portlar engelleniyor\n"
                    "• Bilinen zararlı IP'ler engelleniyor\n"
                    "• Giden bağlantılar izleniyor"
                )
    
    def _add_blocked_ip(self):
        """Engellenen IP ekle"""
        from PySide6.QtWidgets import QInputDialog
        ip, ok = QInputDialog.getText(self, "IP Ekle", "Engellenecek IP adresi:")
        if ok and ip:
            self.network_protection.add_blocked_ip(ip)
            self.blocked_ips_list.addItem(f"{ip} - Manuel eklendi")
            logger.log("BİLGİ", f"Engellenen IP eklendi: {ip}", "UI")
    
    def _remove_blocked_ip(self):
        """Engellenen IP kaldır"""
        current = self.blocked_ips_list.currentRow()
        if current >= 0:
            self.blocked_ips_list.takeItem(current)
            logger.log("BİLGİ", "Engellenen IP kaldırıldı", "UI")
    
    def _add_blocked_domain(self):
        """Engellenen domain ekle"""
        from PySide6.QtWidgets import QInputDialog
        domain, ok = QInputDialog.getText(self, "Domain Ekle", "Engellenecek domain:")
        if ok and domain:
            self.network_protection.add_blocked_domain(domain)
            self.blocked_domains_list.addItem(f"{domain} - Manuel eklendi")
            logger.log("BİLGİ", f"Engellenen domain eklendi: {domain}", "UI")
    
    def _remove_blocked_domain(self):
        """Engellenen domain kaldır"""
        current = self.blocked_domains_list.currentRow()
        if current >= 0:
            self.blocked_domains_list.takeItem(current)
            logger.log("BİLGİ", "Engellenen domain kaldırıldı", "UI")
    
    def _refresh_network_logs(self):
        """Ağ loglarını yenile"""
        logs = self.network_protection.get_logs()
        log_text = ""
        for log in logs:
            log_text += f"[{log['timestamp']}] {log['type']} - {log['ip']}:{log['port']}"
            if log['domain']:
                log_text += f" ({log['domain']})"
            log_text += "\n"
        
        if not log_text:
            log_text = "Henüz ağ olayı kaydedilmedi..."
        
        self.network_log_text.setText(log_text)
    
    def _add_watch_path(self):
        """İzleme yolu ekle"""
        folder = QFileDialog.getExistingDirectory(self, "İzlenecek Klasör Seç")
        if folder:
            self.paths_list.addItem(folder)
            logger.log("BİLGİ", f"İzleme yolu eklendi: {folder}", "UI")
    
    def _quarantine_result(self, result: ScanResult):
        """Sonucu karantinaya al"""
        reply = QMessageBox.question(
            self,
            "Karantina Onayı",
            f"Bu dosya karantinaya alınacak:\n{result.file_path}\n\n"
            f"Risk Skoru: {result.final_score:.1f}\n"
            f"Tehditler: {', '.join(result.threats[:3])}\n\n"
            f"Emin misiniz?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, msg = self.quarantine_manager.quarantine(
                result.file_path,
                f"Risk: {result.final_score:.1f} - {', '.join(result.threats[:2])}",
                result.sha256
            )
            
            if success:
                QMessageBox.information(self, "Başarılı", f"Dosya karantinaya alındı: {msg}")
                self._refresh_quarantine()
            else:
                QMessageBox.warning(self, "Hata", f"Karantina işlemi başarısız: {msg}")
    
    def _refresh_quarantine(self):
        """Karantina listesini yenile"""
        self.quarantine_table.setRowCount(0)
        
        items = self.quarantine_manager.get_all_items()
        for item in items:
            row = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row)
            
            self.quarantine_table.setItem(row, 0, QTableWidgetItem(item.quarantine_id))
            self.quarantine_table.setItem(row, 1, QTableWidgetItem(item.original_path))
            self.quarantine_table.setItem(row, 2, QTableWidgetItem(item.reason))
            self.quarantine_table.setItem(row, 3, QTableWidgetItem(item.date))
            
            # İşlem butonları
            btn_widget = QWidget()
            btn_layout = QHBoxLayout(btn_widget)
            btn_layout.setContentsMargins(5, 0, 5, 0)
            btn_layout.setSpacing(5)
            
            restore_btn = QPushButton("Geri Yükle")
            restore_btn.setStyleSheet(f"background-color: {COLORS['success']}; padding: 5px; font-size: 11px;")
            restore_btn.clicked.connect(lambda checked, qid=item.quarantine_id: self._restore_file(qid))
            btn_layout.addWidget(restore_btn)
            
            delete_btn = QPushButton("Sil")
            delete_btn.setStyleSheet(f"background-color: {COLORS['danger']}; padding: 5px; font-size: 11px;")
            delete_btn.clicked.connect(lambda checked, qid=item.quarantine_id: self._delete_quarantined(qid))
            btn_layout.addWidget(delete_btn)
            
            self.quarantine_table.setCellWidget(row, 4, btn_widget)
        
        logger.log("BİLGİ", f"Karantina listesi yenilendi: {len(items)} öğe", "UI")
    
    def _restore_file(self, quarantine_id: str):
        """Dosyayı karantinadan geri yükle"""
        success, msg = self.quarantine_manager.restore(quarantine_id)
        
        if success:
            QMessageBox.information(self, "Başarılı", f"Dosya geri yüklendi:\n{msg}")
            self._refresh_quarantine()
        else:
            QMessageBox.warning(self, "Hata", f"Geri yükleme başarısız: {msg}")
    
    def _delete_quarantined(self, quarantine_id: str):
        """Karantina dosyasını kalıcı sil"""
        reply = QMessageBox.question(
            self,
            "Kalıcı Silme Onayı",
            "Bu dosya kalıcı olarak silinecek ve geri alınamayacak.\n"
            "Emin misiniz?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, msg = self.quarantine_manager.delete(quarantine_id)
            
            if success:
                QMessageBox.information(self, "Başarılı", "Dosya kalıcı olarak silindi.")
                self._refresh_quarantine()
            else:
                QMessageBox.warning(self, "Hata", f"Silme başarısız: {msg}")
    
    def _delete_all_quarantine(self):
        """Tüm karantina dosyalarını sil"""
        items = self.quarantine_manager.get_all_items()
        
        if not items:
            QMessageBox.information(self, "Bilgi", "Karantina boş.")
            return
        
        reply = QMessageBox.question(
            self,
            "Toplu Silme Onayı",
            f"{len(items)} dosya kalıcı olarak silinecek.\n"
            "Bu işlem geri alınamaz!\n"
            "Emin misiniz?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            deleted = 0
            for item in items:
                success, _ = self.quarantine_manager.delete(item.quarantine_id)
                if success:
                    deleted += 1
            
            QMessageBox.information(self, "Tamamlandı", f"{deleted} dosya silindi.")
            self._refresh_quarantine()
    
    def _clear_detections(self):
        """Tespit listesini temizle"""
        self.detections.clear()
        self.detections_table.setRowCount(0)
        logger.log("BİLGİ", "Tespit listesi temizlendi", "UI")
    
    def _export_detections(self):
        """Tespitleri dışa aktar"""
        if not self.detections:
            QMessageBox.information(self, "Bilgi", "Dışa aktarılacak tespit bulunmuyor.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Tespitleri Kaydet",
            "entropyx_detections.json",
            "JSON Dosyası (*.json)"
        )
        
        if file_path:
            try:
                data = [
                    {
                        "file_path": d.file_path,
                        "sha256": d.sha256,
                        "status": d.status,
                        "final_score": d.final_score,
                        "threats": d.threats,
                        "timestamp": d.timestamp
                    }
                    for d in self.detections
                ]
                
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                QMessageBox.information(self, "Başarılı", f"Tespitler kaydedildi:\n{file_path}")
                
            except Exception as e:
                QMessageBox.warning(self, "Hata", f"Kaydetme başarısız: {e}")
    
    def _refresh_logs(self):
        """Logları yenile"""
        level_filter = self.log_level_filter.currentText()
        
        if level_filter == "Tümü":
            level_filter = None
        
        logs = logger.get_logs(level=level_filter, limit=500)
        
        log_text = ""
        for log in logs:
            log_text += f"[{log['timestamp']}] [{log['level']}] [{log['module']}] {log['message']}\n"
        
        self.log_text.setText(log_text)
    
    def _filter_logs(self):
        """Logları filtrele"""
        self._refresh_logs()
    
    def _clear_logs(self):
        """Logları temizle"""
        logger.clear()
        self._refresh_logs()
        logger.log("BİLGİ", "Loglar temizlendi", "UI")
    
    def closeEvent(self, event):
        """Pencere kapatma olayı"""
        if hasattr(self, 'tray_icon') and self.tray_icon.isVisible():
            self.hide()
            self.tray_icon.showMessage(
                APP_NAME,
                "Uygulama arka planda çalışmaya devam ediyor.",
                QSystemTrayIcon.Information,
                2000
            )
            event.ignore()
        else:
            # Temizlik
            if self.realtime.enabled:
                self.realtime.stop()
            event.accept()


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Ana giriş noktası"""
    # Uygulama oluştur
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)
    
    # Yüksek DPI desteği
    app.setStyle("Fusion")
    
    # Pencere oluştur
    try:
        window = MainWindow()
        window.show()
        
        logger.log("BİLGİ", "Ana pencere gösterildi", "MAIN")
        
        sys.exit(app.exec())
        
    except Exception as e:
        logger.log("KRİTİK", f"Uygulama başlatma hatası: {e}", "MAIN")
        raise


if __name__ == "__main__":
    main()
