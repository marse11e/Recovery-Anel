#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import threading
import time
import random
import platform
import struct
import queue
import logging
from datetime import datetime, timedelta
import multiprocessing
import pwd
import grp
import math
import traceback

from PyQt5 import QtCore, QtGui, QtWidgets

try:
    import pytsk3
except ImportError:
    pytsk3 = None

# Порог для большого устройства (в байтах, ~500 МБ)
LARGE_DISK_THRESHOLD = 500 * 1024 * 1024

SIGNATURES = [
    {'ext': 'jpg', 'start': b'\xff\xd8', 'end': b'\xff\xd9'},
    {'ext': 'png', 'start': b'\x89PNG\r\n\x1a\n', 'end': b'IEND\xaeB`\x82'},
    {'ext': 'gif', 'start': b'GIF89a', 'end': b'\x3B'},
    {'ext': 'pdf', 'start': b'%PDF-', 'end': b'%%EOF'},
    {'ext': 'docx', 'start': b'PK\x03\x04', 'end': b'PK\x05\x06'},
    {'ext': 'xlsx', 'start': b'PK\x03\x04', 'end': b'PK\x05\x06'},
    {'ext': 'mp4', 'start': b'\x00\x00\x00\x18ftyp', 'end': None},
    {'ext': 'zip', 'start': b'PK\x03\x04', 'end': b'PK\x05\x06'},
    {'ext': 'txt', 'start': b'', 'end': None},
    {'ext': 'doc', 'start': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'end': None},
    {'ext': 'mp3', 'start': b'ID3', 'end': None},
    {'ext': 'avi', 'start': b'RIFF', 'end': None},
    {'ext': 'wav', 'start': b'RIFF', 'end': None},
    {'ext': 'exe', 'start': b'MZ', 'end': None},
    {'ext': 'bmp', 'start': b'BM', 'end': None},
    # Дополнительные форматы
    {'ext': 'psd', 'start': b'8BPS', 'end': None},
    {'ext': 'tiff', 'start': b'II*\x00', 'end': None},
    {'ext': 'tiff', 'start': b'MM\x00*', 'end': None},
    {'ext': 'svg', 'start': b'<?xml', 'end': b'</svg>'},
    {'ext': 'webp', 'start': b'RIFF', 'end': None},
    {'ext': 'mov', 'start': b'\x00\x00\x00\x14ftyp', 'end': None},
    {'ext': 'ppt', 'start': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'end': None},
    {'ext': 'pptx', 'start': b'PK\x03\x04', 'end': b'PK\x05\x06'},
    {'ext': 'epub', 'start': b'PK\x03\x04', 'end': b'PK\x05\x06'},
    {'ext': 'rar', 'start': b'Rar!\x1A\x07\x00', 'end': None},
]

# Настройка логирования с использованием очереди для многопоточности


class QueueHandler(logging.Handler):
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(record)


def setup_logging(log_queue):
    handler = QueueHandler(log_queue)
    logger = logging.getLogger('recovery')
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


def get_available_disks():
    disks = []
    if sys.platform == "win32":
        import string
        from ctypes import windll
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                disks.append(f"{letter}:\\")
            bitmask >>= 1
    else:
        dev_dir = '/dev'
        if os.path.exists(dev_dir):
            for device in os.listdir(dev_dir):
                if device.startswith("sd") or device.startswith("nvme"):
                    disks.append(os.path.join(dev_dir, device))
    return disks


def determine_fs_type(device_path):
    try:
        with open(device_path, 'rb') as f:
            boot_sector = f.read(512)
            if boot_sector[3:11] == b'NTFS    ':
                return "NTFS"
            if boot_sector[82:90] == b'FAT32   ':
                return "FAT32"
        with open(device_path, 'rb') as f:
            f.seek(1024)
            sb = f.read(1024)
            magic = struct.unpack("<H", sb[56:58])[0]
            if magic == 0xEF53:
                return "ext4"
    except Exception as e:
        print(f"Ошибка определения ФС: {e}")
    return "Unknown"


def scan_segment(args):
    device_path, offset, length, overlap, stop_event, pause_event, signatures = args
    if stop_event.is_set():
        return []
    results = []
    try:
        with open(device_path, 'rb') as f:
            f.seek(offset)
            buffer = f.read(length + overlap)
        for sig in signatures:
            if stop_event.is_set():
                break
            while pause_event.is_set():
                time.sleep(0.1)
            start_sig = sig['start']
            end_sig = sig['end']
            pos = 0
            while True:
                start_index = buffer.find(start_sig, pos)
                if start_index == -1:
                    break
                if end_sig:
                    end_index = buffer.find(end_sig, start_index)
                    if end_index == -1:
                        break
                    end_index += len(end_sig)
                else:
                    end_index = start_index + 1024 * 1024
                file_size = end_index - start_index
                auto_name = f"recovered_{sig['ext']}_{offset+start_index}_{random.randint(1000, 9999)}.{sig['ext']}"
                file_item = {
                    'name': auto_name,
                    'type': sig['ext'].upper(),
                    'size': file_size,
                    'status': 'Deleted',
                    'deleted_date': 'N/A',
                    'data_offset': offset + start_index,
                    'data_end': offset + end_index,
                    'recovery_status': 'Fully' if file_size > 0 else 'Impossible'
                }
                results.append(file_item)
                pos = end_index
    except Exception:
        pass
    return results


class FileRecoveryEngine(QtCore.QObject):
    progressChanged = QtCore.pyqtSignal(int)
    logMessage = QtCore.pyqtSignal(str)
    scanFinished = QtCore.pyqtSignal(list)
    recoveryFinished = QtCore.pyqtSignal()
    rootWarningNeeded = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        # Используем общие события для многопроцессорной обработки
        self.stop_event = multiprocessing.Event()
        self.pause_event = multiprocessing.Event()
        self.log_queue = multiprocessing.Queue()
        self.logger = setup_logging(self.log_queue)
        self.log_timer = QtCore.QTimer()
        self.log_timer.timeout.connect(self._process_logs)
        self.log_timer.start(100)  # Проверка логов каждые 100 мс
        self.device_requires_root = False
        self.root_warning_shown = False

    def _process_logs(self):
        while not self.log_queue.empty():
            try:
                record = self.log_queue.get(block=False)
                self.logMessage.emit(record.getMessage())
            except queue.Empty:
                break

    def log(self, message):
        self.logger.info(message)

    # Добавлен новый метод для проверки прав доступа к устройству
    def check_device_permissions(self, device_path):
        # Не проверяем для Windows
        if sys.platform == 'win32':
            return True

        self.device_requires_root = False

        # Проверка прав на чтение устройства
        try:
            # Пробуем открыть устройство для чтения
            with open(device_path, 'rb') as f:
                f.read(1)  # Читаем 1 байт для проверки
            return True
        except PermissionError:
            self.log(f"Не хватает прав для доступа к устройству {device_path}")
            self.device_requires_root = True

            # Проверяем, является ли текущий пользователь root
            if os.getuid() != 0:
                self.log(
                    "Для доступа к этому устройству требуются привилегии root")
                if not self.root_warning_shown:
                    self.rootWarningNeeded.emit()
                    self.root_warning_shown = True
            return False
        except Exception as e:
            self.log(f"Ошибка при проверке доступа к устройству: {e}")
            return False

    def open_disk_direct(self, device_path):
        try:
            self.log(f"Открытие устройства {device_path}...")

            # Проверяем права доступа
            if not self.check_device_permissions(device_path):
                if self.device_requires_root:
                    self.log(
                        "Для доступа к устройству требуются права root. Запустите программу через sudo.")
                return False

            time.sleep(0.5)
            return True
        except Exception as e:
            self.log(f"Ошибка открытия устройства: {e}")
            return False

    def determine_filesystem(self, device_path):
        self.log("Определение типа файловой системы...")
        fs = determine_fs_type(device_path)
        self.log(f"Определена файловая система: {fs}")
        return fs

    def recursive_scan(self, fs, directory, results, path="/"):
        for entry in directory:
            if self.stop_event.is_set():
                return
            while self.pause_event.is_set():
                time.sleep(0.1)
            if entry.info.name.name in [b".", b".."]:
                continue
            try:
                name = entry.info.name.name.decode("utf-8")
            except Exception:
                name = str(entry.info.name.name)
            if entry.info.meta is None:
                continue
            full_path = os.path.join(path, name)
            if entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                data_type = ""
                filename = entry.info.name.name.decode()
                _, file_extension = os.path.splitext(filename)
                if entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_REG:
                    data_type = file_extension.lstrip('.').upper()
                elif entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR:
                    data_type = "Folder"
                accessed_time = datetime.fromtimestamp(
                    entry.info.meta.mtime) + timedelta(hours=5)
                file_item = {
                    'name': name,
                    'type': data_type,
                    'size': entry.info.meta.size,
                    'status': 'Deleted',
                    'deleted_date': accessed_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'mft_addr': entry.info.meta.addr,
                    'path': full_path,
                    'recovery_status': 'Fully' if entry.info.meta.size > 0 else 'Impossible'
                }
                results.append(file_item)
                self.log(f"Найден удалённый файл/папка: {full_path}")
            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    sub_directory = entry.as_directory()
                    self.recursive_scan(fs, sub_directory, results, full_path)
                except Exception as e:
                    self.log(f"Ошибка при обходе каталога {full_path}: {e}")

    def scan_with_pytsk3(self, device_path):
        self.log("Сканирование с использованием pytsk3...")
        results = []
        try:
            img = pytsk3.Img_Info(device_path)
            fs = pytsk3.FS_Info(img)
            root_dir = fs.open_dir(path="/")
            self.recursive_scan(fs, root_dir, results)
        except Exception as e:
            self.log(f"Ошибка сканирования: {e}")
        return results

    # Улучшенная функция сканирования по сигнатурам с лучшей обработкой многопроцессности
    def scan_by_signature(self):
        """Сканирование диска по сигнатурам файлов."""
        self.log("Начало сканирования по сигнатурам...")
        
        # Проверяем, что устройство установлено
        if not self.current_device or not os.path.exists(self.current_device):
            self.log("Ошибка: устройство не найдено или не выбрано")
            return []
        
        all_found_files = []
        
        try:
            # Получаем размер файла устройства
            file_size = os.path.getsize(self.current_device)
            self.log(f"Размер диска: {file_size} байт")
            
            # Для больших дисков используем мультипроцессинг
            if file_size > self.LARGE_DISK_THRESHOLD:
                self.log("Обнаружен большой диск. Используем многопроцессное сканирование.")
                # Определяем количество ядер и оптимальный размер сегмента
                num_cores = min(multiprocessing.cpu_count(), 8)  # Не более 8 процессов
                segment_size = math.ceil(file_size / num_cores)
                
                # Создаем пул процессов
                with multiprocessing.Pool(processes=num_cores) as pool:
                    # Подготавливаем сегменты для сканирования
                    segments = []
                    for i in range(num_cores):
                        start = i * segment_size
                        end = min((i + 1) * segment_size, file_size)
                        segments.append((self.current_device, start, end, self.signatures))
                    
                    # Отображаем прогресс-бар
                    self.progressBar.setMaximum(100)
                    self.progressBar.setValue(0)
                    
                    # Запускаем многопроцессное сканирование
                    self.log(f"Запуск {num_cores} процессов для сканирования...")
                    results = []
                    
                    # Используем apply_async для асинхронного выполнения
                    for segment in segments:
                        result = pool.apply_async(self._scan_segment, segment)
                        results.append(result)
                    
                    # Отслеживаем завершение процессов и обновляем прогресс
                    total_segments = len(segments)
                    completed = 0
                    while completed < total_segments:
                        completed = sum(1 for r in results if r.ready())
                        progress = int((completed / total_segments) * 100)
                        self.progressBar.setValue(progress)
                        self.log(f"Прогресс сканирования: {progress}%", update=True)
                        QtWidgets.QApplication.processEvents()
                        time.sleep(0.5)
                    
                    # Собираем результаты
                    for result in results:
                        segment_files = result.get()
                        all_found_files.extend(segment_files)
            else:
                # Для маленьких дисков сканируем в одном процессе
                self.log("Стандартное сканирование в одном процессе.")
                self.progressBar.setMaximum(100)
                
                # Сканируем весь диск одним процессом
                all_found_files = self._scan_segment(self.current_device, 0, file_size, self.signatures)
                self.progressBar.setValue(100)
            
            self.log(f"Сканирование завершено. Найдено {len(all_found_files)} файлов")
            
        except Exception as e:
            self.log(f"Ошибка сканирования: {e}")
            self.log(f"Трассировка: {traceback.format_exc()}")
        
        return all_found_files

    def scan_disk(self, device_path, deep_scan=False):
        self.stop_event.clear()
        self.pause_event.clear()
        self.log(f"Начало сканирования диска: {device_path}")
        fs_type = self.determine_filesystem(device_path)
        results = []
        total_size = os.path.getsize(device_path)
        try:
            if not deep_scan and pytsk3 is not None and fs_type in ["NTFS", "FAT32", "ext4"]:
                # Быстрое сканирование по метаданным
                self.log("Выполняется быстрое сканирование по метаданным...")
                results = self.scan_with_pytsk3(device_path)
            else:
                # Глубокое сканирование включает оба метода
                if deep_scan:
                    self.log("Выполняется глубокое сканирование...")
                else:
                    self.log("Выполняется сканирование по сигнатурам...")
                
                results = self.scan_by_signature()
                
                # Добавляем результаты из pytsk3, если доступно
                if deep_scan and pytsk3 and fs_type in ["NTFS", "FAT32", "ext4"]:
                    self.log("Дополняем сканирование метаданными...")
                    pytsk_results = self.scan_with_pytsk3(device_path)
                    # Объединяем результаты, избегая дубликатов
                    existing_paths = set(r.get('path', '') for r in results)
                    for r in pytsk_results:
                        if r.get('path', '') not in existing_paths:
                            results.append(r)
                            existing_paths.add(r.get('path', ''))
        except Exception as e:
            self.log(f"Ошибка при сканировании: {e}")
        
        self.log(f"Сканирование завершено. Найдено {len(results)} файлов/папок.")
        self.progressChanged.emit(100)
        self.scanFinished.emit(results)

    def recover_files(self, files, output_dir, device_path):
        self.log("Начало восстановления файлов...")
        recovered_count = 0
        
        # Обработка прав доступа с учетом платформы
        is_windows = sys.platform == 'win32'
        
        if not is_windows:
            # Получаем UID и GID текущего пользователя
            current_uid = os.getuid()
            current_gid = os.getgid()
            
            # Если программа запущена от root, пытаемся определить реального пользователя
            effective_uid = current_uid
            effective_gid = current_gid
            
            # Проверяем, запущена ли программа с sudo
            sudo_uid = os.environ.get('SUDO_UID')
            sudo_gid = os.environ.get('SUDO_GID')
            
            if current_uid == 0 and sudo_uid is not None:
                # Если запущено через sudo, используем реального пользователя
                effective_uid = int(sudo_uid)
                effective_gid = int(sudo_gid) if sudo_gid else current_gid
                try:
                    username = pwd.getpwuid(effective_uid).pw_name
                    self.log(f"Программа запущена от root, но восстановление будет для пользователя: {username}")
                except:
                    self.log("Программа запущена от root, используется пользователь из SUDO_UID")
            else:
                # Обычный пользователь или root без sudo
                try:
                    username = pwd.getpwuid(current_uid).pw_name
                    self.log(f"Восстановление будет производиться для пользователя: {username}")
                except:
                    self.log("Не удалось определить имя текущего пользователя")
        else:
            self.log("Windows: особая обработка прав доступа не требуется")
            effective_uid = None
            effective_gid = None
        
        try:
            with open(device_path, 'rb') as disk:
                for file in files:
                    if self.stop_event.is_set():
                        self.log("Остановка восстановления.")
                        break
                    
                    # Восстанавливаем файл по смещению в данных
                    if 'data_offset' in file:
                        try:
                            disk.seek(file['data_offset'])
                            size = file['data_end'] - file['data_offset']
                            data = disk.read(size)
                            
                            # Создаем полный путь к файлу для восстановления
                            out_path = os.path.join(output_dir, file['name'])
                            dir_path = os.path.dirname(out_path)
                            
                            # Создаем директории с правильными правами доступа
                            if not os.path.exists(dir_path):
                                os.makedirs(dir_path, exist_ok=True, mode=0o775 if not is_windows else 0o777)
                                # Меняем владельца директории только для Linux/Unix
                                if not is_windows and effective_uid is not None:
                                    try:
                                        os.chown(dir_path, effective_uid, effective_gid)
                                    except Exception as e:
                                        self.log(f"Предупреждение: не удалось изменить владельца директории {dir_path}: {e}")
                            
                            # Записываем файл
                            with open(out_path, 'wb') as out_file:
                                out_file.write(data)
                            
                            # Устанавливаем расширенные права и владельца файла
                            try:
                                os.chmod(out_path, 0o664 if not is_windows else 0o666)
                                if not is_windows and effective_uid is not None:
                                    os.chown(out_path, effective_uid, effective_gid)
                            except Exception as e:
                                self.log(f"Предупреждение: не удалось установить права для {out_path}: {e}")
                            
                            recovered_count += 1
                            self.log(f"Файл восстановлен: {out_path} ({size} байт)")
                        except Exception as e:
                            self.log(f"Ошибка восстановления {file['name']}: {e}")
                    
                    # Восстанавливаем файл по MFT-записи
                    elif 'mft_addr' in file and file['mft_addr']:
                        try:
                            img = pytsk3.Img_Info(device_path)
                            fs = pytsk3.FS_Info(img)
                            file_entry = fs.open_meta(file['mft_addr'])
                            size = file_entry.info.meta.size
                            
                            if size <= 0:
                                self.log(f"Пропуск файла {file['name']}: недопустимый размер.")
                                continue
                                
                            data = file_entry.read_random(0, size)
                            out_path = os.path.join(output_dir, file['path'].lstrip('/'))
                            dir_path = os.path.dirname(out_path)
                            
                            # Создаем директории с правильными правами доступа
                            if not os.path.exists(dir_path):
                                os.makedirs(dir_path, exist_ok=True, mode=0o775 if not is_windows else 0o777)
                                # Меняем владельца директории только для Linux/Unix
                                if not is_windows and effective_uid is not None:
                                    try:
                                        os.chown(dir_path, effective_uid, effective_gid)
                                    except Exception as e:
                                        self.log(f"Предупреждение: не удалось изменить владельца директории {dir_path}: {e}")
                            
                            # Записываем файл и устанавливаем права
                            with open(out_path, 'wb') as f:
                                f.write(data)
                            
                            # Устанавливаем расширенные права и владельца файла
                            try:
                                os.chmod(out_path, 0o664 if not is_windows else 0o666)
                                if not is_windows and effective_uid is not None:
                                    os.chown(out_path, effective_uid, effective_gid)
                            except Exception as e:
                                self.log(f"Предупреждение: не удалось установить права для {out_path}: {e}")
                            
                            recovered_count += 1
                            self.log(f"Файл восстановлен: {out_path} ({size} байт)")
                        except Exception as e:
                            self.log(f"Ошибка восстановления {file['name']}: {e}")
                    
                    # Восстанавливаем директорию
                    elif file.get('type') == "Folder":
                        try:
                            out_path = os.path.join(output_dir, file['path'].lstrip('/'))
                            os.makedirs(out_path, exist_ok=True, mode=0o775 if not is_windows else 0o777)
                            
                            # Меняем владельца директории только для Linux/Unix
                            if not is_windows and effective_uid is not None:
                                try:
                                    os.chown(out_path, effective_uid, effective_gid)
                                except Exception as e:
                                    self.log(f"Предупреждение: не удалось изменить владельца директории {out_path}: {e}")
                            
                            recovered_count += 1
                            self.log(f"Папка восстановлена: {out_path}")
                        except Exception as e:
                            self.log(f"Ошибка восстановления папки {file['name']}: {e}")
            
            # Обеспечиваем правильные права на корневую директорию восстановления
            if not is_windows:
                try:
                    os.chmod(output_dir, 0o775)
                    if effective_uid is not None:
                        os.chown(output_dir, effective_uid, effective_gid)
                    
                    # Рекурсивно устанавливаем права на все восстановленные файлы и папки
                    self.log("Установка прав доступа на все восстановленные файлы...")
                    for root, dirs, files in os.walk(output_dir):
                        for dir_name in dirs:
                            try:
                                dir_path = os.path.join(root, dir_name)
                                os.chmod(dir_path, 0o775)
                                if effective_uid is not None:
                                    os.chown(dir_path, effective_uid, effective_gid)
                            except Exception:
                                pass
                        
                        for file_name in files:
                            try:
                                file_path = os.path.join(root, file_name)
                                os.chmod(file_path, 0o664)
                                if effective_uid is not None:
                                    os.chown(file_path, effective_uid, effective_gid)
                            except Exception:
                                pass
                except Exception as e:
                    self.log(f"Предупреждение: не удалось установить права для директории восстановления: {e}")
            else:
                try:
                    # В Windows устанавливаем максимальные права
                    os.chmod(output_dir, 0o777)
                    # Для Windows используем другой метод установки полных прав (если доступно)
                    try:
                        import win32security
                        import ntsecuritycon
                        import win32con
                        
                        self.log("Установка полных прав Windows на директорию восстановления...")
                        # Пытаемся установить полные права для всех пользователей
                        # (это сложнее реализовать, поэтому делаем только базовую установку)
                    except ImportError:
                        self.log("Модули win32security не найдены, используются стандартные права")
                        
                except Exception as e:
                    self.log(f"Предупреждение при установке прав Windows: {e}")
                
            self.log(f"Восстановление завершено. Восстановлено: {recovered_count} файлов/папок.")
        except Exception as e:
            self.log(f"Глобальная ошибка восстановления: {e}")
            
        self.recoveryFinished.emit()

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Инструмент восстановления файлов")
        self.resize(1000, 600)
        self.engine = FileRecoveryEngine()
        self.current_device = None
        self.all_files = []
        self.setup_ui()
        self.setup_connections()

    def setup_ui(self):
        centralWidget = QtWidgets.QWidget()
        mainLayout = QtWidgets.QVBoxLayout()

        topPanel = QtWidgets.QHBoxLayout()
        self.deviceCombo = QtWidgets.QComboBox()
        disks = get_available_disks()
        if not disks:
            disks = ["Нет дисков"]
        self.deviceCombo.addItems(disks)
        self.scanTypeCombo = QtWidgets.QComboBox()
        self.scanTypeCombo.addItems(["Быстрое (метаданные)", "Глубокое (сигнатуры + метаданные)"])
        self.scanButton = QtWidgets.QPushButton("Сканировать диск")
        self.stopButton = QtWidgets.QPushButton("Остановить")
        self.pauseButton = QtWidgets.QPushButton("Пауза")
        self.searchEdit = QtWidgets.QLineEdit()
        self.searchEdit.setPlaceholderText("Поиск по имени или пути...")
        topPanel.addWidget(QtWidgets.QLabel("Устройство:"))
        topPanel.addWidget(self.deviceCombo)
        topPanel.addWidget(QtWidgets.QLabel("Тип сканирования:"))
        topPanel.addWidget(self.scanTypeCombo)
        topPanel.addWidget(self.scanButton)
        topPanel.addWidget(self.stopButton)
        topPanel.addWidget(self.pauseButton)
        topPanel.addWidget(self.searchEdit)
        topPanel.addStretch()

        tabWidget = QtWidgets.QTabWidget()
        mainTab = QtWidgets.QWidget()
        mainTabLayout = QtWidgets.QVBoxLayout()

        filterGroup = QtWidgets.QGroupBox("Фильтры и сортировка")
        filterLayout = QtWidgets.QHBoxLayout()
        self.filterType = QtWidgets.QComboBox()
        self.filterType.addItem("Все типы")
        self.filterType.addItems(["JPG", "PNG", "GIF", "PDF", "DOCX", "XLSX", "MP4", "ZIP", "TXT", "DOC", "MP3", "AVI", "WAV", "EXE", "BMP", "Folder"])
        self.filterSize = QtWidgets.QLineEdit()
        self.filterSize.setPlaceholderText("Размер (байт)")
        self.filterStatus = QtWidgets.QComboBox()
        self.filterStatus.addItem("Все статусы")
        self.filterStatus.addItem("Deleted")
        self.sortNameButton = QtWidgets.QPushButton("Сортировать по имени")
        self.sortSizeButton = QtWidgets.QPushButton("Сортировать по размеру")
        self.sortDateButton = QtWidgets.QPushButton("Сортировать по дате")
        filterLayout.addWidget(QtWidgets.QLabel("Тип:"))
        filterLayout.addWidget(self.filterType)
        filterLayout.addWidget(QtWidgets.QLabel("Размер:"))
        filterLayout.addWidget(self.filterSize)
        filterLayout.addWidget(QtWidgets.QLabel("Статус:"))
        filterLayout.addWidget(self.filterStatus)
        filterLayout.addWidget(self.sortNameButton)
        filterLayout.addWidget(self.sortSizeButton)
        filterLayout.addWidget(self.sortDateButton)
        filterGroup.setLayout(filterLayout)

        self.fileTable = QtWidgets.QTableWidget(0, 6)
        self.fileTable.setHorizontalHeaderLabels(["Имя", "Тип", "Размер", "Статус", "Дата удаления", "Статус восстановления"])
        self.fileTable.horizontalHeader().setStretchLastSection(True)
        self.fileTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.fileTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.treeWidget = QtWidgets.QTreeWidget()
        self.treeWidget.setHeaderLabels(["Путь", "Тип", "Размер"])
        self.treeWidget.setColumnWidth(0, 400)

        previewGroup = QtWidgets.QGroupBox("Предпросмотр")
        previewLayout = QtWidgets.QVBoxLayout()
        self.previewLabel = QtWidgets.QLabel("Предпросмотр не доступен")
        self.previewLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.infoText = QtWidgets.QTextEdit()
        self.infoText.setReadOnly(True)
        previewLayout.addWidget(self.previewLabel)
        previewLayout.addWidget(self.infoText)
        previewGroup.setLayout(previewLayout)

        controlPanel = QtWidgets.QHBoxLayout()
        self.recoverButton = QtWidgets.QPushButton("Восстановить")
        self.rescanButton = QtWidgets.QPushButton("Сканировать заново")
        controlPanel.addWidget(self.recoverButton)
        controlPanel.addWidget(self.rescanButton)
        controlPanel.addStretch()

        self.progressBar = QtWidgets.QProgressBar()
        self.progressBar.setValue(0)

        self.logText = QtWidgets.QTextEdit()
        self.logText.setReadOnly(True)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        leftWidget = QtWidgets.QWidget()
        leftLayout = QtWidgets.QVBoxLayout()
        leftLayout.addWidget(filterGroup)
        leftLayout.addWidget(self.fileTable)
        leftWidget.setLayout(leftLayout)
        splitter.addWidget(leftWidget)
        splitter.addWidget(previewGroup)
        splitter.setSizes([600, 400])
        mainTabLayout.addLayout(topPanel)
        mainTabLayout.addWidget(splitter)
        mainTabLayout.addWidget(self.progressBar)
        mainTabLayout.addLayout(controlPanel)
        mainTab.setLayout(mainTabLayout)

        tabWidget.addTab(mainTab, "Таблица")
        tabWidget.addTab(self.treeWidget, "Дерево")
        tabWidget.addTab(self.logText, "Логи")

        mainLayout.addWidget(tabWidget)
        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)
        self.setAcceptDrops(True)

        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #1e1e1e; color: #d4d4d4; font-family: Arial; font-size: 12pt; }
            QLabel, QGroupBox { color: #d4d4d4; }
            QPushButton { background-color: #3c3c3c; border: 1px solid #555; border-radius: 4px; padding: 6px 12px; color: #d4d4d4; }
            QPushButton:hover { background-color: #505050; }
            QPushButton:pressed { background-color: #2d2d2d; }
            QLineEdit, QComboBox, QTextEdit, QTableWidget { background-color: #252526; border: 1px solid #3c3c3c; border-radius: 4px; color: #d4d4d4; }
            QTableWidget { gridline-color: #3c3c3c; }
            QHeaderView::section { background-color: #2d2d30; padding: 4px; border: 1px solid #3c3c3c; }
            QProgressBar { background-color: #3c3c3c; border: 1px solid #3c3c3c; text-align: center; color: #d4d4d4; }
            QProgressBar::chunk { background-color: #007acc; }
            QTextEdit { background-color: #1e1e1e; }
            QTreeWidget { background-color: #252526; border: 1px solid #3c3c3c; color: #d4d4d4; }
        """)

    def setup_connections(self):
        self.scanButton.clicked.connect(self.start_scan)
        self.stopButton.clicked.connect(self.stop_scan)
        self.pauseButton.clicked.connect(self.toggle_pause)
        self.rescanButton.clicked.connect(self.start_scan)
        self.recoverButton.clicked.connect(self.recover_selected_files)
        self.engine.progressChanged.connect(self.progressBar.setValue)
        self.engine.logMessage.connect(self.append_log)
        self.engine.scanFinished.connect(self.update_file_table)
        self.engine.recoveryFinished.connect(self.on_recovery_finished)
        self.engine.rootWarningNeeded.connect(self.show_root_warning)
        self.fileTable.itemSelectionChanged.connect(self.show_preview)
        self.filterType.currentIndexChanged.connect(self.filter_table)
        self.filterStatus.currentIndexChanged.connect(self.filter_table)
        self.filterSize.textChanged.connect(self.filter_table)
        self.searchEdit.textChanged.connect(self.filter_table)
        self.sortNameButton.clicked.connect(lambda: self.sort_table(0))
        self.sortSizeButton.clicked.connect(lambda: self.sort_table(2))
        self.sortDateButton.clicked.connect(lambda: self.sort_table(4))

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            folder = urls[0].toLocalFile()
            if os.path.isdir(folder):
                self.append_log(f"Выбрана папка: {folder}")
                self.output_dir = folder

    def start_scan(self):
        self.fileTable.setRowCount(0)
        self.treeWidget.clear()
        self.progressBar.setValue(0)
        device = self.deviceCombo.currentText()
        self.current_device = device
        deep_scan = self.scanTypeCombo.currentText() == "Глубокое (сигнатуры + метаданные)"
        self.append_log(f"Сканирование устройства: {device} ({'глубокое' if deep_scan else 'быстрое'})")
        if not self.engine.open_disk_direct(device):
            self.append_log("Ошибка доступа!")
            return
        self.scanThread = threading.Thread(target=self.engine.scan_disk, args=(device, deep_scan))
        self.scanThread.start()

    def stop_scan(self):
        self.engine.stop_event.set()
        self.append_log("Остановка сканирования.")

    def toggle_pause(self):
        if self.engine.pause_event.is_set():
            self.engine.pause_event.clear()
            self.pauseButton.setText("Пауза")
            self.append_log("Сканирование возобновлено.")
        else:
            self.engine.pause_event.set()
            self.pauseButton.setText("Возобновить")
            self.append_log("Сканирование приостановлено.")

    def update_file_table(self, files):
        self.all_files = files
        self.filter_table()
        self.update_tree()

    def filter_table(self):
        self.fileTable.setRowCount(0)
        type_filter = self.filterType.currentText()
        status_filter = self.filterStatus.currentText()
        size_filter = self.filterSize.text().strip()
        search_text = self.searchEdit.text().strip().lower()
        for file in self.all_files:
            if type_filter != "Все типы" and file['type'] != type_filter:
                continue
            if status_filter != "Все статусы" and file['status'] != status_filter:
                continue
            if size_filter:
                try:
                    if int(file['size']) < int(size_filter):
                        continue
                except ValueError:
                    pass
            if search_text and search_text not in file['name'].lower() and ('path' not in file or search_text not in file['path'].lower()):
                continue
            row = self.fileTable.rowCount()
            self.fileTable.insertRow(row)
            self.fileTable.setItem(row, 0, QtWidgets.QTableWidgetItem(file['name']))
            self.fileTable.setItem(row, 1, QtWidgets.QTableWidgetItem(file['type']))
            self.fileTable.setItem(row, 2, QtWidgets.QTableWidgetItem(str(file['size'])))
            self.fileTable.setItem(row, 3, QtWidgets.QTableWidgetItem(file['status']))
            self.fileTable.setItem(row, 4, QtWidgets.QTableWidgetItem(file['deleted_date']))
            self.fileTable.setItem(row, 5, QtWidgets.QTableWidgetItem(file['recovery_status']))

    def update_tree(self):
        self.treeWidget.clear()
        tree_dict = {}
        for file in self.all_files:
            path = file.get('path', file['name'])
            parts = path.strip('/').split('/')
            current = tree_dict
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = file
        def add_items(parent, items):
            for name, item in items.items():
                if isinstance(item, dict) and 'size' not in item:
                    tree_item = QtWidgets.QTreeWidgetItem(parent, [name, "Folder", ""])
                    add_items(tree_item, item)
                else:
                    QtWidgets.QTreeWidgetItem(parent, [name, item['type'], str(item['size'])])
        add_items(self.treeWidget, tree_dict)
        self.treeWidget.expandAll()

    def sort_table(self, column):
        self.fileTable.sortItems(column, QtCore.Qt.AscendingOrder)

    def show_preview(self):
        selected_items = self.fileTable.selectedItems()
        if not selected_items:
            return
        
        row = self.fileTable.currentRow()
        if row >= len(self.all_files):
            return
        
        file = self.all_files[row]
        preview_text = ""
        self.previewLabel.clear()
        
        # Отображаем информацию о файле даже если предпросмотр недоступен
        info_template = (
            f"Имя: {file['name']}\n"
            f"Устройство: {self.deviceCombo.currentText()}\n"
            f"Тип: {file.get('type', 'Неизвестно')}\n"
            f"Размер: {file.get('size', 0)} байт\n"
            f"MFT-адрес: {file.get('mft_addr', 'N/A')}\n"
            f"Статус: {file.get('status', 'N/A')}\n"
            f"Дата удаления: {file.get('deleted_date', 'N/A')}\n"
            f"Статус восстановления: {file.get('recovery_status', 'N/A')}\n"
        )
        
        # Получаем данные файла для предпросмотра
        preview_data = None
        if 'data_offset' in file and self.current_device and os.path.exists(self.current_device):
            try:
                with open(self.current_device, 'rb') as f:
                    f.seek(file['data_offset'])
                    # Ограничиваем размер данных для предпросмотра
                    read_size = min(1024 * 1024, file.get('size', 1024 * 10))  # Максимум 1 МБ или весь файл
                    preview_data = f.read(read_size)
            except Exception as e:
                preview_text = f"Ошибка чтения данных: {e}"
        elif 'mft_addr' in file and file['mft_addr'] and pytsk3 and self.current_device:
            try:
                img = pytsk3.Img_Info(self.current_device)
                fs = pytsk3.FS_Info(img)
                file_entry = fs.open_meta(file['mft_addr'])
                read_size = min(1024 * 1024, file.get('size', 0))  # Максимум 1 МБ
                if read_size > 0:
                    preview_data = file_entry.read_random(0, read_size)
            except Exception as e:
                preview_text = f"Ошибка чтения данных через MFT: {e}"
        
        if preview_data:
            # Определяем тип файла для правильного предпросмотра
            file_ext = os.path.splitext(file['name'])[1].lower()
            file_type = file.get('type', '').lower()
            
            # Обрабатываем изображения
            if file_ext in ['.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp', '.tiff'] or file_type in ['png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp', 'tiff']:
                image = QtGui.QImage()
                if image.loadFromData(preview_data):
                    # Масштабируем изображение с сохранением пропорций
                    pixmap = QtGui.QPixmap.fromImage(image)
                    label_size = self.previewLabel.size()
                    scaled_pixmap = pixmap.scaled(
                        label_size, 
                        QtCore.Qt.KeepAspectRatio, 
                        QtCore.Qt.SmoothTransformation
                    )
                    self.previewLabel.setPixmap(scaled_pixmap)
                    preview_text = "Изображение успешно загружено."
                else:
                    preview_text = "Невозможно отобразить изображение. Возможно, файл поврежден."
                    # Отображаем HEX данных изображения
                    preview_text += f"\n\nHEX данных (первые 100 байт):\n{preview_data[:100].hex()}"
            
            # Обрабатываем текстовые файлы
            elif file_ext in ['.txt', '.log', '.csv', '.xml', '.html', '.htm', '.js', '.css', '.json', '.py', '.c', '.cpp', '.h', '.java'] or file_type in ['txt', 'text']:
                try:
                    # Пробуем различные кодировки
                    encodings = ['utf-8', 'cp1251', 'latin-1', 'ascii']
                    decoded = False
                    
                    for encoding in encodings:
                        try:
                            text_content = preview_data.decode(encoding)
                            # Ограничиваем объем текста для отображения
                            if len(text_content) > 5000:
                                text_content = text_content[:5000] + "\n...(текст обрезан)..."
                            preview_text = f"Текстовое содержимое (кодировка {encoding}):\n\n{text_content}"
                            decoded = True
                            break
                        except UnicodeDecodeError:
                            continue
                    
                    if not decoded:
                        # Если не удалось декодировать как текст, отображаем в HEX
                        preview_text = "Не удалось декодировать как текст. Возможно, файл бинарный или использует другую кодировку."
                        preview_text += f"\n\nHEX данных (первые 200 байт):\n{preview_data[:200].hex()}"
                except Exception as e:
                    preview_text = f"Ошибка при обработке текста: {e}"
            
            # PDF файлы
            elif file_ext == '.pdf' or file_type == 'pdf':
                if preview_data.startswith(b'%PDF'):
                    preview_text = "PDF документ. Доступна только служебная информация.\n\n"
                    # Извлекаем некоторую метаинформацию PDF
                    try:
                        headers = preview_data[:1000].decode('latin-1', errors='ignore')
                        preview_text += f"Заголовок:\n{headers[:500]}"
                    except Exception:
                        preview_text += "Невозможно извлечь метаданные PDF."
                else:
                    preview_text = "Файл не соответствует формату PDF."
                
            # Документы Office
            elif file_ext in ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt'] or file_type in ['docx', 'xlsx', 'pptx', 'doc', 'xls', 'ppt']:
                preview_text = f"Документ Microsoft Office {file_ext[1:].upper()}. Предпросмотр недоступен."
                if preview_data[:4] == b'PK\x03\x04':  # Office XML
                    preview_text += "\n\nФайл в формате Office Open XML."
                elif preview_data[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':  # OLE
                    preview_text += "\n\nФайл в формате OLE/Compound Document."
                preview_text += f"\n\nHEX данных (первые 100 байт):\n{preview_data[:100].hex()}"
            
            # Архивы
            elif file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz'] or file_type in ['zip', 'rar', '7z', 'archive']:
                preview_text = f"Архив {file_ext[1:].upper()}. Предпросмотр содержимого недоступен."
                preview_text += f"\n\nHEX данных (первые 100 байт):\n{preview_data[:100].hex()}"
            
            # Аудио/видео файлы
            elif file_ext in ['.mp3', '.wav', '.mp4', '.avi', '.mov', '.mkv'] or file_type in ['mp3', 'wav', 'mp4', 'avi', 'mov', 'audio', 'video']:
                preview_text = f"Медиафайл {file_ext[1:].upper()}. Предпросмотр недоступен."
                preview_text += f"\n\nHEX данных (первые 100 байт):\n{preview_data[:100].hex()}"
            
            # Исполняемые файлы
            elif file_ext in ['.exe', '.dll', '.so'] or file_type in ['exe', 'binary']:
                preview_text = "Исполняемый файл. Предпросмотр недоступен."
                preview_text += f"\n\nHEX данных (первые 200 байт):\n{preview_data[:200].hex()}"
                
                # MZ заголовок для Windows EXE
                if preview_data[:2] == b'MZ':
                    preview_text += "\n\nФайл содержит корректный заголовок MZ (Windows EXE/DLL)."
                    
                    # Попытаемся извлечь информацию о версии, если есть
                    try:
                        version_info = ""
                        for i in range(len(preview_data) - 8):
                            if preview_data[i:i+8] == b'VS_VERSION_INFO':
                                version_info = preview_data[i:i+200].decode('utf-16le', errors='ignore')
                                break
                        if version_info:
                            preview_text += f"\n\nИнформация о версии:\n{version_info}"
                    except Exception:
                        pass
            
            # Для других неизвестных типов показываем HEX дамп
            else:
                preview_text = f"Бинарные данные {file_ext[1:] if file_ext else file_type}. Отображение первых 300 байт в HEX формате:\n\n"
                
                # Форматированный HEX дамп с адресами
                hex_dump = ""
                for i in range(0, min(300, len(preview_data)), 16):
                    hex_line = preview_data[i:i+16].hex(' ')
                    ascii_repr = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in preview_data[i:i+16]])
                    hex_dump += f"{i:04X}: {hex_line:<48} | {ascii_repr}\n"
                
                preview_text += hex_dump
        else:
            preview_text = "Предпросмотр недоступен. Не удалось получить данные файла."
        
        # Объединяем информацию о файле и результаты предпросмотра
        full_info = info_template + "\n\nПредпросмотр:\n" + preview_text
        self.infoText.setPlainText(full_info)

    def recover_selected_files(self):
        selected_rows = set(item.row() for item in self.fileTable.selectedItems())
        if not selected_rows:
            self.append_log("Файлы не выбраны.")
            return
        
        files_to_recover = [self.all_files[i] for i in selected_rows]
        
        if not hasattr(self, 'output_dir'):
            self.output_dir = QtWidgets.QFileDialog.getExistingDirectory(self, "Выберите папку")
        
        if not self.output_dir:
            self.append_log("Папка не выбрана!")
            return
        
        # Проверяем права доступа к выбранной директории
        if not os.access(self.output_dir, os.W_OK):
            try:
                # Пытаемся создать тестовый файл для проверки прав
                test_file = os.path.join(self.output_dir, ".test_write_access")
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
            except Exception as e:
                # Если нет прав на запись, предлагаем выбрать другую директорию
                self.append_log(f"Ошибка доступа к директории: {e}")
                msg = QtWidgets.QMessageBox()
                msg.setIcon(QtWidgets.QMessageBox.Warning)
                msg.setText("Нет прав доступа")
                msg.setInformativeText(f"У вас нет прав на запись в директорию {self.output_dir}. Выберите другую директорию.")
                msg.setWindowTitle("Ошибка доступа")
                msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
                msg.exec_()
                
                # Запрашиваем новую директорию
                self.output_dir = QtWidgets.QFileDialog.getExistingDirectory(self, "Выберите папку с правами записи")
                if not self.output_dir:
                    self.append_log("Восстановление отменено!")
                    return
        
        # Вычисляем общий размер выбранных файлов
        total_size = sum(f.get('size', 0) for f in files_to_recover)
        num_files = len(files_to_recover)
        
        # Запрашиваем подтверждение у пользователя
        confirm_msg = QtWidgets.QMessageBox()
        confirm_msg.setIcon(QtWidgets.QMessageBox.Question)
        confirm_msg.setText("Подтверждение восстановления")
        confirm_msg.setInformativeText(f"Будет восстановлено {num_files} файлов общим размером {total_size/1024/1024:.2f} МБ в директорию:\n{self.output_dir}\n\nПродолжить?")
        confirm_msg.setWindowTitle("Подтверждение")
        confirm_msg.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        confirm_msg.setDefaultButton(QtWidgets.QMessageBox.Yes)
        
        if confirm_msg.exec_() != QtWidgets.QMessageBox.Yes:
            self.append_log("Восстановление отменено пользователем.")
            return
        
        self.recoverButton.setEnabled(False)
        device = self.deviceCombo.currentText()
        
        # Запускаем восстановление в отдельном потоке
        self.append_log(f"Начинаем восстановление {num_files} файлов в {self.output_dir}")
        threading.Thread(target=self.engine.recover_files, args=(files_to_recover, self.output_dir, device)).start()

    def on_recovery_finished(self):
        self.append_log("Восстановление завершено.")
        self.fileTable.clearSelection()
        self.recoverButton.setEnabled(True)

    def append_log(self, message):
        # Создаем метку времени
        timestamp = time.strftime("[%H:%M:%S]", time.localtime())
        log_message = f"{timestamp} {message}"
        
        # Используем сигналы Qt для безопасного обновления GUI из других потоков
        QtCore.QMetaObject.invokeMethod(
            self.logText, 
            "append", 
            QtCore.Qt.QueuedConnection,
            QtCore.Q_ARG(str, log_message)
        )
        
        # Принудительно обрабатываем события для обновления интерфейса
        QtWidgets.QApplication.processEvents()

    # Добавляем метод отображения предупреждения о root-правах
    def show_root_warning(self):
        warning = QtWidgets.QMessageBox(self)
        warning.setIcon(QtWidgets.QMessageBox.Warning)
        warning.setWindowTitle("Требуются права администратора")
        warning.setText("Для доступа к устройству требуются права администратора (root)")
        warning.setInformativeText("Запустите программу с правами администратора (sudo) для полного доступа к устройству. Иначе восстановление может не сработать или восстановленные файлы будут недоступны для редактирования/удаления.")
        warning.setStandardButtons(QtWidgets.QMessageBox.Ok)
        warning.exec_()

def main():
    # Необходимо для правильной работы multiprocessing в Windows
    if sys.platform == 'win32':
        multiprocessing.freeze_support()
    
    # Устанавливаем метод запуска новых процессов
    multiprocessing.set_start_method('spawn', force=True)
    
    app = QtWidgets.QApplication(sys.argv)
    
    # Устанавливаем стиль приложения
    app.setStyle('Fusion')
    
    # Проверяем наличие необходимых библиотек
    if pytsk3 is None:
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Warning)
        msg.setText("Библиотека pytsk3 не установлена")
        msg.setInformativeText("Некоторые функции восстановления будут недоступны. Рекомендуется установить pytsk3 для полной функциональности.")
        msg.setWindowTitle("Предупреждение")
        msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msg.exec_()
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()