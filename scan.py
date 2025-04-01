#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import threading
import time
import random
import platform
import struct
from datetime import datetime, timedelta
import multiprocessing

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
    {'ext': 'mp4', 'start': b'\x00\x00\x00\x18ftyp', 'end': None},  # MP4 без явного конца
    {'ext': 'zip', 'start': b'PK\x03\x04', 'end': b'PK\x05\x06'},
]

# Функция для обнаружения доступных дисков
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

# Функция определения типа файловой системы
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

# Функция для сканирования сегмента диска по сигнатурам
def scan_segment(args):
    device_path, offset, length, overlap, stop_event, signatures = args
    if stop_event.is_set():
        return []
    results = []
    try:
        with open(device_path, 'rb') as f:
            f.seek(offset)
            buffer = f.read(length + overlap)
        for sig in signatures:
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
                    end_index = start_index + 1024 * 1024  # Фиксированный размер для файлов без конца
                file_size = end_index - start_index
                auto_name = f"recovered_{sig['ext']}_{offset+start_index}_{random.randint(1000,9999)}.{sig['ext']}"
                file_item = {
                    'name': auto_name,
                    'type': sig['ext'].upper(),
                    'size': file_size,
                    'status': 'Deleted',
                    'deleted_date': 'N/A',
                    'data_offset': offset + start_index,
                    'data_end': offset + end_index
                }
                results.append(file_item)
                pos = end_index
    except Exception:
        pass
    return results

# Класс для восстановления файлов
class FileRecoveryEngine(QtCore.QObject):
    progressChanged = QtCore.pyqtSignal(int)
    logMessage = QtCore.pyqtSignal(str)
    scanFinished = QtCore.pyqtSignal(list)
    recoveryFinished = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.stop_event = multiprocessing.Event()

    def open_disk_direct(self, device_path):
        try:
            self.logMessage.emit(f"Открытие устройства {device_path}...")
            time.sleep(0.5)
            return True
        except Exception as e:
            self.logMessage.emit(f"Ошибка открытия устройства: {e}")
            return False

    def determine_filesystem(self, device_path):
        self.logMessage.emit("Определение типа файловой системы...")
        fs = determine_fs_type(device_path)
        self.logMessage.emit(f"Определена файловая система: {fs}")
        return fs

    def recursive_scan(self, fs, directory, results, path="/"):
        for entry in directory:
            if self.stop_event.is_set():
                return
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
                    data_type = file_extension
                elif entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR:
                    data_type = "Folder."
                accessed_time = datetime.fromtimestamp(entry.info.meta.mtime) + timedelta(hours=5)
                file_item = {
                    'name': name,
                    'type': data_type,
                    'size': entry.info.meta.size,
                    'status': 'Deleted',
                    'deleted_date': accessed_time.strftime('%Y-%m-%d'),
                    'mft_addr': entry.info.meta.addr,
                    'path': full_path
                }
                results.append(file_item)
                self.logMessage.emit(f"Найден удалённый файл/папка: {full_path}")
            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    sub_directory = entry.as_directory()
                    self.recursive_scan(fs, sub_directory, results, full_path)
                except Exception as e:
                    self.logMessage.emit(f"Ошибка при обходе каталога {full_path}: {e}")

    def scan_with_pytsk3(self, device_path):
        self.logMessage.emit("Сканирование с использованием pytsk3...")
        results = []
        try:
            img = pytsk3.Img_Info(device_path)
            fs = pytsk3.FS_Info(img)
            root_dir = fs.open_dir(path="/")
            self.recursive_scan(fs, root_dir, results)
        except Exception as e:
            self.logMessage.emit(f"Ошибка сканирования: {e}")
        return results

    def scan_by_signature(self, device_path):
        self.logMessage.emit("Поиск файлов по сигнатурам...")
        results = []
        block_size = 1024 * 1024  # 1 МБ
        overlap = 1024
        file_size = os.path.getsize(device_path)
        if file_size > LARGE_DISK_THRESHOLD:
            self.logMessage.emit("Большой диск – параллельное сканирование...")
            pool = multiprocessing.Pool()
            segments = []
            seg_size = block_size * 10
            for offset in range(0, file_size, seg_size):
                length = seg_size if offset + seg_size < file_size else file_size - offset
                segments.append((device_path, offset, length, overlap, self.stop_event, SIGNATURES))
            pool_results = pool.map(scan_segment, segments)
            pool.close()
            pool.join()
            for seg in pool_results:
                results.extend(seg)
        else:
            try:
                with open(device_path, 'rb') as f:
                    offset = 0
                    buffer = b""
                    while not self.stop_event.is_set():
                        data = f.read(block_size)
                        if not data:
                            break
                        buffer += data
                        for sig in SIGNATURES:
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
                                file_size_found = end_index - start_index
                                auto_name = f"recovered_{sig['ext']}_{offset+start_index}_{random.randint(1000,9999)}.{sig['ext']}"
                                file_item = {
                                    'name': auto_name,
                                    'type': sig['ext'].upper(),
                                    'size': file_size_found,
                                    'status': 'Deleted',
                                    'deleted_date': 'N/A',
                                    'data_offset': offset + start_index,
                                    'data_end': offset + end_index
                                }
                                results.append(file_item)
                                self.logMessage.emit(f"Найден файл: {auto_name}")
                                pos = end_index
                        if len(buffer) > overlap:
                            buffer = buffer[-overlap:]
                        offset += block_size
            except Exception as e:
                self.logMessage.emit(f"Ошибка при поиске сигнатур: {e}")
        self.logMessage.emit("Сканирование по сигнатурам завершено.")
        return results

    def scan_disk(self, device_path):
        self.stop_event.clear()
        self.logMessage.emit(f"Начало сканирования диска: {device_path}")
        fs_type = self.determine_filesystem(device_path)
        results = []
        try:
            if pytsk3 is not None and fs_type in ["NTFS", "FAT32", "ext4"]:
                results = self.scan_with_pytsk3(device_path)
                if not results:
                    self.logMessage.emit("Структурированное сканирование не дало результатов. Переход к сигнатурам...")
                    results = self.scan_by_signature(device_path)
            else:
                results = self.scan_by_signature(device_path)
        except Exception as e:
            self.logMessage.emit(f"Ошибка при сканировании: {e}")
        self.logMessage.emit("Сканирование завершено.")
        self.scanFinished.emit(results)

    def recover_files(self, files, output_dir, device_path):
        self.logMessage.emit("Начало восстановления файлов...")
        try:
            with open(device_path, 'rb') as disk:
                for file in files:
                    if self.stop_event.is_set():
                        self.logMessage.emit("Остановка восстановления.")
                        break
                    if 'data_offset' in file:
                        try:
                            disk.seek(file['data_offset'])
                            size = file['data_end'] - file['data_offset']
                            data = disk.read(size)
                            out_path = os.path.join(output_dir, file['name'])
                            os.makedirs(os.path.dirname(out_path), exist_ok=True)
                            with open(out_path, 'wb') as out_file:
                                out_file.write(data)
                            os.chmod(os.path.dirname(out_path), 0o755)
                            self.logMessage.emit(f"Файл восстановлен: {out_path} ({size} байт)")
                        except Exception as e:
                            self.logMessage.emit(f"Ошибка восстановления {file['name']}: {e}")
                    elif 'mft_addr' in file and file['mft_addr']:
                        try:
                            img = pytsk3.Img_Info(device_path)
                            fs = pytsk3.FS_Info(img)
                            file_entry = fs.open_meta(file['mft_addr'])
                            size = file_entry.info.meta.size
                            data = file_entry.read_random(0, size)
                            out_path = os.path.join(output_dir, file['path'].lstrip('/'))
                            os.makedirs(os.path.dirname(out_path), exist_ok=True)
                            with open(out_path, 'wb') as f:
                                f.write(data)
                            os.chmod(os.path.dirname(out_path), 0o755)
                            self.logMessage.emit(f"Файл восстановлен: {out_path} ({size} байт)")
                        except Exception as e:
                            self.logMessage.emit(f"Ошибка восстановления {file['name']}: {e}")
                    elif file.get('type') == "Folder.":
                        try:
                            out_path = os.path.join(output_dir, file['path'].lstrip('/'))
                            os.makedirs(out_path, exist_ok=True)
                            os.chmod(out_path, 0o755)
                            self.logMessage.emit(f"Папка восстановлена: {out_path}")
                        except Exception as e:
                            self.logMessage.emit(f"Ошибка восстановления папки {file['name']}: {e}")
            self.logMessage.emit("Восстановление завершено.")
        except Exception as e:
            self.logMessage.emit(f"Ошибка восстановления: {e}")
        self.recoveryFinished.emit()

# GUI
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Инструмент восстановления файлов")
        self.resize(1000, 600)
        self.engine = FileRecoveryEngine()
        self.current_device = None
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
        self.scanButton = QtWidgets.QPushButton("Сканировать диск")
        self.stopButton = QtWidgets.QPushButton("Остановить")
        topPanel.addWidget(QtWidgets.QLabel("Устройство:"))
        topPanel.addWidget(self.deviceCombo)
        topPanel.addWidget(self.scanButton)
        topPanel.addWidget(self.stopButton)
        topPanel.addStretch()

        self.fileTable = QtWidgets.QTableWidget(0, 5)
        self.fileTable.setHorizontalHeaderLabels(["Имя", "Тип", "Размер", "Статус", "Дата удаления"])
        self.fileTable.horizontalHeader().setStretchLastSection(True)
        self.fileTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.fileTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        filterGroup = QtWidgets.QGroupBox("Фильтры")
        filterLayout = QtWidgets.QHBoxLayout()
        self.filterType = QtWidgets.QComboBox()
        self.filterType.addItem("Все типы")
        self.filterType.addItems(["Image", "Document", "Video", "Archive", "Folder."])
        self.filterSize = QtWidgets.QLineEdit()
        self.filterSize.setPlaceholderText("Размер (байт)")
        self.filterStatus = QtWidgets.QComboBox()
        self.filterStatus.addItem("Все статусы")
        self.filterStatus.addItem("Deleted")
        self.filterDateFrom = QtWidgets.QDateEdit()
        self.filterDateFrom.setCalendarPopup(True)
        self.filterDateFrom.setDisplayFormat("yyyy-MM-dd")
        self.filterDateFrom.setDate(QtCore.QDate.currentDate().addDays(-30))
        self.filterDateTo = QtWidgets.QDateEdit()
        self.filterDateTo.setCalendarPopup(True)
        self.filterDateTo.setDisplayFormat("yyyy-MM-dd")
        self.filterDateTo.setDate(QtCore.QDate.currentDate())
        filterLayout.addWidget(QtWidgets.QLabel("Тип:"))
        filterLayout.addWidget(self.filterType)
        filterLayout.addWidget(QtWidgets.QLabel("Размер:"))
        filterLayout.addWidget(self.filterSize)
        filterLayout.addWidget(QtWidgets.QLabel("Статус:"))
        filterLayout.addWidget(self.filterStatus)
        filterLayout.addWidget(QtWidgets.QLabel("Дата от:"))
        filterLayout.addWidget(self.filterDateFrom)
        filterLayout.addWidget(QtWidgets.QLabel("до:"))
        filterLayout.addWidget(self.filterDateTo)
        filterGroup.setLayout(filterLayout)

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
        tabWidget = QtWidgets.QTabWidget()
        mainTab = QtWidgets.QWidget()
        mainTabLayout = QtWidgets.QVBoxLayout()
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
        tabWidget.addTab(mainTab, "Интерфейс")
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
        """)

    def setup_connections(self):
        self.scanButton.clicked.connect(self.start_scan)
        self.stopButton.clicked.connect(self.stop_scan)
        self.rescanButton.clicked.connect(self.start_scan)
        self.recoverButton.clicked.connect(self.recover_selected_files)
        self.engine.progressChanged.connect(self.progressBar.setValue)
        self.engine.logMessage.connect(self.append_log)
        self.engine.scanFinished.connect(self.update_file_table)
        self.engine.recoveryFinished.connect(self.on_recovery_finished)
        self.fileTable.itemSelectionChanged.connect(self.show_preview)
        self.filterType.currentIndexChanged.connect(self.filter_table)
        self.filterStatus.currentIndexChanged.connect(self.filter_table)
        self.filterSize.textChanged.connect(self.filter_table)
        self.filterDateFrom.dateChanged.connect(self.filter_table)
        self.filterDateTo.dateChanged.connect(self.filter_table)

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
        self.progressBar.setValue(0)
        device = self.deviceCombo.currentText()
        self.current_device = device
        self.append_log(f"Сканирование устройства: {device}")
        if not self.engine.open_disk_direct(device):
            self.append_log("Ошибка доступа!")
            return
        self.scanThread = threading.Thread(target=self.engine.scan_disk, args=(device,))
        self.scanThread.start()

    def stop_scan(self):
        self.engine.stop_event.set()
        self.append_log("Остановка сканирования.")

    def update_file_table(self, files):
        self.all_files = files
        self.filter_table()

    def filter_table(self):
        self.fileTable.setRowCount(0)
        type_filter = self.filterType.currentText()
        status_filter = self.filterStatus.currentText()
        size_filter = self.filterSize.text().strip()
        date_from = self.filterDateFrom.date().toPyDate()
        date_to = self.filterDateTo.date().toPyDate()
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
            try:
                file_date = datetime.strptime(file['deleted_date'], "%Y-%m-%d").date()
                if file_date < date_from or file_date > date_to:
                    continue
            except Exception:
                pass
            row = self.fileTable.rowCount()
            self.fileTable.insertRow(row)
            self.fileTable.setItem(row, 0, QtWidgets.QTableWidgetItem(file['name']))
            self.fileTable.setItem(row, 1, QtWidgets.QTableWidgetItem(file['type']))
            self.fileTable.setItem(row, 2, QtWidgets.QTableWidgetItem(str(file['size'])))
            self.fileTable.setItem(row, 3, QtWidgets.QTableWidgetItem(file['status']))
            self.fileTable.setItem(row, 4, QtWidgets.QTableWidgetItem(file['deleted_date']))

    def show_preview(self):
        selected_items = self.fileTable.selectedItems()
        if not selected_items:
            return
        row = self.fileTable.currentRow()
        file = self.all_files[row]
        preview_text = ""
        self.previewLabel.clear()
        if 'data_offset' in file and self.current_device and os.path.exists(self.current_device):
            try:
                with open(self.current_device, 'rb') as f:
                    f.seek(file['data_offset'])
                    preview_data = f.read(1024)
                if file['name'].lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
                    image = QtGui.QImage()
                    if image.loadFromData(preview_data):
                        pixmap = QtGui.QPixmap.fromImage(image).scaled(200, 200, QtCore.Qt.KeepAspectRatio)
                        self.previewLabel.setPixmap(pixmap)
                    else:
                        preview_text = "Не удалось загрузить изображение."
                elif file['name'].lower().endswith(('.txt', '.log', '.csv')):
                    try:
                        preview_text = preview_data.decode('utf-8')
                    except Exception:
                        preview_text = "Не удалось декодировать текст."
                else:
                    preview_text = preview_data.hex()
            except Exception as e:
                preview_text = f"Ошибка предпросмотра: {e}"
        else:
            preview_text = "Предпросмотр не доступен"
        info = (f"Устройство: {self.deviceCombo.currentText()}\n"
                f"MFT addr: {file.get('mft_addr', 'N/A')}\n"
                f"Статус: {file['status']}\n"
                f"Дата удаления: {file['deleted_date']}\n\n"
                f"Предпросмотр:\n{preview_text}")
        self.infoText.setPlainText(info)

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
        self.recoverButton.setEnabled(False)
        device = self.deviceCombo.currentText()
        threading.Thread(target=self.engine.recover_files, args=(files_to_recover, self.output_dir, device)).start()

    def on_recovery_finished(self):
        self.append_log("Восстановление завершено.")
        self.fileTable.clearSelection()
        self.recoverButton.setEnabled(True)

    def append_log(self, message):
        timestamp = time.strftime("[%H:%M:%S]", time.localtime())
        self.logText.append(f"{timestamp} {message}")
        QtWidgets.QApplication.processEvents()

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()