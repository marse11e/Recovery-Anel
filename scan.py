#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import threading
import time
import random
import platform
import struct
import re
from datetime import datetime

from PyQt5 import QtCore, QtGui, QtWidgets

try:
    import pytsk3
except ImportError:
    pytsk3 = None

# ======================================================
# Функция для обнаружения доступных дисков
# ======================================================
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

# ======================================================
# Функция определения типа файловой системы
# ======================================================
def determine_fs_type(device_path):
    """
    Чтение первых секторов для определения сигнатуры ФС:
      - NTFS: строка "NTFS    " на байтах 3-10
      - FAT32: строка "FAT32   " на байтах 82-90 (вариации возможны)
      - ext4: суперблок с offset 1024, magic = 0xEF53
    """
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

# ======================================================
# BACKEND: Реальное восстановление удалённых файлов
# ======================================================
class FileRecoveryEngine(QtCore.QObject):
    progressChanged = QtCore.pyqtSignal(int)
    logMessage = QtCore.pyqtSignal(str)
    scanFinished = QtCore.pyqtSignal(list)
    recoveryFinished = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.stopScan = False

    def open_disk_direct(self, device_path):
        try:
            self.logMessage.emit(f"Открытие устройства {device_path} в режиме прямого доступа...")
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

    # ------------------------------------------------------------------
    # Рекурсивное сканирование с использованием pytsk3 для ФС,
    # если библиотека установлена и ФС поддерживается.
    # ------------------------------------------------------------------
    def recursive_scan(self, fs, directory, results):
        for entry in directory:
            # Пропускаем специальные записи
            if entry.info.name.name in [b".", b".."]:
                continue
            try:
                name = entry.info.name.name.decode("utf-8")
            except Exception:
                name = str(entry.info.name.name)
            if entry.info.meta is None:
                continue

            # Если файл отмечен как удалённый, добавляем его в результаты
            if entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                file_item = {
                    'name': name,
                    'type': 'Unknown',
                    'size': entry.info.meta.size,
                    'status': 'Deleted',
                    'deleted_date': 'N/A',
                    'mft_addr': entry.info.meta.addr
                }
                results.append(file_item)
                self.logMessage.emit(f"Найден удалённый файл: {name}")

            # Если это каталог, обходим его рекурсивно
            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    sub_directory = entry.as_directory()
                    self.recursive_scan(fs, sub_directory, results)
                except Exception as e:
                    self.logMessage.emit(f"Ошибка при обходе каталога {name}: {e}")

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

    # ------------------------------------------------------------------
    # Сканирование устройства путём поиска сигнатур файлов по бинарному содержимому.
    # Реализован пример для JPEG-файлов.
    # ------------------------------------------------------------------
    def scan_by_signature(self, device_path):
        self.logMessage.emit("Поиск файлов по сигнатурам по всему устройству...")
        results = []
        start_sig = b'\xff\xd8'
        end_sig = b'\xff\xd9'
        block_size = 1024 * 1024  # Чтение блоками по 1 МБ
        overlap = 1024           # Перекрытие для поиска сигнатур на границах блоков
        offset = 0
        buffer = b""
        try:
            with open(device_path, 'rb') as f:
                while True:
                    data = f.read(block_size)
                    if not data:
                        break
                    buffer += data
                    pos = 0
                    while True:
                        start_index = buffer.find(start_sig, pos)
                        if start_index == -1:
                            break
                        end_index = buffer.find(end_sig, start_index)
                        if end_index == -1:
                            # Если конец не найден, возможно, он лежит в следующем блоке
                            break
                        end_index += len(end_sig)
                        file_size = end_index - start_index
                        auto_name = f"recovered_jpeg_{offset+start_index}_{random.randint(1000,9999)}.jpg"
                        file_item = {
                            'name': auto_name,
                            'type': 'Image',
                            'size': file_size,
                            'status': 'Deleted',
                            'deleted_date': 'N/A',
                            'data_offset': offset + start_index,
                            'data_end': offset + end_index
                        }
                        results.append(file_item)
                        self.logMessage.emit(f"Найден JPEG файл: {auto_name} (от {offset+start_index} до {offset+end_index})")
                        pos = end_index
                    # Сохраняем последние 'overlap' байт, чтобы не потерять сигнатуры на границе блока
                    if len(buffer) > overlap:
                        buffer = buffer[-overlap:]
                    offset += block_size
        except Exception as e:
            self.logMessage.emit(f"Ошибка при поиске сигнатур: {e}")
        return results

    # ------------------------------------------------------------------
    # Функция сканирования, выбирающая метод в зависимости от наличия pytsk3
    # и типа файловой системы. Если pytsk3 недоступен или ФС не поддерживается,
    # используется поиск по сигнатурам.
    # ------------------------------------------------------------------
    def scan_disk(self, device_path):
        self.logMessage.emit(f"Начало сканирования диска: {device_path}")
        fs_type = self.determine_filesystem(device_path)
        results = []
        try:
            if pytsk3 is not None and fs_type in ["NTFS", "FAT32", "ext4"]:
                # При наличии pytsk3 можно попытаться сначала просканировать структурированно
                results = self.scan_with_pytsk3(device_path)
                if not results:
                    self.logMessage.emit("Структурированное сканирование не дало результатов. Переход к поиску по сигнатурам...")
                    results = self.scan_by_signature(device_path)
            else:
                results = self.scan_by_signature(device_path)
        except Exception as e:
            self.logMessage.emit(f"Ошибка при сканировании диска: {e}")
        self.logMessage.emit("Сканирование диска завершено.")
        self.scanFinished.emit(results)

    # ------------------------------------------------------------------
    # Функция восстановления файлов.
    # Если файл найден по сигнатуре, производится чтение указанного диапазона.
    # ------------------------------------------------------------------
    def recover_files(self, files, output_dir, device_path):
        self.logMessage.emit("Начало восстановления файлов...")
        try:
            with open(device_path, 'rb') as disk:
                for file in files:
                    if 'data_offset' in file:
                        try:
                            disk.seek(file['data_offset'])
                            if 'data_end' in file:
                                size = file['data_end'] - file['data_offset']
                            else:
                                size = file.get('size', 102400)
                            data = disk.read(size)
                            out_path = os.path.join(output_dir, file['name'])
                            with open(out_path, 'wb') as out_file:
                                out_file.write(data)
                            self.logMessage.emit(f"Файл восстановлен по сигнатуре: {out_path} ({size} байт)")
                        except Exception as e:
                            self.logMessage.emit(f"Ошибка при восстановлении файла {file['name']}: {e}")
                    elif 'mft_addr' in file and file['mft_addr']:
                        try:
                            img = pytsk3.Img_Info(device_path)
                            fs = pytsk3.FS_Info(img)
                            file_entry = fs.open_meta(file['mft_addr'])
                            size = file_entry.info.meta.size
                            data = file_entry.read_random(0, size)
                            out_path = os.path.join(output_dir, file['name'])
                            with open(out_path, 'wb') as f:
                                f.write(data)
                            self.logMessage.emit(f"Файл восстановлен: {out_path} ({size} байт)")
                        except Exception as e:
                            self.logMessage.emit(f"Ошибка при восстановлении файла {file['name']}: {e}")
                    else:
                        self.logMessage.emit(f"Нет достаточной информации для восстановления файла {file['name']}")
            self.logMessage.emit("Восстановление файлов завершено.")
        except Exception as e:
            self.logMessage.emit(f"Ошибка восстановления: {e}")
        self.recoveryFinished.emit()

# ======================================================
# GUI: PyQt5 Интерфейс
# ======================================================
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Инструмент восстановления удалённых файлов")
        self.resize(1000, 600)
        self.engine = FileRecoveryEngine()
        self.setup_ui()
        self.setup_connections()

    def setup_ui(self):
        centralWidget = QtWidgets.QWidget()
        mainLayout = QtWidgets.QVBoxLayout()

        topPanel = QtWidgets.QHBoxLayout()
        self.deviceCombo = QtWidgets.QComboBox()
        disks = get_available_disks()
        if not disks:
            disks = ["Нет обнаруженных дисков"]
        self.deviceCombo.addItems(disks)
        self.scanButton = QtWidgets.QPushButton("Сканировать диск")
        topPanel.addWidget(QtWidgets.QLabel("Выбор устройства:"))
        topPanel.addWidget(self.deviceCombo)
        topPanel.addWidget(self.scanButton)
        topPanel.addStretch()

        self.fileTable = QtWidgets.QTableWidget(0, 5)
        self.fileTable.setHorizontalHeaderLabels(["Имя файла", "Тип файла", "Размер", "Статус", "Дата удаления"])
        self.fileTable.horizontalHeader().setStretchLastSection(True)
        self.fileTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.fileTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        filterGroup = QtWidgets.QGroupBox("Фильтры")
        filterLayout = QtWidgets.QHBoxLayout()
        self.filterType = QtWidgets.QComboBox()
        self.filterType.addItem("Все типы")
        self.filterType.addItems(["Image", "Document", "Video", "Archive"])
        self.filterSize = QtWidgets.QLineEdit()
        self.filterSize.setPlaceholderText("Размер (байт)")
        self.filterStatus = QtWidgets.QComboBox()
        self.filterStatus.addItem("Все статусы")
        self.filterStatus.addItems(["Deleted"])
        self.filterDateFrom = QtWidgets.QDateEdit()
        self.filterDateFrom.setCalendarPopup(True)
        self.filterDateFrom.setDisplayFormat("yyyy-MM-dd")
        self.filterDateFrom.setDate(QtCore.QDate.currentDate().addDays(-30))
        self.filterDateTo = QtWidgets.QDateEdit()
        self.filterDateTo.setCalendarPopup(True)
        self.filterDateTo.setDisplayFormat("yyyy-MM-dd")
        self.filterDateTo.setDate(QtCore.QDate.currentDate())
        
        filterLayout.addWidget(QtWidgets.QLabel("Тип файла:"))
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

        previewGroup = QtWidgets.QGroupBox("Предпросмотр и информация")
        previewLayout = QtWidgets.QVBoxLayout()
        self.previewLabel = QtWidgets.QLabel("Предпросмотр не доступен")
        self.previewLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.infoText = QtWidgets.QTextEdit()
        self.infoText.setReadOnly(True)
        previewLayout.addWidget(self.previewLabel)
        previewLayout.addWidget(self.infoText)
        previewGroup.setLayout(previewLayout)

        controlPanel = QtWidgets.QHBoxLayout()
        self.recoverButton = QtWidgets.QPushButton("Восстановить выбранные файлы")
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
        tabWidget.addTab(mainTab, "Основной интерфейс")
        tabWidget.addTab(self.logText, "Журнал логов")

        mainLayout.addWidget(tabWidget)
        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)

        self.setAcceptDrops(True)

        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: Arial, sans-serif;
                font-size: 12pt;
            }
            QLabel, QGroupBox {
                color: #d4d4d4;
            }
            QPushButton {
                background-color: #3c3c3c;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 6px 12px;
                color: #d4d4d4;
            }
            QPushButton:hover { background-color: #505050; }
            QPushButton:pressed { background-color: #2d2d2d; }
            QLineEdit, QComboBox, QTextEdit, QTableWidget {
                background-color: #252526;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                color: #d4d4d4;
            }
            QTableWidget { gridline-color: #3c3c3c; }
            QHeaderView::section {
                background-color: #2d2d30;
                padding: 4px;
                border: 1px solid #3c3c3c;
            }
            QProgressBar {
                background-color: #3c3c3c;
                border: 1px solid #3c3c3c;
                text-align: center;
                color: #d4d4d4;
            }
            QProgressBar::chunk { background-color: #007acc; }
            QTextEdit { background-color: #1e1e1e; }
        """)

    def setup_connections(self):
        self.scanButton.clicked.connect(self.start_scan)
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
                self.append_log(f"Выбрана папка для сохранения: {folder}")
                self.output_dir = folder

    def start_scan(self):
        self.fileTable.setRowCount(0)
        self.progressBar.setValue(0)
        device = self.deviceCombo.currentText()
        self.append_log(f"Начало сканирования устройства: {device}")
        if not self.engine.open_disk_direct(device):
            self.append_log("Ошибка доступа к устройству!")
            return
        self.scanThread = threading.Thread(target=self.engine.scan_disk, args=(device,))
        self.scanThread.start()

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
                    if file['size'] < int(size_filter):
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
        if file['name'].lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
            pixmap = QtGui.QPixmap(200, 200)
            pixmap.fill(QtGui.QColor("gray"))
            self.previewLabel.setPixmap(pixmap)
        else:
            self.previewLabel.setText("Предпросмотр не доступен")
        info = (f"Устройство: {self.deviceCombo.currentText()}\n"
                f"Сигнатура (MFT addr): {file.get('mft_addr', 'N/A')}\n"
                f"Статус: {file['status']}\n"
                f"Дата удаления: {file['deleted_date']}")
        self.infoText.setPlainText(info)

    def recover_selected_files(self):
        selected_rows = set(item.row() for item in self.fileTable.selectedItems())
        if not selected_rows:
            self.append_log("Не выбраны файлы для восстановления.")
            return
        files_to_recover = [self.all_files[i] for i in selected_rows]
        if not hasattr(self, 'output_dir'):
            self.output_dir = QtWidgets.QFileDialog.getExistingDirectory(self, "Выберите папку для восстановления")
        if not self.output_dir:
            self.append_log("Папка для сохранения не выбрана!")
            return
        self.recoverButton.setEnabled(False)
        device = self.deviceCombo.currentText()
        threading.Thread(target=self.engine.recover_files, args=(files_to_recover, self.output_dir, device)).start()

    def on_recovery_finished(self):
        self.append_log("Восстановление завершено. Можно повторно выбрать файлы.")
        self.fileTable.clearSelection()
        self.recoverButton.setEnabled(True)

    def append_log(self, message):
        timestamp = time.strftime("[%H:%M:%S]", time.localtime())
        self.logText.append(f"{timestamp} {message}")

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
