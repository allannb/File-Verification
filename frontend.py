#___  ___       _   _           _               
#|  \/  |      | | | |         | |                  /\ o o o\
#| .  . |_ __  | |_| | __ _ ___| |__   ___ _ __    /o \ o o o\_______
#| |\/| | '__| |  _  |/ _` / __| '_ \ / _ \ '__|  <    >------>   o /|
#| |  | | |_   | | | | (_| \__ \ | | |  __/ |      \ o/  o   /_____/o|
#\_|  |_/_(_)  \_| |_/\__,_|___/_| |_|\___|_|       \/______/     |oo|
#                                                         |   o   |o/
#                                                         |_______|/
import sys
import os 
import random 
import time 
import traceback 
import configparser 
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QProgressBar, QTextEdit,
    QStackedWidget, QFileDialog, QMessageBox, QFrame, QSpacerItem, QSizePolicy,
    QStyle
)
from PyQt6.QtGui import QIcon, QFont, QPixmap 
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal


script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

import backend
import backend2 

# --- Icons path ---
# btw os.path.join(script_dir searches for Icons Folder that is in the Main directorgy
ICON_FOLDER_NAME = "Icons" 
ICON_PATH_EXTRACT = os.path.join(script_dir, ICON_FOLDER_NAME, "icons8-online-binary-code-48.png")
ICON_PATH_MONITOR = os.path.join(script_dir, ICON_FOLDER_NAME, "icons8-binoculars-48.png")
ICON_PATH_CONFIG = os.path.join(script_dir, ICON_FOLDER_NAME, "icons8-gear-48.png")
ICON_PATH_CHECKER = os.path.join(script_dir, ICON_FOLDER_NAME, "icons8-website-bug-48.png")
ICON_PATH_ABOUT = os.path.join(script_dir, ICON_FOLDER_NAME, "icons8-about-48.png") 
APP_ICON_PATH = os.path.join(script_dir, ICON_FOLDER_NAME, "favicon (1).ico")
CONFIG_FILE_PATH = os.path.join(script_dir, "config.ini")


class MonitoringWorker(QThread):
    log_message = pyqtSignal(str)
    progress_update = pyqtSignal(int, str) 
    stage_complete = pyqtSignal(str, object) 
    process_error = pyqtSignal(str)
    process_finished_successfully = pyqtSignal(str) 

    def __init__(self, integrity_verifier, installer_path, target_dir, default_save_dir, output_format):
        super().__init__()
        self.integrity_verifier = integrity_verifier
        self.installer_path = installer_path
        self.target_dir = target_dir
        self.default_save_dir = default_save_dir
        self.output_format = output_format
        self._is_running = True
        self.integrity_verifier.was_manually_stopped = False 

    def run(self):
        try:
            # --- Step 1: Initial Snapshot ---
            if not self._is_running: return
            self.log_message.emit("<br><b>--- Worker Log ---</b>")
            self.log_message.emit("Worker: Starting initial snapshot...")
            self.progress_update.emit(10, "Step 1/4: Initial Snapshot - Scanning files... %p%") 
            
            self.integrity_verifier.system_drives = [self.target_dir]
            snapshot_before = self.integrity_verifier.take_system_snapshot()
            if not self._is_running: self.log_message.emit("Worker: Initial snapshot cancelled."); return
            
            self.integrity_verifier.snapshot_before = snapshot_before 
            self.progress_update.emit(30, "Step 1/4: Initial snapshot done. %p%")
            self.stage_complete.emit("initial_snapshot_done", snapshot_before)
            for log_entry in self.integrity_verifier.debug_log: self.log_message.emit(f"<i>[SNAPSHOT_BEFORE]</i> {log_entry}")
            self.integrity_verifier.debug_log = []

            # --- Step 2: Run Installer ---
            if not self._is_running: return
            self.log_message.emit(f"<br>Worker: Attempting to run installer: <b>{os.path.basename(self.installer_path)}</b>...")
            self.progress_update.emit(40, "Step 2/4: Monitoring installer... %p%")

            monitor_success = self.integrity_verifier.monitor_installation(self.installer_path)
            if not self._is_running and not monitor_success: 
                self.log_message.emit("Worker: Installer monitoring cancelled or failed during stop request.")
                self.process_error.emit("Monitoring process cancelled by user during installation.")
                return

            for log_entry in self.integrity_verifier.debug_log: self.log_message.emit(f"<i>[INSTALL_MONITOR]</i> {log_entry}")
            self.integrity_verifier.debug_log = []

            if not monitor_success:
                self.process_error.emit("Installer monitoring failed, was stopped, or requires elevation. Check logs. Please run this application as Administrator if the installer requires it.")
                return
            
            self.progress_update.emit(60, "Step 2/4: Installer finished. %p%")
            self.stage_complete.emit("installer_done", None)

            # --- Step 3: Final Snapshot ---
            if not self._is_running: return
            self.log_message.emit("<br>Worker: Taking final snapshot...")
            self.progress_update.emit(70, "Step 3/4: Final Snapshot - Scanning files... %p%")

            self.integrity_verifier.system_drives = [self.target_dir]
            snapshot_after = self.integrity_verifier.take_system_snapshot()
            if not self._is_running: self.log_message.emit("Worker: Final snapshot cancelled."); return
            
            self.integrity_verifier.snapshot_after = snapshot_after 
            self.progress_update.emit(90, "Step 3/4: Final snapshot done. %p%")
            self.stage_complete.emit("final_snapshot_done", snapshot_after)
            for log_entry in self.integrity_verifier.debug_log: self.log_message.emit(f"<i>[SNAPSHOT_AFTER]</i> {log_entry}")
            self.integrity_verifier.debug_log = []

            # --- Step 4: Identify and Report Changes ---
            if not self._is_running: return
            self.log_message.emit("<br>Worker: Identifying changes...")
            self.progress_update.emit(95, "Step 4/4: Identifying changes... %p%")
            changes = self.integrity_verifier._identify_changes()
            if not self._is_running: self.log_message.emit("Worker: Change identification cancelled."); return
            self.stage_complete.emit("changes_identified", changes)

            report_file_path_final = "N/A"
            if changes:
                self.log_message.emit(f"<br>Worker: Detected <b>{len(changes)}</b> new or modified files. Generating report...")
                self.integrity_verifier.install_path = self.target_dir 
                save_success, report_file_path = self.integrity_verifier.generate_checksums(
                    installer_filename_for_report=os.path.basename(self.installer_path or "UnknownInstaller"),
                    output_base_dir=self.default_save_dir,
                    output_format=self.output_format 
                )
                if save_success and report_file_path:
                    report_file_path_final = report_file_path
                    self.log_message.emit(f"Worker: Changes report saved to: <b>{report_file_path}</b>")
                else:
                    self.log_message.emit("Worker: <font color='red'>Failed to save changes report.</font>")
            else:
                self.log_message.emit("Worker: No changes detected between snapshots.")
            
            self.progress_update.emit(100, "Complete!")
            self.process_finished_successfully.emit(report_file_path_final)

        except Exception as e:
            self.log_message.emit(f"<font color='red'><b>Worker Thread Error:</b> {type(e).__name__} - {str(e)}</font>")
            self.log_message.emit(f"<pre>{traceback.format_exc()}</pre>")
            self.process_error.emit(f"An unexpected error occurred in the monitoring process: {e}")
        finally:
            self._is_running = False

    def request_stop(self):
        self.log_message.emit("Worker: Stop requested.")
        self._is_running = False
        self.integrity_verifier.was_manually_stopped = True 
        if self.integrity_verifier.proc and self.integrity_verifier.installer_pid:
            self.integrity_verifier.request_stop_monitoring() 


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mr. Hasher") 
        if os.path.exists(APP_ICON_PATH): 
            self.setWindowIcon(QIcon(APP_ICON_PATH))
        else:
            print(f"Warning: Application icon not found at {APP_ICON_PATH}")
        
        self.active_loading_bar = None
        self.active_toggle_button = None 
        self.loading_timer = QTimer(self) 
        self.loading_timer.timeout.connect(self.update_loading_bar)
        self.loading_progress = 0
        self.on_loading_complete_callback = None 

        self.imported_checksum_data_tab2 = [] 
        self.integrity_verifier_tab3 = backend2.IntegrityVerifier() 
        self.monitoring_target_directory_tab3 = None 
        self.monitoring_installer_path_tab3 = None
        self.temp_extraction_path = os.path.join(script_dir, "temp_extraction") 
        
        self.default_save_directory = script_dir 
        self.default_checksum_format = "JSON Format (.json)" 
        self.monitoring_worker_tab3 = None 

        self.init_ui()
        self.apply_styles()
        self.load_config() 
        self.adjustSize() 
        self.setup_config_tab_events() 

    def load_config(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE_PATH):
            try:
                config.read(CONFIG_FILE_PATH)
                self.default_save_directory = config.get('Settings', 'DefaultSaveDirectory', fallback=script_dir)
                self.default_checksum_format = config.get('Settings', 'DefaultChecksumFormat', fallback="JSON Format (.json)")
                
                if hasattr(self, 'config_current_save_dir_display'): 
                    self.config_current_save_dir_display.setText(self.default_save_directory)
                
                if hasattr(self, 'config_save_format_combo'): 
                    index = self.config_save_format_combo.findText(self.default_checksum_format, Qt.MatchFlag.MatchFixedString)
                    if index >= 0:
                        self.config_save_format_combo.setCurrentIndex(index)
                print(f"Configuration loaded: SaveDir='{self.default_save_directory}', Format='{self.default_checksum_format}'")
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
                self.default_save_directory = script_dir
                self.default_checksum_format = "JSON Format (.json)"
        else:
            print("Config file not found. Using defaults and creating one.")
            self.default_save_directory = script_dir
            self.default_checksum_format = "JSON Format (.json)"
            if hasattr(self, 'config_current_save_dir_display'): self.config_current_save_dir_display.setText(self.default_save_directory)
            if hasattr(self, 'config_save_format_combo'):
                index = self.config_save_format_combo.findText(self.default_checksum_format, Qt.MatchFlag.MatchFixedString)
                if index >=0: self.config_save_format_combo.setCurrentIndex(index)
            self.save_config() 

    def save_config(self):
        config = configparser.ConfigParser()
        if not config.has_section('Settings'):
            config.add_section('Settings')
            
        config.set('Settings', 'DefaultSaveDirectory', self.default_save_directory)
        current_format = self.default_checksum_format 
        if hasattr(self, 'config_save_format_combo') and self.config_save_format_combo.count() > 0: 
            current_format = self.config_save_format_combo.currentText()
        config.set('Settings', 'DefaultChecksumFormat', current_format)
        
        try:
            with open(CONFIG_FILE_PATH, 'w') as configfile:
                config.write(configfile)
            print(f"Configuration saved: {CONFIG_FILE_PATH}")
        except Exception as e:
            print(f"Error saving config: {e}")
            QMessageBox.warning(self, "Config Error", f"Could not save configuration: {e}")


    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0,0,0,0) 
        main_layout.setSpacing(0) 

        sidebar_widget = QWidget()
        sidebar_widget.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar_widget)
        sidebar_layout.setContentsMargins(10, 10, 10, 10)
        sidebar_layout.setSpacing(5)
        sidebar_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.btn_extract = QPushButton("Custom Extract")
        self.btn_extract.setObjectName("sidebarButton")
        self.btn_extract.setProperty("tabTarget", "tab1")
        if os.path.exists(ICON_PATH_EXTRACT): self.btn_extract.setIcon(QIcon(ICON_PATH_EXTRACT))
        self.btn_extract.clicked.connect(self.switch_tab)

        self.btn_monitor = QPushButton("Update Monitoring")
        self.btn_monitor.setObjectName("sidebarButton")
        self.btn_monitor.setProperty("tabTarget", "tab3") 
        if os.path.exists(ICON_PATH_MONITOR): self.btn_monitor.setIcon(QIcon(ICON_PATH_MONITOR))
        self.btn_monitor.clicked.connect(self.switch_tab)
        
        self.btn_checker = QPushButton("Checker")
        self.btn_checker.setObjectName("sidebarButton")
        self.btn_checker.setProperty("tabTarget", "tab2") 
        if os.path.exists(ICON_PATH_CHECKER): self.btn_checker.setIcon(QIcon(ICON_PATH_CHECKER)) 
        self.btn_checker.clicked.connect(self.switch_tab)

        self.btn_config = QPushButton("Configuration")
        self.btn_config.setObjectName("sidebarButton")
        self.btn_config.setProperty("tabTarget", "tab4")
        if os.path.exists(ICON_PATH_CONFIG): self.btn_config.setIcon(QIcon(ICON_PATH_CONFIG))
        self.btn_config.clicked.connect(self.switch_tab)

        self.btn_about = QPushButton("About")
        self.btn_about.setObjectName("sidebarButton")
        self.btn_about.setProperty("tabTarget", "tab5")
        if os.path.exists(ICON_PATH_ABOUT): self.btn_about.setIcon(QIcon(ICON_PATH_ABOUT)) 
        self.btn_about.clicked.connect(self.switch_tab)

        sidebar_layout.addWidget(self.btn_extract)
        sidebar_layout.addWidget(self.btn_monitor)
        sidebar_layout.addWidget(self.btn_checker)
        sidebar_layout.addWidget(self.btn_config)
        sidebar_layout.addWidget(self.btn_about)
        
        self.sidebar_buttons = [self.btn_extract, self.btn_monitor, self.btn_checker, self.btn_config, self.btn_about]

        main_layout.addWidget(sidebar_widget, 1) 

        self.stacked_content = QStackedWidget()
        self.stacked_content.setObjectName("mainContent")
        main_layout.addWidget(self.stacked_content, 4) 

        self.tab1_widget = self.create_tab1_ui()
        self.tab2_widget = self.create_tab2_ui() 
        self.tab3_widget = self.create_tab3_ui() 
        self.tab4_widget = self.create_tab4_ui()
        self.tab5_widget = self.create_tab5_ui()

        self.stacked_content.addWidget(self.tab1_widget) 
        self.stacked_content.addWidget(self.tab3_widget) 
        self.stacked_content.addWidget(self.tab2_widget) 
        self.stacked_content.addWidget(self.tab4_widget) 
        self.stacked_content.addWidget(self.tab5_widget) 
        
        self.switch_tab(initial_target="tab1")


    def create_tab_pane_widget(self):
        pane = QWidget()
        pane.setObjectName("tabPane")
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(20, 20, 20, 20) 
        layout.setSpacing(15) 
        return pane, layout

    def create_tab1_ui(self):
        pane, layout = self.create_tab_pane_widget()
        title = QLabel("Custom Extract")
        title.setObjectName("tabTitle")
        layout.addWidget(title)
        desc = QLabel("Select a program file (.exe, .msi) or folder without installing it, and generate its checksum for verification purposes.")
        desc.setObjectName("tabDescription")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        file_selection_card = QFrame()
        file_selection_card.setObjectName("cardFrame")
        file_selection_card_layout = QVBoxLayout(file_selection_card)
        file_selection_card_layout.setSpacing(5) 

        file_label = QLabel("1. Select Program File or Archive:")
        file_label.setObjectName("cardTitle")
        file_selection_card_layout.addWidget(file_label)

        file_browse_layout = QHBoxLayout()
        self.extract_file_display_tab1 = QLineEdit("No file selected") 
        self.extract_file_display_tab1.setReadOnly(True)
        self.extract_file_display_tab1.setObjectName("winInput")
        file_browse_layout.addWidget(self.extract_file_display_tab1, 1)
        
        btn_browse_extract = QPushButton() 
        btn_browse_extract.setObjectName("winButton")
        btn_browse_extract.setToolTip("Browse for Archive/File")
        style = self.style()
        if style:
            icon_open = style.standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon)
            btn_browse_extract.setIcon(icon_open)
        else:
            btn_browse_extract.setText("Browse...") 
        btn_browse_extract.setMinimumHeight(self.extract_file_display_tab1.sizeHint().height()) 
        btn_browse_extract.clicked.connect(self.browse_archive_tab1) 
        file_browse_layout.addWidget(btn_browse_extract)
        file_selection_card_layout.addLayout(file_browse_layout)
        layout.addWidget(file_selection_card)


        algo_selection_card = QFrame()
        algo_selection_card.setObjectName("cardFrame")
        algo_card_layout = QVBoxLayout(algo_selection_card)
        algo_card_layout.setSpacing(5)

        algo_label = QLabel("2. Select Algorithm for Checksum Generation:") 
        algo_label.setObjectName("cardTitle")
        algo_card_layout.addWidget(algo_label)

        self.extract_algorithm_combo_tab1 = QComboBox() 
        self.extract_algorithm_combo_tab1.setObjectName("winSelect")
        self.extract_algorithm_combo_tab1.addItems(["MD5", "SHA1", "SHA256"]) 
        self.extract_algorithm_combo_tab1.setCurrentText("SHA256")
        algo_card_layout.addWidget(self.extract_algorithm_combo_tab1)
        
        algo_helper_text = QLabel("This determines the type of checksum that will be generated for the selected file/archive contents.")
        algo_helper_text.setObjectName("helperText") 
        algo_card_layout.addWidget(algo_helper_text)
        layout.addWidget(algo_selection_card)
        
        action_button_layout = QHBoxLayout()
        action_button_layout.addStretch(1)
        self.extract_toggle_button_tab1 = QPushButton("Start Extraction") 
        self.extract_toggle_button_tab1.setObjectName("extract_toggle_button_tab1") 
        self.extract_toggle_button_tab1.setProperty("primaryAction", "true") 
        if style:
            icon_play = style.standardIcon(QStyle.StandardPixmap.SP_MediaPlay) 
            self.extract_toggle_button_tab1.setIcon(icon_play)
        self.extract_toggle_button_tab1.setProperty("state", "start") 
        self.extract_toggle_button_tab1.clicked.connect(self.toggle_extract_and_checksum_process_tab1) 
        action_button_layout.addWidget(self.extract_toggle_button_tab1)
        action_button_layout.addStretch(1)
        layout.addLayout(action_button_layout)

        layout.addWidget(QLabel("Process Progress:"))
        self.progress_bar_tab1 = QProgressBar()
        self.progress_bar_tab1.setValue(0)
        self.progress_bar_tab1.setTextVisible(True) 
        layout.addWidget(self.progress_bar_tab1)

        layout.addWidget(QLabel("Generated Checksum Output / Log:"))
        self.terminal_extract_tab1 = QTextEdit() 
        self.terminal_extract_tab1.setPlaceholderText("Checksum data and process logs will appear here...\nSelect a file and click 'Start Extraction'.")
        self.terminal_extract_tab1.setReadOnly(True) 
        self.terminal_extract_tab1.setObjectName("winTextarea") 
        self.terminal_extract_tab1.setFixedHeight(120) 
        layout.addWidget(self.terminal_extract_tab1)
        
        layout.addStretch(1) 
        return pane

    def create_tab2_ui(self): 
        pane, layout = self.create_tab_pane_widget()
        title = QLabel("Checksum Verifier")
        title.setObjectName("tabTitle")
        layout.addWidget(title)
        desc = QLabel("Import a previously generated checksum file. Then, select a target directory (e.g., an application's installation folder) to verify its contents against the imported checksums. Results are logged in the terminal.")
        desc.setObjectName("tabDescription")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        import_layout = QHBoxLayout()
        self.checksum_file_display_tab2 = QLineEdit("No checksum file selected")
        self.checksum_file_display_tab2.setReadOnly(True)
        self.checksum_file_display_tab2.setObjectName("winInput")
        import_layout.addWidget(self.checksum_file_display_tab2, 1)
        btn_browse_import_tab2 = QPushButton("Import File")
        btn_browse_import_tab2.setObjectName("winButton")
        btn_browse_import_tab2.clicked.connect(self.import_checksum_file_tab2)
        import_layout.addWidget(btn_browse_import_tab2)
        layout.addLayout(import_layout)
        
        spacer_label = QLabel("Imported checksums will be processed. Verification results will appear in the terminal below.")
        spacer_label.setObjectName("infoText") 
        spacer_label.setWordWrap(True)
        layout.addWidget(spacer_label)

        layout.addWidget(QLabel("Verification Progress:"))
        self.progress_bar_tab2_verify = QProgressBar()
        self.progress_bar_tab2_verify.setValue(0)
        self.progress_bar_tab2_verify.setTextVisible(True)
        layout.addWidget(self.progress_bar_tab2_verify)

        self.verify_files_button_tab2 = QPushButton("Verify Directory")
        self.verify_files_button_tab2.setObjectName("winButton")
        self.verify_files_button_tab2.clicked.connect(self.verify_directory_tab2)
        layout.addWidget(self.verify_files_button_tab2, alignment=Qt.AlignmentFlag.AlignLeft)

        layout.addWidget(QLabel("Checksum Verification Terminal:"))
        self.terminal_checker_tab2 = QTextEdit()
        self.terminal_checker_tab2.setPlaceholderText("Verification logs will appear here...\nImport a checksum file and select a directory to verify.")
        self.terminal_checker_tab2.setReadOnly(True)
        self.terminal_checker_tab2.setObjectName("winTextarea")
        self.terminal_checker_tab2.setFixedHeight(120)
        layout.addWidget(self.terminal_checker_tab2)

        self.save_report_button_tab2 = QPushButton("Save Report (.txt)")
        self.save_report_button_tab2.setObjectName("winButton")
        self.save_report_button_tab2.clicked.connect(self.save_checker_report_tab2)
        layout.addWidget(self.save_report_button_tab2, alignment=Qt.AlignmentFlag.AlignRight)


        layout.addStretch(1)
        return pane

    def create_tab3_ui(self): 
        pane, layout = self.create_tab_pane_widget()
        title = QLabel("Update Monitoring")
        title.setObjectName("tabTitle")
        layout.addWidget(title)
        desc = QLabel("Select an installer (.exe, .msi) and its target installation directory. This tool will snapshot the directory, run the installer, snapshot again, and then report any file changes.")
        desc.setObjectName("tabDescription")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        installer_card = QFrame()
        installer_card.setObjectName("cardFrame")
        installer_card_layout = QVBoxLayout(installer_card)
        installer_card_layout.setSpacing(5)

        installer_label = QLabel("1. Select Installer File (.exe, .msi)")
        installer_label.setObjectName("cardTitle")
        installer_card_layout.addWidget(installer_label)
        
        installer_select_layout = QHBoxLayout()
        self.monitor_installer_display_tab3 = QLineEdit("No installer selected")
        self.monitor_installer_display_tab3.setReadOnly(True)
        self.monitor_installer_display_tab3.setObjectName("winInput")
        installer_select_layout.addWidget(self.monitor_installer_display_tab3, 1)
        btn_browse_installer_tab3 = QPushButton() 
        btn_browse_installer_tab3.setObjectName("winButton")
        style = self.style() 
        if style:
            icon_open = style.standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon)
            btn_browse_installer_tab3.setIcon(icon_open)
        else: 
            btn_browse_installer_tab3.setText("Browse...")
        btn_browse_installer_tab3.setMinimumHeight(self.monitor_installer_display_tab3.sizeHint().height())
        btn_browse_installer_tab3.setToolTip("Browse for Installer File")
        btn_browse_installer_tab3.clicked.connect(self.browse_installer_tab3)
        installer_select_layout.addWidget(btn_browse_installer_tab3)
        installer_card_layout.addLayout(installer_select_layout)
        layout.addWidget(installer_card)

        target_dir_card = QFrame()
        target_dir_card.setObjectName("cardFrame")
        target_dir_card_layout = QVBoxLayout(target_dir_card)
        target_dir_card_layout.setSpacing(5)

        target_dir_label = QLabel("2. Select Target Installation Directory")
        target_dir_label.setObjectName("cardTitle")
        target_dir_card_layout.addWidget(target_dir_label)
        
        dir_select_layout = QHBoxLayout()
        self.monitor_target_dir_display_tab3 = QLineEdit("No target directory selected") 
        self.monitor_target_dir_display_tab3.setReadOnly(True)
        self.monitor_target_dir_display_tab3.setObjectName("winInput")
        dir_select_layout.addWidget(self.monitor_target_dir_display_tab3, 1)
        btn_browse_monitor_dir_tab3 = QPushButton() 
        if style: 
            icon_dir = style.standardIcon(QStyle.StandardPixmap.SP_DirIcon)
            btn_browse_monitor_dir_tab3.setIcon(icon_dir)
        else:
            btn_browse_monitor_dir_tab3.setText("Browse...")
        btn_browse_monitor_dir_tab3.setObjectName("winButton")
        btn_browse_monitor_dir_tab3.setMinimumHeight(self.monitor_target_dir_display_tab3.sizeHint().height())
        btn_browse_monitor_dir_tab3.setToolTip("Browse for Target Directory")
        btn_browse_monitor_dir_tab3.clicked.connect(self.browse_target_directory_tab3)
        dir_select_layout.addWidget(btn_browse_monitor_dir_tab3)
        target_dir_card_layout.addLayout(dir_select_layout)
        layout.addWidget(target_dir_card)
        
        action_button_layout_tab3 = QHBoxLayout()
        action_button_layout_tab3.addStretch(1)
        self.monitor_toggle_button_tab3 = QPushButton("Start Monitoring Installation") 
        self.monitor_toggle_button_tab3.setObjectName("monitor_toggle_button_tab3") 
        self.monitor_toggle_button_tab3.setProperty("state", "start") 
        if style:
            self.icon_play_monitor = style.standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
            self.icon_stop_monitor = style.standardIcon(QStyle.StandardPixmap.SP_MediaStop)
            self.monitor_toggle_button_tab3.setIcon(self.icon_play_monitor)
        self.monitor_toggle_button_tab3.clicked.connect(self.toggle_monitoring_process_tab3) 
        action_button_layout_tab3.addWidget(self.monitor_toggle_button_tab3)
        action_button_layout_tab3.addStretch(1)
        layout.addLayout(action_button_layout_tab3)
        
        layout.addWidget(QLabel("Monitoring Progress:"))
        self.progress_bar_tab3 = QProgressBar()
        self.progress_bar_tab3.setValue(0)
        self.progress_bar_tab3.setTextVisible(True)
        layout.addWidget(self.progress_bar_tab3)

        layout.addWidget(QLabel("Monitoring Log & Results:"))
        self.terminal_monitoring_tab3 = QTextEdit() 
        self.terminal_monitoring_tab3.setPlaceholderText("Monitoring logs and comparison results will appear here...\nSelect installer and target directory, then start monitoring.")
        self.terminal_monitoring_tab3.setReadOnly(True) 
        self.terminal_monitoring_tab3.setObjectName("winTextarea") 
        self.terminal_monitoring_tab3.setFixedHeight(150) 
        layout.addWidget(self.terminal_monitoring_tab3)
        
        layout.addStretch(1)
        return pane

    def create_tab4_ui(self):
        pane, layout = self.create_tab_pane_widget()
        title = QLabel("Configuration")
        title.setObjectName("tabTitle")
        layout.addWidget(title)
        desc = QLabel("This tab is for adjusting application settings and preferences. Changes are saved automatically.")
        desc.setObjectName("tabDescription")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        saving_title = QLabel("File Saving Preferences")
        saving_title.setObjectName("subTitle") 
        layout.addWidget(saving_title)

        saving_frame = QFrame() 
        saving_frame.setObjectName("configSectionFrame")
        saving_frame_layout = QVBoxLayout(saving_frame)
        saving_frame_layout.setSpacing(10)

        format_label = QLabel("Default Checksum File Format:")
        self.config_save_format_combo = QComboBox()
        self.config_save_format_combo.setObjectName("winSelect")
        self.config_save_format_combo.addItems(["JSON Format (.json)", "Plain Text (.txt)", "MD5SUM Format (.md5)"]) 
        self.config_save_format_combo.currentIndexChanged.connect(self.handle_save_format_changed) 
        saving_frame_layout.addWidget(format_label)
        saving_frame_layout.addWidget(self.config_save_format_combo)
        
        save_dir_layout = QHBoxLayout()
        save_dir_label = QLabel("Current Default Save Directory:")
        self.config_current_save_dir_display = QLineEdit(self.default_save_directory)
        self.config_current_save_dir_display.setReadOnly(True)
        self.config_current_save_dir_display.setObjectName("winInput")
        save_dir_layout.addWidget(save_dir_label)
        save_dir_layout.addWidget(self.config_current_save_dir_display, 1)
        saving_frame_layout.addLayout(save_dir_layout)


        self.config_set_save_dir_button = QPushButton("Set Default Save Directory") 
        self.config_set_save_dir_button.setObjectName("winButton")
        saving_frame_layout.addWidget(self.config_set_save_dir_button)
        
        note1 = QLabel("Note: Checksum files from 'Custom Extract' and 'Update Monitoring' are saved to the 'checksum' subfolder within the chosen directory (or script directory by default).")
        note1.setObjectName("configNote")
        note1.setWordWrap(True)
        saving_frame_layout.addWidget(note1)
        
        layout.addWidget(saving_frame)

        other_title = QLabel("Other Preferences")
        other_title.setObjectName("subTitle")
        layout.addWidget(other_title)
        other_frame = QFrame()
        other_frame.setObjectName("configSectionFrame")
        other_frame_layout = QVBoxLayout(other_frame)
        other_desc = QLabel("Future settings could include default algorithm preferences, theme selection, etc.")
        other_desc.setObjectName("infoText")
        other_desc.setWordWrap(True)
        other_frame_layout.addWidget(other_desc)
        layout.addWidget(other_frame)

        layout.addStretch(1)
        return pane

    def create_tab5_ui(self):
        pane, layout = self.create_tab_pane_widget()
        title = QLabel("About Mr. Hasher") 
        title.setObjectName("tabTitle")
        layout.addWidget(title)
        
        version_label = QLabel("<strong>Version:</strong> 1.9.1 (Functional Configuration & UI Enhancements)") 
        version_label.setTextFormat(Qt.TextFormat.RichText) 
        layout.addWidget(version_label)
        
        desc1_text = (
            "Mr. Hasher is a utility designed for file and directory integrity verification. "
            "It provides tools to generate checksums for individual files, extracted archive contents (using 7-Zip), "
            "or entire folders. The 'Update Monitoring' feature allows tracking file system changes "
            "before and after an application installation or update."
        )
        desc1 = QLabel(desc1_text)
        desc1.setWordWrap(True)
        layout.addWidget(desc1)
        
        desc2_text = (
            "<b>Key Features:</b><br>"
            "- <b>Custom Extract:</b> Generate checksums for files, archives, or folders using MD5, SHA1, or SHA256.<br>"
            "- <b>Update Monitoring:</b> Snapshot a directory, monitor an installer, and report file changes.<br>"
            "- <b>Checker:</b> Verify files against an imported checksum list.<br>"
            "- <b>Configuration:</b> Set default save locations and report formats.<br><br>"
            "This application utilizes real hashing algorithms and file system operations. "
            "The 7-Zip functionality requires '7z.exe' to be present in a '7-Zip' subfolder."
        )
        desc2 = QLabel(desc2_text)
        desc2.setTextFormat(Qt.TextFormat.RichText) # Enable HTML rendering
        desc2.setWordWrap(True)
        layout.addWidget(desc2)

        copyright_label = QLabel("&copy; 2024-2025 Your App Company. All Rights Reserved (for demo purposes).")
        copyright_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(copyright_label)
        
        layout.addStretch(1)
        return pane

    def switch_tab(self, initial_target=None):
        sender_button = self.sender()
        target_tab_id = initial_target 

        if sender_button: 
            target_tab_id = sender_button.property("tabTarget")
        
        if not target_tab_id: return

        for btn in self.sidebar_buttons:
            if btn.property("tabTarget") == target_tab_id:
                btn.setProperty("active", True)
            else:
                btn.setProperty("active", False)
            btn.style().polish(btn) 

        if target_tab_id == "tab1": self.stacked_content.setCurrentWidget(self.tab1_widget)
        elif target_tab_id == "tab3": self.stacked_content.setCurrentWidget(self.tab3_widget) 
        elif target_tab_id == "tab2": self.stacked_content.setCurrentWidget(self.tab2_widget) 
        elif target_tab_id == "tab4": self.stacked_content.setCurrentWidget(self.tab4_widget)
        elif target_tab_id == "tab5": self.stacked_content.setCurrentWidget(self.tab5_widget)

    def start_loading_process(self, bar_id, duration, on_complete_callback, toggle_button_element=None): 
        self.active_loading_bar = bar_id
        self.active_toggle_button = toggle_button_element 
        self.loading_progress = 0
        self.on_loading_complete_callback = on_complete_callback
        
        progress_bar = None
        if bar_id == "loading-bar-tab1": progress_bar = self.progress_bar_tab1
        elif bar_id == "loading-bar-tab2-verify": progress_bar = self.progress_bar_tab2_verify
        
        if progress_bar: 
            progress_bar.setValue(0)
            progress_bar.setFormat("%p%") 
            self.loading_timer.stop() 
            self.loading_timer_duration_total_steps = 100 
            self.loading_timer_step_duration = duration // self.loading_timer_duration_total_steps if self.loading_timer_duration_total_steps > 0 else duration
            if self.loading_timer_step_duration <= 0: self.loading_timer_step_duration = 20 
            self.loading_timer.start(self.loading_timer_step_duration)

    def update_loading_bar(self): 
        self.loading_progress += 1
        progress_bar = None
        if self.active_loading_bar == "loading-bar-tab1": progress_bar = self.progress_bar_tab1
        elif self.active_loading_bar == "loading-bar-tab2-verify": progress_bar = self.progress_bar_tab2_verify
        
        if progress_bar:
            progress_bar.setValue(self.loading_progress)

        if self.loading_progress >= 100:
            self.loading_timer.stop()
            if progress_bar: progress_bar.setFormat("Complete!")
            if self.active_toggle_button: 
                if self.active_toggle_button.objectName() == 'extract_toggle_button_tab1': 
                    self.reset_button_state_pyqt(self.extract_toggle_button_tab1, "Start Extraction", True, start_icon=self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
            
            if self.on_loading_complete_callback:
                self.on_loading_complete_callback()
                self.on_loading_complete_callback = None 

            self.active_loading_bar = None
            self.active_toggle_button = None


    def stop_loading_process(self): 
        self.loading_timer.stop()
        progress_bar = None
        if self.active_loading_bar == "loading-bar-tab1": progress_bar = self.progress_bar_tab1
        elif self.active_loading_bar == "loading-bar-tab2-verify": progress_bar = self.progress_bar_tab2_verify
        
        if progress_bar and self.loading_progress < 100 :
             progress_bar.setFormat(f"Stopped at {self.loading_progress}%")
        
        if self.active_toggle_button:
            if self.active_toggle_button.objectName() == 'extract_toggle_button_tab1': 
                self.reset_button_state_pyqt(self.extract_toggle_button_tab1, "Start Extraction", True, start_icon=self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        
        self.active_loading_bar = None
        self.active_toggle_button = None 
        self.loading_progress = 0


    def reset_button_state_pyqt(self, button, start_text, is_start_state, start_icon=None, stop_icon=None):
        if button: 
            if is_start_state:
                button.setText(start_text)
                button.setProperty("state", "start")
                if start_icon: button.setIcon(start_icon)
                button.setProperty("primaryAction", "true") 
                button.setProperty("cancelAction", "false")
            else:
                stop_action = start_text.split(' ')[1] if len(start_text.split(' ')) > 1 else "Process"
                button.setText(f"Stop {stop_action}")
                button.setProperty("state", "stop")
                if stop_icon: button.setIcon(stop_icon)
                button.setProperty("primaryAction", "false")
                button.setProperty("cancelAction", "true") 
            button.style().polish(button) 

    #I inverted the tab orders, but does no affect the handling. tab 3 to tab 2. Update monitoring to Checker tab. :D
    # --- Tab 1 Specific Logic ---
    def browse_archive_tab1(self): 
        fileName, _ = QFileDialog.getOpenFileName(self, "Select Archive File", "", "Archives (*.zip *.rar *.7z *.exe *.msi);;All Files (*)")
        if fileName:
            self.extract_file_display_tab1.setText(fileName) 
        else:
            self.extract_file_display_tab1.setText("No file selected")
            
    def toggle_extract_and_checksum_process_tab1(self): 
        button = self.sender()
        button.setObjectName("extract_toggle_button_tab1") 
        is_starting = button.property("state") == "start"

        if is_starting:
            archive_path = self.extract_file_display_tab1.text()
            if not archive_path or archive_path == "No file selected":
                QMessageBox.warning(self, "Input Error", "Please select an archive file first.")
                return
            
            self.terminal_extract_tab1.clear()
            self.terminal_extract_tab1.append(f"Selected archive: <b>{os.path.basename(archive_path)}</b>")
            self.terminal_extract_tab1.append(f"Using algorithm: <b>{self.extract_algorithm_combo_tab1.currentText()}</b>")
            QApplication.processEvents()
            
            play_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
            stop_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop)
            self.reset_button_state_pyqt(button, "Start Extract & Checksum", False, start_icon=play_icon, stop_icon=stop_icon) 
            
            if os.path.exists(self.temp_extraction_path):
                self.terminal_extract_tab1.append(f"<i>Attempting to remove existing temp folder: {self.temp_extraction_path}</i>")
                QApplication.processEvents()
                success, logs = backend.cleanup_temp_folder(self.temp_extraction_path)
                for log_msg in logs:
                    self.terminal_extract_tab1.append(f"<i>{log_msg}</i>")
                if not success:
                    QMessageBox.warning(self, "Cleanup Failed", f"Could not remove existing temp folder: {self.temp_extraction_path}. Please check permissions or remove it manually.")
                    self.reset_button_state_pyqt(button, "Start Extract & Checksum", True, start_icon=play_icon, stop_icon=stop_icon)
                    return

            self.start_loading_process("loading-bar-tab1", 2000, self.on_extract_and_checksum_complete_tab1, button) 
        else:
            self.stop_loading_process() 
            self.terminal_extract_tab1.append("<b>Process stopped by user.</b>")

    def on_extract_and_checksum_complete_tab1(self): 
        archive_path = self.extract_file_display_tab1.text()
        algorithm = self.extract_algorithm_combo_tab1.currentText()
        
        self.terminal_extract_tab1.append("<i>UI: Calling backend to extract and generate checksums...</i>")
        QApplication.processEvents()

        result = backend.extract_archive_and_generate_checksums_for_contents(
            archive_path, 
            self.temp_extraction_path, 
            algorithm,
            self.default_save_directory, 
            self.config_save_format_combo.currentText() 
        )
        
        self.terminal_extract_tab1.append("<br><b>--- Backend Process Log ---</b>")
        QApplication.processEvents()
        has_7zip_output_started = False
        has_checksum_gen_started = False

        for log_msg in result.get("logs", []):
            if "ERROR:" in log_msg or "WARNING:" in log_msg:
                self.terminal_extract_tab1.append(f"<font color='red'>{log_msg}</font>")
            elif "7-Zip Output:" in log_msg and not has_7zip_output_started:
                self.terminal_extract_tab1.append("<br><b>--- 7-Zip Detailed Output ---</b>")
                has_7zip_output_started = True
                self.terminal_extract_tab1.append(log_msg) 
            elif "Generating checksums for extracted contents..." in log_msg and not has_checksum_gen_started:
                self.terminal_extract_tab1.append("<br><b>--- Checksum Generation ---</b>")
                has_checksum_gen_started = True
                self.terminal_extract_tab1.append(log_msg)
            else:
                self.terminal_extract_tab1.append(f"<i>{log_msg}</i>")
            QApplication.processEvents() 
        
        self.terminal_extract_tab1.append("---------------------------")
        
        if result["status"] == "success" and result["json_path"]:
            self.terminal_extract_tab1.append(f"<br><b><font color='green'>SUCCESS:</font></b> Checksum file generated at: <b>{result['json_path']}</b>")
            self.terminal_extract_tab1.append("Temporary extraction folder will now be cleaned up.")
            QMessageBox.information(self, 
                                    "Process Complete", 
                                    f"Extraction and checksum generation successful.\n"
                                    f"Checksums file saved to:\n{result['json_path']}\n\n"
                                    f"Temporary extraction folder is being cleaned up.")
        else:
            self.terminal_extract_tab1.append(f"<br><b><font color='red'>PROCESS FAILED:</font></b> {result['message']}")
            QMessageBox.warning(self, "Process Failed", f"Extraction and checksum generation failed: {result['message']}")
        QApplication.processEvents()

        self.terminal_extract_tab1.append("<br><b>--- Cleanup ---</b>")
        QApplication.processEvents()
        cleaned_successfully, cleanup_logs = backend.cleanup_temp_folder(self.temp_extraction_path)
        for log_msg in cleanup_logs:
            self.terminal_extract_tab1.append(f"<i>{log_msg}</i>")
        if cleaned_successfully:
            self.terminal_extract_tab1.append("Temporary files cleaned up successfully.")
        else:
            self.terminal_extract_tab1.append("<font color='red'>ERROR: Failed to clean up all temporary files. Please check manually.</font>")
            QMessageBox.warning(self, "Cleanup Warning", "Failed to clean up all temporary files from the extraction process. Please check the 'temp_extraction' folder manually.")
        QApplication.processEvents()
        
        play_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
        self.reset_button_state_pyqt(self.extract_toggle_button_tab1, "Start Extract & Checksum", True, start_icon=play_icon)


    # --- Tab 2 Specific Logic ---
    def import_checksum_file_tab2(self):
        fileName, _ = QFileDialog.getOpenFileName(self, "Import Checksum File", "", "Text Files (*.txt);;JSON Files (*.json);;MD5 Files (*.md5);;SHA256 Files (*.sha256);;All Files (*)")
        if fileName:
            self.checksum_file_display_tab2.setText(fileName.split('/')[-1])
            try:
                with open(fileName, 'r', encoding='utf-8') as f: 
                    contents = f.read()
                self.imported_checksum_data_tab2 = backend.parse_checksum_file_content(contents)
                self.terminal_checker_tab2.clear()
                
                if not self.imported_checksum_data_tab2:
                    self.terminal_checker_tab2.append(f"File \"{fileName.split('/')[-1]}\" imported, but <b>no valid checksum entries found</b> or file is empty/not recognized.")
                else:
                    self.terminal_checker_tab2.append(f"Successfully imported <b>{len(self.imported_checksum_data_tab2)}</b> checksum entries from \"{fileName.split('/')[-1]}\". Ready for verification.")

            except Exception as e:
                QMessageBox.critical(self, "Import Error", f"Could not read or parse checksum file: {e}")
                self.imported_checksum_data_tab2 = []
                self.terminal_checker_tab2.append(f"<font color='red'>Error importing file: {fileName.split('/')[-1]}</font>")
        else:
            self.checksum_file_display_tab2.setText("No checksum file selected")
            self.imported_checksum_data_tab2 = []
            self.terminal_checker_tab2.append("Checksum file import cancelled.")


    def verify_directory_tab2(self):
        if not self.imported_checksum_data_tab2:
            QMessageBox.warning(self, "Verification Error", "Please import a checksum file with valid entries first.")
            return
        
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory to Verify")
        if not dir_path:
            self.terminal_checker_tab2.append("Directory selection cancelled. Verification aborted.")
            return

        self.terminal_checker_tab2.append(f"<br><b>Starting verification for directory: {dir_path}...</b>")
        QApplication.processEvents()
        self.start_loading_process("loading-bar-tab2-verify", len(self.imported_checksum_data_tab2) * 100, self.on_verify_complete_tab2, None) 

    def on_verify_complete_tab2(self):
        self.terminal_checker_tab2.append("<i>UI: Calling backend for verification logic...</i>")
        QApplication.processEvents()
        verification_results = backend.perform_verification_logic(list(self.imported_checksum_data_tab2)) 
        
        for item in verification_results:
            status_color = "green"
            if item['status'] == "MISMATCH": status_color = "orange"
            elif item['status'] == "FILE NOT FOUND": status_color = "red"
            
            log_entry = (f"File: <b>{item['filename']}</b> - Imported: {item['imported_checksum']} - "
                         f"Local (Sim): {item['local_checksum']} - Status: <font color='{status_color}'><b>{item['status']}</b></font>")
            self.terminal_checker_tab2.append(log_entry)
        QApplication.processEvents()

        self.terminal_checker_tab2.append("<br><b>Verification process complete.</b>")
        QMessageBox.information(self, "Verification Complete", "File verification simulation complete! Check the terminal for detailed results.")
        
    def save_checker_report_tab2(self):
        report_content = self.terminal_checker_tab2.toPlainText() 
        if not report_content.strip():
            QMessageBox.warning(self, "No Data", "There is no report data in the terminal to save.")
            return

        initial_dir = self.default_save_directory if self.default_save_directory and os.path.isdir(self.default_save_directory) else script_dir
        
        fileName, _ = QFileDialog.getSaveFileName(self, "Save Report As...", initial_dir, "Text Files (*.txt);;All Files (*)")
        if fileName:
            if not fileName.lower().endswith(".txt"):
                fileName += ".txt"
            try:
                with open(fileName, 'w', encoding='utf-8') as f:
                    f.write(report_content) 
                QMessageBox.information(self, "Report Saved", f"Report saved successfully to:\n{fileName}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Could not save report: {e}")


    # --- Tab 3 Specific Logic (Update Monitoring with backend2) ---
    def browse_installer_tab3(self):
        fileName, _ = QFileDialog.getOpenFileName(self, "Select Installer File", "", "Executables (*.exe *.msi);;All Files (*)")
        if fileName:
            self.monitor_installer_display_tab3.setText(fileName)
            self.monitoring_installer_path_tab3 = fileName
        else:
            self.monitor_installer_display_tab3.setText("No installer selected (optional)")
            self.monitoring_installer_path_tab3 = None

    def browse_target_directory_tab3(self): 
        dirName = QFileDialog.getExistingDirectory(self, "Select Target Installation Directory")
        if dirName:
            self.monitor_target_dir_display_tab3.setText(dirName) 
            self.monitoring_target_directory_tab3 = dirName 
            self.terminal_monitoring_tab3.append(f"Monitoring directory set to: <b>{dirName}</b>")
            QApplication.processEvents()
        else:
            self.monitor_target_dir_display_tab3.setText("No target directory selected")
            self.monitoring_target_directory_tab3 = None

    def toggle_monitoring_process_tab3(self):
        button = self.monitor_toggle_button_tab3 
        
        worker_is_valid_and_running = False
        if isinstance(self.monitoring_worker_tab3, MonitoringWorker): 
            if self.monitoring_worker_tab3.isRunning():
                worker_is_valid_and_running = True
        
        if worker_is_valid_and_running:
            self.terminal_monitoring_tab3.append("<b>UI: User requested cancellation of monitoring process...</b>")
            QApplication.processEvents()
            self.monitoring_worker_tab3.request_stop()
        else:
            if not self.monitoring_target_directory_tab3:
                QMessageBox.warning(self, "Input Error", "Please select the target installation directory to monitor.")
                return
            if not self.monitoring_installer_path_tab3:
                QMessageBox.warning(self, "Input Error", "Please select an installer file (.exe, .msi) to monitor.")
                return

            self.terminal_monitoring_tab3.clear()
            self.terminal_monitoring_tab3.append(f"Selected Installer: <b>{os.path.basename(self.monitoring_installer_path_tab3)}</b>")
            self.terminal_monitoring_tab3.append(f"Monitoring Target Directory: <b>{self.monitoring_target_directory_tab3}</b>")
            QApplication.processEvents()
            
            self.reset_button_state_pyqt(button, "Start Monitoring Installation", False, start_icon=self.icon_play_monitor, stop_icon=self.icon_stop_monitor)
            
            self.progress_bar_tab3.setValue(0) 
            self.progress_bar_tab3.setFormat("Starting...")
            QApplication.processEvents()
            
            self.monitoring_worker_tab3 = MonitoringWorker(
                self.integrity_verifier_tab3,
                self.monitoring_installer_path_tab3,
                self.monitoring_target_directory_tab3,
                self.default_save_directory,
                self.config_save_format_combo.currentText() 
            )
            self.monitoring_worker_tab3.log_message.connect(self.log_to_tab3_terminal)
            self.monitoring_worker_tab3.progress_update.connect(self.update_tab3_progress)
            self.monitoring_worker_tab3.process_error.connect(self.handle_tab3_process_error)
            self.monitoring_worker_tab3.process_finished_successfully.connect(self.handle_tab3_process_finished)
            self.monitoring_worker_tab3.finished.connect(self.on_monitoring_worker_finished_tab3)
            
            self.integrity_verifier_tab3.was_manually_stopped = False
            self.monitoring_worker_tab3.start()

    def log_to_tab3_terminal(self, message):
        self.terminal_monitoring_tab3.append(message) 
        QApplication.processEvents() 

    def update_tab3_progress(self, value, format_str):
        self.progress_bar_tab3.setValue(value)
        self.progress_bar_tab3.setFormat(format_str if "%p%" in format_str else f"{format_str} %p%")
        QApplication.processEvents()

    def handle_tab3_process_error(self, error_message):
        self.terminal_monitoring_tab3.append(f"<br><b><font color='red'>ERROR:</font></b> {error_message}")
        QApplication.processEvents()
        QMessageBox.critical(self, "Monitoring Process Error", error_message)
        self.progress_bar_tab3.setFormat("Error!")
        self.reset_button_state_pyqt(self.monitor_toggle_button_tab3, "Start Monitoring Installation", True, start_icon=self.icon_play_monitor, stop_icon=self.icon_stop_monitor)
        if self.monitoring_worker_tab3: 
            self.monitoring_worker_tab3.deleteLater()
            self.monitoring_worker_tab3 = None


    def handle_tab3_process_finished(self, report_file_path):
        self.terminal_monitoring_tab3.append("<br><b>Update monitoring process fully complete.</b>")
        if report_file_path and report_file_path != "N/A":
            self.terminal_monitoring_tab3.append(f"Final report saved to: <b>{report_file_path}</b>")
            QMessageBox.information(self, "Monitoring Complete", f"Update monitoring and comparison finished.\nReport saved to: {report_file_path}")
        else:
            QMessageBox.information(self, "Monitoring Complete", "Update monitoring and comparison finished. Check the log for details (no report file generated if no changes or error).")
        
        self.progress_bar_tab3.setValue(100)
        self.progress_bar_tab3.setFormat("Complete!")
        self.reset_button_state_pyqt(self.monitor_toggle_button_tab3, "Start Monitoring Installation", True, start_icon=self.icon_play_monitor, stop_icon=self.icon_stop_monitor)
        self.integrity_verifier_tab3.snapshot_before = None 
        self.integrity_verifier_tab3.snapshot_after = None

    def on_monitoring_worker_finished_tab3(self):
        self.terminal_monitoring_tab3.append("<i>UI: Monitoring worker thread finished.</i>")
        QApplication.processEvents()
        self.reset_button_state_pyqt(self.monitor_toggle_button_tab3, "Start Monitoring Installation", True, start_icon=self.icon_play_monitor, stop_icon=self.icon_stop_monitor)
        
        if self.monitoring_worker_tab3:
            self.monitoring_worker_tab3.deleteLater()
            self.monitoring_worker_tab3 = None
        
        self.integrity_verifier_tab3.snapshot_before = None
        self.integrity_verifier_tab3.snapshot_after = None


    # --- Shared Utility --- 
    def show_copy_to_clipboard_alert_pyqt(self, type_str, content_str): 
        QMessageBox.information(self, f"Simulated {type_str} Save", f"{type_str} Content (Simulated Copy to Clipboard):\n------------------------------------\n{content_str}\n------------------------------------\n\nThis content would typically be copied to your clipboard. For this simulation, please copy the text manually if needed.")


    # --- Tab 4: Configuration Logic ---
    def handle_set_default_save_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Default Save Directory", self.default_save_directory)
        if dir_path:
            self.default_save_directory = dir_path
            self.config_current_save_dir_display.setText(self.default_save_directory)
            self.save_config() 
            QMessageBox.information(self, "Configuration Update", f"Default save directory set to:\n{self.default_save_directory}")

    def handle_save_format_changed(self):
        self.default_checksum_format = self.config_save_format_combo.currentText()
        self.save_config() 
        QMessageBox.information(self, "Configuration Update", f"Default checksum format set to: {self.default_checksum_format}")


    def setup_config_tab_events(self): 
        self.config_set_save_dir_button.clicked.connect(self.handle_set_default_save_directory)
        self.config_save_format_combo.currentIndexChanged.connect(self.handle_save_format_changed)


    def apply_styles(self):
        font = QFont("Segoe UI", 9) 
        QApplication.setFont(font)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #0078D4; 
            }
            QWidget#sidebar {
                background-color: #E1E1E1;
                border-right: 1px solid #C0C0C0;
            }
            QPushButton#sidebarButton {
                padding: 10px 15px;
                text-align: left;
                background-color: #D4D4D4;
                border: 1px solid #B0B0B0;
                border-radius: 3px;
                font-size: 10pt; 
                color: #000000;
                margin-bottom: 5px; 
            }
            QPushButton#sidebarButton:hover {
                background-color: #C0C0C0;
            }
            QPushButton#sidebarButton[active="true"] { 
                background-color: #0078D4;
                color: white;
                border-color: #0053A0;
            }
            QPushButton#sidebarButton QLabel { 
                color: white;
            }
            QPushButton#sidebarButton img[active="true"] { 
                 filter: brightness(0) invert(1);
            }

            QWidget#mainContent { 
                background-color: #F0F0F0; 
                border: 1px solid #B0B0B0; 
                border-radius: 0px 8px 8px 0px; 
            }
            QWidget#tabPane { 
                background-color: #F0F0F0;
            }
            QLabel { 
                color: #000000; /* Default black for all QLabels */
            }
            QLabel#tabTitle {
                font-size: 14pt; 
                font-weight: bold;
                margin-bottom: 10px;
                color: #000000; 
            }
            QLabel#cardTitle {
                font-size: 10pt;
                font-weight: bold;
                color: #222222; 
                margin-bottom: 3px;
            }
            QLabel#helperText {
                font-size: 8pt;
                color: #555555; 
                font-style: italic;
            }
            QLabel#tabDescription, QLabel#infoText, QLabel#configNote {
                font-size: 9pt;
                color: #4B5563; 
                margin-bottom: 10px;
            }
             QLabel#subTitle {
                font-size: 11pt;
                font-weight: bold;
                color: #333333;
                margin-top: 10px;
                margin-bottom: 5px;
                border-bottom: 1px solid #CCCCCC;
                padding-bottom: 3px;
            }
            QFrame#configSectionFrame, QFrame#cardFrame { 
                border: 1px solid #C0C0C0;
                border-radius: 4px;
                background-color: #F8F8F8; 
                padding: 10px;
                margin-bottom: 10px;
            }

            QPushButton#winButton, QPushButton { 
                background-color: #E1E1E1;
                border: 1px solid #ADADAD;
                padding: 6px 12px;
                font-size: 10pt;
                color: #000000;
                border-radius: 3px;
            }
            QPushButton#winButton:hover, QPushButton:hover {
                background-color: #E5F1FB;
                border-color: #0078D4;
            }
            QPushButton#winButton:pressed, QPushButton:pressed {
                background-color: #CCE4F7;
                border-color: #005A9E;
            }
            QPushButton#extract_toggle_button_tab1[state="start"], 
            QPushButton#monitor_toggle_button_tab3[state="start"] { 
                background-color: #22C55E; color: white; font-weight: bold;
            }
            QPushButton#extract_toggle_button_tab1[state="start"]:hover:!disabled, 
            QPushButton#monitor_toggle_button_tab3[state="start"]:hover:!disabled {
                background-color: #16A34A;
            }

            QPushButton#extract_toggle_button_tab1[state="stop"],
            QPushButton#monitor_toggle_button_tab3[state="stop"] { 
                background-color: #EF4444; color: white; font-weight: bold;
            }
            QPushButton#extract_toggle_button_tab1[state="stop"]:hover:!disabled,
            QPushButton#monitor_toggle_button_tab3[state="stop"]:hover:!disabled {
                background-color: #DC2626;
            }
            
            QPushButton#winButton[primaryAction="true"] { 
                background-color: #22C55E; 
                color: white;
                font-weight: bold;
            }
            QPushButton#winButton[primaryAction="true"]:hover:!disabled {
                background-color: #16A34A;
            }
            QPushButton#winButton[cancelAction="true"] { 
                background-color: #EF4444; 
                color: white;
            }
            QPushButton#winButton[cancelAction="true"]:hover:!disabled {
                background-color: #DC2626;
            }

             QPushButton#winButton[enabled="false"], QPushButton[disabled="true"],
             QPushButton#extract_toggle_button_tab1[enabled="false"], QPushButton#extract_toggle_button_tab1[disabled="true"],
             QPushButton#monitor_toggle_button_tab3[enabled="false"], QPushButton#monitor_toggle_button_tab3[disabled="true"] { 
                background-color: #CDCDCD !important; 
                border-color: #A0A0A0 !important;
                color: #707070 !important;
            }


            QLineEdit#winInput, QLineEdit {
                border: 1px solid #767676;
                padding: 6px 8px;
                font-size: 10pt;
                border-radius: 2px;
                background-color: #FFFFFF;
                color: #000000;
            }
            QLineEdit#winInput:focus, QLineEdit:focus {
                border-color: #0078D4;
            }
            QLineEdit[readOnly="true"] {
                 background-color: #F0F0F0; 
            }

            QComboBox#winSelect, QComboBox {
                border: 1px solid #767676;
                padding: 5px 8px; 
                font-size: 10pt;
                border-radius: 2px;
                background-color: #FFFFFF;
                color: #000000; 
            }
            QComboBox#winSelect::drop-down, QComboBox::drop-down {
                border: none;
            }
            QComboBox#winSelect QAbstractItemView, QComboBox QAbstractItemView { 
                background-color: white;
                border: 1px solid #767676;
                selection-background-color: #0078D4;
                color: #000000; 
                selection-color: white; 
            }
             QComboBox::item:selected { 
                background: #0078D4;
                color: white;
            }
            QComboBox::item:!selected { 
                color: #000000;
            }
            QComboBox[enabled="false"] { 
                 background-color: #E0E0E0 !important;
                 color: #707070 !important;
                 border: 1px solid #A0A0A0 !important;
            }


            QProgressBar {
                border: 1px solid #B0B0B0;
                border-radius: 2px;
                text-align: center;
                background-color: #D4D4D4;
                height: 18px; 
            }
            QProgressBar::chunk {
                background-color: #0078D4;
                border-radius: 1px; 
            }
            QTextEdit#winTextarea, QTextEdit { 
                border: 1px solid #767676;
                padding: 8px;
                font-family: Consolas, 'Courier New', monospace; 
                font-size: 9pt; 
                background-color: #FFFFFF;
                color: #000000;
                border-radius: 2px;
            }
        """)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
