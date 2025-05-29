#___  ___       _   _           _               
#|  \/  |      | | | |         | |                  /\ o o o\
#| .  . |_ __  | |_| | __ _ ___| |__   ___ _ __    /o \ o o o\_______
#| |\/| | '__| |  _  |/ _` / __| '_ \ / _ \ '__|  <    >------>   o /|
#| |  | | |_   | | | | (_| \__ \ | | |  __/ |      \ o/  o   /_____/o|
#\_|  |_/_(_)  \_| |_/\__,_|___/_| |_|\___|_|       \/______/     |oo|
#                                                         |   o   |o/
#                                                         |_______|/
import os
import hashlib
import json
import time
import sys
import subprocess
import platform
import psutil 
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple, Optional, Any
import traceback 
import re 
try:
    import integrity_verifier_cy 
    _CYTHON_MODULE_IMPORTED_SUCCESSFULLY = True 
    print("!!! Cython module IMPORTED successfully. !!!")
except ImportError as e:
    _CYTHON_MODULE_IMPORTED_SUCCESSFULLY = False
    print(f"!!! CRITICAL: Could not import Cython module Error: {e} !!!")
    print("!!! The application will NOT function correctly without the Cython module for hashing. !!!")

# ---- CONFIGURATION  ----
CYTHON_AVAILABLE = _CYTHON_MODULE_IMPORTED_SUCCESSFULLY 

if CYTHON_AVAILABLE:
    print("!!! CYTHON IS ENABLED. !!!")
else:
    print("!!! CYTHON MODULE MISSING. !!!") #shit


# --- Functions for ProcessPoolExecutor ---
def _log_debug_worker(message: str):
    """Basic logger for worker processes."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [WORKER] {message}"
    print(log_entry) 

def _walk_error_handler(err):
    """Handles errors during os.walk, prints to stderr of the calling process."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [OS_WALK_ERROR] {err.filename if hasattr(err, 'filename') else str(err)}", file=sys.stderr)


def _fast_hash_py_worker(file_path: str) -> Tuple[str, Optional[str]]: 
    """Fallback Python hashing function (SHOULD NOT BE CALLED IF CYTHON IS MANDATORY AND AVAILABLE).""" #please, ensure this.
    _log_debug_worker(f"WARNING: Python fallback hashing explicitly called for {file_path}.")
    try:
        if not os.path.isfile(file_path): 
            return file_path, None
        file_size = os.path.getsize(file_path)
        if file_size == 0: 
            return file_path, hashlib.sha256(b"").hexdigest()
        
        from mmap import ACCESS_READ, mmap as pymmap 
        mmapped_file_obj = None
        with open(file_path, 'rb') as f:
            try:
                mmapped_file_obj = pymmap(f.fileno(), 0, access=ACCESS_READ)
                hasher = hashlib.sha256()
                hasher.update(mmapped_file_obj)
                return file_path, hasher.hexdigest()
            finally:
                if mmapped_file_obj is not None: mmapped_file_obj.close()
    except PermissionError:
        _log_debug_worker(f"Permission denied for {file_path} (Python fallback)")
        return file_path, None
    except FileNotFoundError: 
        _log_debug_worker(f"File not found during hashing: {file_path} (Python fallback)")
        return file_path, None
    except OSError as e: 
        _log_debug_worker(f"OS error hashing {file_path} (Python fallback): {type(e).__name__} - {str(e)}")
        return file_path, None
    except Exception as e: 
        _log_debug_worker(f"Generic hash failed for {file_path} (Python fallback): {type(e).__name__} - {str(e)}")
        return file_path, None

def _fast_hash_worker(file_path: str) -> Tuple[str, Optional[str]]:
    """Top-level hashing function - Cython only if available."""
    if CYTHON_AVAILABLE: 
        try:
            hash_val = integrity_verifier_cy._fast_hash_cy(file_path) 
            return file_path, hash_val if hash_val else None
        except Exception as e: 
            _log_debug_worker(f"[CYTHON] Hash FAILED for {file_path}: {type(e).__name__} - {str(e)}. No Python fallback will be used.")
            return file_path, None 
    else: 
        _log_debug_worker(f"CRITICAL ERROR: Cython module not available, cannot hash file: {file_path}.")
        return file_path, None 

def _process_batch_worker(file_batch: List[str]) -> Dict[str, str]: 
    """Top-level batch processing function."""
    batch_results = {}
    if not CYTHON_AVAILABLE: 
        _log_debug_worker("CRITICAL ERROR: Cython module not available. Batch processing skipped.")
        return batch_results 

    for path_in_batch in file_batch:
        processed_path, file_hash = _fast_hash_worker(path_in_batch) 
        if file_hash: 
            batch_results[processed_path] = file_hash
    return batch_results

def get_next_monitoring_report_filename(base_dir: str, prefix: str = "monitoring_report_", extension: str = ".json") -> str:
    """
    Determines the next sequential filename (e.g., monitoring_report_1.json or monitoring_report_1.txt).
    """
    try:
        os.makedirs(base_dir, exist_ok=True)
    except OSError as e:
        print(f"Error creating directory {base_dir} for monitoring report: {e}")
        return f"{prefix}1{extension}"

    existing_files = [f for f in os.listdir(base_dir) if os.path.isfile(os.path.join(base_dir, f))]
    max_num = 0
    safe_extension = re.escape(extension)
    # Ensure prefix is matched from the start of the filename
    pattern = rf"^{re.escape(prefix)}(\d+){safe_extension}$" 
    
    for f_name in existing_files:
        match = re.match(pattern, f_name)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num
    return f"{prefix}{max_num + 1}{extension}"


class IntegrityVerifier:
    def __init__(self):
        self.chunk_size = 1 * 1024 * 1024 
        self.max_workers = os.cpu_count() 
        self.file_batch_size = 4000 
        self.monitoring_timeout = 3600  
        self.post_install_delay = 5  

        self.system_drives = self._get_system_drives() 
        self.exclude_dirs = self._get_default_exclude_dirs()
        self.exclude_extensions = {'.log', '.tmp', '.bak', '.cache', '.pdb', '.obj', '.ilk', '.DS_Store', '.swp', '.swo'}

        self.install_path: Optional[str] = None
        self.snapshot_before: Optional[Dict[str, str]] = None
        self.snapshot_after: Optional[Dict[str, str]] = None
        self.installer_pid: Optional[int] = None
        self.debug_log: List[str] = []
        self.proc: Optional[subprocess.Popen] = None 
        self.was_manually_stopped: bool = False 

    def _log_debug(self, message: str):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.debug_log.append(log_entry)
        print(log_entry) 

    def _get_system_drives(self) -> List[str]:
        paths_to_scan = []
        if platform.system() == "Windows":
            program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
            program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
            paths_to_scan.extend([pf for pf in [program_files, program_files_x86] if pf]) 
        else: 
            paths_to_scan.extend(['/usr/local', '/opt', '/Applications'])
            user_home = os.path.expanduser('~')
            paths_to_scan.extend([
                os.path.join(user_home, '.local'), 
                os.path.join(user_home, 'Applications') 
            ])
        return [p for p in paths_to_scan if p and os.path.exists(p) and os.path.isdir(p)] 

    def _get_default_exclude_dirs(self) -> Set[str]:
        base_excludes = set()
        if platform.system() == "Windows":
            windir = os.environ.get('WINDIR', 'C:\\Windows').lower()
            userprofile = os.environ.get('USERPROFILE', '').lower()
            programdata = os.environ.get('PROGRAMDATA', 'C:\\ProgramData').lower()
            temp_path = os.environ.get('TEMP', os.path.join(userprofile, 'appdata\\local\\temp') if userprofile else '').lower()
            tmp_path = os.environ.get('TMP', '').lower()
            steam_common = os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Steam", "steamapps", "common").lower()
            
            paths_to_add = [
                windir,
                os.path.join(programdata, 'microsoft\\windows defender') if programdata else None,
                'c:\\$recycle.bin', 'c:\\windows.old', 'c:\\msocache',
                temp_path, tmp_path,
                os.path.join(userprofile, 'appdata\\local\\google\\chrome\\user data') if userprofile else None,
                os.path.join(userprofile, 'appdata\\local\\microsoft\\edge\\user data') if userprofile else None,
                os.path.join(userprofile, 'appdata\\roaming\\mozilla\\firefox\\profiles') if userprofile else None,
                os.path.dirname(sys.executable).lower(),
                os.path.join(os.path.dirname(sys.executable).lower(), 'lib', 'site-packages'),
                os.path.join(os.path.abspath(os.path.dirname(__file__)), 'build').lower(),
                os.path.join(steam_common, "DayZ", "!dzsal"), 
                os.path.join(steam_common, "DayZ", "!Workshop") 
            ]
            base_excludes.update(p for p in paths_to_add if p) 
        else: 
            user_home = os.path.expanduser('~').lower()
            base_excludes.update({
                '/dev', '/proc', '/sys', '/tmp', '/var/tmp', '/run', '/mnt', '/media',
                os.path.join(user_home, '.cache'),
                '/var/log', '/var/lib/apt/lists', '/private/var/folders',
                os.path.dirname(sys.executable).lower(),
                os.path.join(os.path.dirname(sys.executable).lower(), 'lib'),
                os.path.join(os.path.abspath(os.path.dirname(__file__)), 'build').lower(),
            })
        return {os.path.normpath(p) for p in base_excludes if p}

    def _should_exclude(self, file_or_dir_path: str) -> bool:
        norm_path = os.path.normpath(file_or_dir_path.lower())
        if os.path.splitext(norm_path)[1] in self.exclude_extensions and '.' in os.path.basename(norm_path):
            return True
        for excluded_dir in self.exclude_dirs:
            if norm_path.startswith(excluded_dir + os.sep) or norm_path == excluded_dir:
                return True
        return False

    def _parallel_scan(self, root_path_to_scan: str) -> Dict[str, str]:
        self._log_debug(f"Starting parallel scan of: {root_path_to_scan}")
        file_hashes: Dict[str, str] = {}

        if not CYTHON_AVAILABLE: 
            self._log_debug(f"CRITICAL: Cython module not available. Cannot perform hash scan for {root_path_to_scan}.")
            return file_hashes 

        if self._should_exclude(root_path_to_scan):
            self._log_debug(f"Skipping excluded root scan path: {root_path_to_scan}")
            return file_hashes
        
        all_files_to_process: List[str] = []
        try:
            for root, dirs, files in os.walk(root_path_to_scan, topdown=True, onerror=_walk_error_handler): 
                if self.was_manually_stopped: 
                    self._log_debug(f"Scan of {root_path_to_scan} aborted during file collection.")
                    return {} 
                dirs[:] = [d for d in dirs if not self._should_exclude(os.path.join(root, d))]
                for file_name in files:
                    full_path = os.path.join(root, file_name)
                    if not self._should_exclude(full_path):
                        if os.path.isfile(full_path) and not os.path.islink(full_path):
                            all_files_to_process.append(full_path)
        except Exception as e:
            self._log_debug(f"Critical error during os.walk in {root_path_to_scan}: {e}")
            return file_hashes 

        if not all_files_to_process:
            self._log_debug(f"No files collected from {root_path_to_scan} for hashing (after exclusions).")
            return file_hashes
        self._log_debug(f"Collected {len(all_files_to_process)} files from {root_path_to_scan} for hashing.")

        executor = None 
        try:
            executor = ProcessPoolExecutor(max_workers=self.max_workers)
            futures_map: Dict[Any, List[str]] = {}
            for i in range(0, len(all_files_to_process), self.file_batch_size):
                if self.was_manually_stopped: 
                    self._log_debug(f"Scan of {root_path_to_scan} aborted before processing all batches.")
                    break 
                batch = all_files_to_process[i:i + self.file_batch_size]
                future = executor.submit(_process_batch_worker, batch) 
                futures_map[future] = batch
            
            processed_count = 0
            total_batches = len(futures_map)
            batch_counter = 0
            log_interval = max(1, total_batches // 20) if total_batches > 0 else 1

            for future in as_completed(futures_map):
                if self.was_manually_stopped: 
                    self._log_debug(f"Scan of {root_path_to_scan} aborted while processing batches.")
                    for f_cancel in futures_map.keys():
                        if not f_cancel.done():
                            f_cancel.cancel()
                    break 
                batch_processed = futures_map[future]
                batch_counter += 1
                try:
                    batch_result = future.result() 
                    if batch_result: 
                        file_hashes.update(batch_result)
                    processed_count += len(batch_processed)
                    if batch_counter % log_interval == 0 or batch_counter == total_batches:
                         self._log_debug(f"Parallel scan progress for {root_path_to_scan}: Batch {batch_counter}/{total_batches} complete. {processed_count}/{len(all_files_to_process)} files processed.")
                except Exception as e:
                    first_file_in_batch = batch_processed[0] if batch_processed else "N/A"
                    self._log_debug(f"Error processing a batch (first file: {first_file_in_batch}, {len(batch_processed)} files total): {type(e).__name__} - {e}")
        finally:
            if executor:
                self._log_debug(f"[{root_path_to_scan}] Explicitly shutting down executor...")
                executor.shutdown(wait=True)
                self._log_debug(f"[{root_path_to_scan}] Executor shutdown complete.")
        
        self._log_debug(f"Completed scan of {root_path_to_scan}. Found {len(file_hashes)} valid file hashes.")
        return file_hashes

    def take_system_snapshot(self) -> Dict[str, str]:
        self.debug_log = [] 
        if not CYTHON_AVAILABLE:
            self._log_debug("CRITICAL ERROR: Cython module is not available. Snapshot cannot be performed as Cython is mandatory.")
            return {} 
            
        self._log_debug("Cython module is active. Starting system snapshot...")
        full_snapshot: Dict[str, str] = {}
        for drive_or_path in self.system_drives: 
            if self.was_manually_stopped: 
                self._log_debug("Snapshot taking aborted manually.")
                break
            if os.path.exists(drive_or_path) and os.path.isdir(drive_or_path):
                self._log_debug(f"Scanning drive/path for snapshot: {drive_or_path}")
                full_snapshot.update(self._parallel_scan(drive_or_path))
            else:
                self._log_debug(f"Skipping non-existent or non-directory path for snapshot: {drive_or_path}")
        self._log_debug(f"System snapshot complete. Total files hashed: {len(full_snapshot)}")
        return full_snapshot

    def _is_process_complete(self, proc_handle: subprocess.Popen, pid_to_check: int) -> bool:
        self._log_debug(f"PID {pid_to_check}: _is_process_complete called.")
        if pid_to_check is None:
            self._log_debug(f"PID {pid_to_check}: _is_process_complete: Called with None PID, assuming complete.")
            return True
        parent_process_obj = None
        try:
            self._log_debug(f"PID {pid_to_check}: Attempting psutil.Process({pid_to_check}).")
            parent_process_obj = psutil.Process(pid_to_check)
            process_name = "N/A"; process_status = "N/A"
            try:
                process_name = parent_process_obj.name(); process_status = parent_process_obj.status()
            except (psutil.NoSuchProcess, psutil.AccessDenied): pass
            self._log_debug(f"PID {pid_to_check}: psutil.Process() access attempt. Name: {process_name}, Status: {process_status}.")
            current_poll = proc_handle.poll() 
            if current_poll is not None:
                self._log_debug(f"PID {pid_to_check} ({process_name}): Popen.poll() is {current_poll}. Main process has exited according to Popen.")
                children = parent_process_obj.children(recursive=True)
                if not children: self._log_debug(f"PID {pid_to_check}: No children found. Process tree complete."); return True
                active_children_found = False
                for child in children:
                    try:
                        if child.is_running() and child.status() not in [psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD]:
                            self._log_debug(f"PID {pid_to_check}: Main proc Popen-ended, but child {child.pid} ({child.name()}) still active (Status: {child.status()})."); active_children_found = True; break
                    except psutil.NoSuchProcess: continue
                    except psutil.AccessDenied: self._log_debug(f"PID {pid_to_check}: Access denied checking child {child.pid} (main Popen-ended). Assuming active."); active_children_found = True; break
                if not active_children_found: self._log_debug(f"PID {pid_to_check}: Main proc Popen-ended, and all children are non-active or gone. Process tree complete."); return True
                self._log_debug(f"PID {pid_to_check}: Main proc Popen-ended, but active children remain. Not complete."); return False
            if not parent_process_obj.is_running() or parent_process_obj.status() in [psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD]:
                self._log_debug(f"PID {pid_to_check} ({process_name}): Popen.poll() is None, but psutil status is {parent_process_obj.status()}. Checking children.")
                children = parent_process_obj.children(recursive=True)
                if not children: self._log_debug(f"PID {pid_to_check}: No children found (psutil says parent {parent_process_obj.status()}). Process tree likely complete."); return True
                active_children_found = False
                for child in children:
                    try:
                        if child.is_running() and child.status() not in [psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD]:
                            self._log_debug(f"PID {pid_to_check}: Main proc psutil status {parent_process_obj.status()}, child {child.pid} ({child.name()}) active (Status: {child.status()})."); active_children_found = True; break
                    except psutil.NoSuchProcess: continue
                    except psutil.AccessDenied: self._log_debug(f"PID {pid_to_check}: Access denied checking child {child.pid} (parent status {parent_process_obj.status()}). Assuming active."); active_children_found = True; break
                if not active_children_found: self._log_debug(f"PID {pid_to_check}: Main proc psutil status {parent_process_obj.status()}, children non-active/gone. Process tree complete."); return True
                self._log_debug(f"PID {pid_to_check}: Main proc psutil status {parent_process_obj.status()}, but active children remain. Not complete."); return False
            self._log_debug(f"PID {pid_to_check} ({process_name}): Main process is active (Popen poll: None, psutil status: {parent_process_obj.status()}). Not complete."); return False
        except psutil.NoSuchProcess: self._log_debug(f"PID {pid_to_check}: psutil.NoSuchProcess encountered when creating parent psutil.Process object. Process likely gone. Assuming complete."); return True
        except psutil.AccessDenied: self._log_debug(f"PID {pid_to_check}: psutil.AccessDenied when trying to create parent psutil.Process object. Assuming not complete to be safe."); return False
        except Exception as e: self._log_debug(f"PID {pid_to_check}: Error in _is_process_complete (outer try/except): {type(e).__name__} - {e}"); return False

    def monitor_installation(self, setup_path: str) -> bool:
        self._log_debug(f"Starting installation monitoring for: {setup_path}")
        if not os.path.exists(setup_path):
            self._log_debug(f"Error: Installer executable not found at '{setup_path}'")
            return False
        if not os.access(setup_path, os.X_OK) and platform.system() != "Windows":
            self._log_debug(f"Warning: Installer at '{setup_path}' may not be executable (check permissions).")

        self.proc = None 
        try:
            installer_dir = os.path.dirname(setup_path)
            if not installer_dir: installer_dir = "." 
            args = [setup_path]
            
            self._log_debug(f"Launching installer: '{setup_path}' with args {args} from CWD: '{installer_dir}'")
            if platform.system() == "Windows":
                self.proc = subprocess.Popen(args, cwd=installer_dir)
            else: 
                self.proc = subprocess.Popen(args, cwd=installer_dir)

            self.installer_pid = self.proc.pid
            if self.installer_pid is None:
                self._log_debug(f"Error: Failed to get PID for '{setup_path}'.")
                return False
            self._log_debug(f"Installer process started with PID: {self.installer_pid}")
            start_time = time.time()
            self._log_debug(f"Monitoring installer PID {self.installer_pid} process completion...")
            
            while True:
                if self.was_manually_stopped: 
                    self._log_debug(f"PID {self.installer_pid}: Detected manual stop request. Breaking monitoring loop.")
                    break 
                if self._is_process_complete(self.proc, self.installer_pid):
                    self._log_debug(f"PID {self.installer_pid}: Installation process and its children appear to have completed.")
                    break
                if time.time() - start_time > self.monitoring_timeout:
                    self._log_debug(f"Monitoring timeout ({self.monitoring_timeout}s) reached for installer PID {self.installer_pid}.")
                    self.request_stop_monitoring() 
                    return False 
                time.sleep(1) 
            
            installer_exit_code = self.proc.poll() 
            if installer_exit_code is None: 
                try:
                    installer_exit_code = self.proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    self._log_debug(f"Installer PID {self.installer_pid} did not exit gracefully after loop, poll is None.")
            
            if self.was_manually_stopped:
                self._log_debug("Installation monitoring was manually stopped by user.")
                return False 

            if installer_exit_code is not None and installer_exit_code != 0:
                self._log_debug(f"Installer PID {self.installer_pid} exited with non-zero code: {installer_exit_code}.")
            else:
                self._log_debug(f"Installer PID {self.installer_pid} exited (Code: {installer_exit_code}).")
            
            self._log_debug(f"Waiting {self.post_install_delay}s for filesystem changes to settle...")
            time.sleep(self.post_install_delay)
            self._log_debug("Installation monitoring phase complete.")
            return True
        except FileNotFoundError: 
            self._log_debug(f"Error: Installer executable not found at '{setup_path}' when trying Popen."); return False
        except PermissionError: 
            self._log_debug(f"Error: Permission denied when trying to execute installer '{setup_path}'."); return False
        except OSError as e: 
            if platform.system() == "Windows" and hasattr(e, 'winerror') and e.winerror == 740:
                self._log_debug(f"OSError [WinError 740]: The requested operation requires elevation for '{setup_path}'. Please run this script as an administrator.")
            else:
                self._log_debug(f"OSError during installation monitoring for '{setup_path}': {type(e).__name__} - {str(e)}")
            import traceback; self._log_debug(traceback.format_exc()); return False
        except psutil.Error as e: 
            self._log_debug(f"psutil error during monitoring setup for '{setup_path}': {type(e).__name__} - {e}"); return False
        except Exception as e:
            self._log_debug(f"Critical error during installation monitoring for '{setup_path}': {type(e).__name__} - {e}")
            import traceback; self._log_debug(traceback.format_exc()); return False
        finally:
            pass

    def request_stop_monitoring(self):
        self._log_debug("External stop monitoring request received in backend.")
        self.was_manually_stopped = True 
        if self.proc and self.installer_pid is not None:
            self._log_debug(f"Attempting to terminate process tree for PID {self.installer_pid} due to stop request...")
            try:
                parent = psutil.Process(self.installer_pid)
                children = parent.children(recursive=True)
                for child in children:
                    try: self._log_debug(f"Terminating child PID {child.pid} ({child.name()})"); child.terminate()
                    except psutil.Error: self._log_debug(f"Could not terminate child {child.pid}, it might already be gone.")
                
                self._log_debug(f"Terminating parent PID {self.installer_pid} ({parent.name()})")
                parent.terminate()
                
                try:
                    self.proc.terminate() 
                    self.proc.wait(timeout=2) 
                    self._log_debug(f"Popen process {self.installer_pid} terminated/waited (poll: {self.proc.poll()}).")
                except subprocess.TimeoutExpired:
                    self._log_debug(f"Popen process {self.installer_pid} did not terminate in time, trying kill.")
                    self.proc.kill()
                    self.proc.wait(timeout=1)
                except Exception as e_popen:
                    self._log_debug(f"Exception during Popen terminate/wait: {e_popen}")

                self._log_debug(f"Process tree for PID {self.installer_pid} termination attempt complete.")
                return True 
            except psutil.NoSuchProcess:
                self._log_debug(f"PID {self.installer_pid} already gone during stop request.")
                if self.proc and self.proc.poll() is None: 
                     self._log_debug(f"Forcing Popen handle to acknowledge process is gone.")
                     try: self.proc.kill(); self.proc.wait(timeout=0.1) 
                     except: pass
            except psutil.Error as ps_e:
                self._log_debug(f"psutil error during stop request for {self.installer_pid}: {ps_e}")
            except Exception as term_e:
                self._log_debug(f"Generic error during stop request for {self.installer_pid}: {term_e}")
        else:
            self._log_debug("No active process (self.proc) or PID (self.installer_pid) to stop for monitoring.")
        return False

    def _identify_changes(self) -> Dict[str, str]:
        self._log_debug("IntegrityVerifier._identify_changes: Starting...")
        if self.snapshot_before is None or self.snapshot_after is None: 
            self._log_debug("IntegrityVerifier._identify_changes: Cannot identify changes: one or both snapshots are missing.")
            return {}
        self._log_debug(f"IntegrityVerifier._identify_changes: Before: {len(self.snapshot_before)} files, After: {len(self.snapshot_after)} files.")
        changes: Dict[str, str] = {}
        
        after_keys = set(self.snapshot_after.keys())
        before_keys = set(self.snapshot_before.keys())

        new_files = after_keys - before_keys
        self._log_debug(f"IntegrityVerifier._identify_changes: Found {len(new_files)} potentially new files.")
        for file_path in new_files:
            changes[file_path] = self.snapshot_after[file_path]
        
        common_files = after_keys.intersection(before_keys)
        self._log_debug(f"IntegrityVerifier._identify_changes: Found {len(common_files)} common files to compare.")
        modified_count = 0
        for file_path in common_files:
            if file_path in self.snapshot_before and file_path in self.snapshot_after:
                 if self.snapshot_before[file_path] != self.snapshot_after[file_path]:
                    changes[file_path] = self.snapshot_after[file_path]
                    modified_count +=1
            elif file_path in self.snapshot_after: 
                changes[file_path] = self.snapshot_after[file_path]
                modified_count +=1


        self._log_debug(f"IntegrityVerifier._identify_changes: Found {modified_count} modified files among common ones.")
        
        self._log_debug(f"IntegrityVerifier._identify_changes: Identified {len(changes)} total new or modified files."); 
        return changes

    def generate_checksums(self, installer_filename_for_report: Optional[str] = None, 
                           output_base_dir: Optional[str] = None, 
                           output_format: str = "JSON Format (.json)") -> Tuple[bool, Optional[str]]:
        self._log_debug("IntegrityVerifier.generate_checksums: Attempting to generate checksums...")
        try:
            if self.snapshot_before is None or self.snapshot_after is None: 
                self._log_debug("IntegrityVerifier.generate_checksums: Snapshots not available. Cannot generate checksums.")
                return False, None
            
            self._log_debug("IntegrityVerifier.generate_checksums: Calling _identify_changes...")
            changes = self._identify_changes()
            self._log_debug(f"IntegrityVerifier.generate_checksums: _identify_changes returned {len(changes)} changes.")

            install_path_for_checksum = self.install_path
            if not install_path_for_checksum and changes:
                dir_counts: Dict[str, int] = {}
                for file_path in changes.keys(): dir_counts[os.path.dirname(file_path)] = dir_counts.get(os.path.dirname(file_path), 0) + 1
                if dir_counts: 
                    install_path_for_checksum = max(dir_counts, key=dir_counts.get)
                    self._log_debug(f"IntegrityVerifier.generate_checksums: Inferred install path for checksum: {install_path_for_checksum}")
                else: 
                    install_path_for_checksum = "Unknown - No common directory found"
                    self._log_debug("IntegrityVerifier.generate_checksums: Could not infer install path, no common directory.")
            elif not install_path_for_checksum and not changes: 
                install_path_for_checksum = "N/A - No changes detected"
                self._log_debug("IntegrityVerifier.generate_checksums: No changes detected, install path set to N/A.")
            
            final_install_path_in_checksum = self.install_path if self.install_path else install_path_for_checksum
            
            current_script_dir = os.path.dirname(os.path.abspath(__file__))
            base_save_dir = output_base_dir if output_base_dir and os.path.isdir(output_base_dir) else current_script_dir
            
            persistent_checksum_dir = os.path.join(base_save_dir, 'checksum')
            try:
                os.makedirs(persistent_checksum_dir, exist_ok=True)
            except OSError as e:
                self._log_debug(f"CRITICAL ERROR: Could not create checksum directory '{persistent_checksum_dir}': {e}")
                return False, None

            
            report_prefix = "monitoring_report_"
            if installer_filename_for_report:
                base_installer_name = os.path.splitext(os.path.basename(installer_filename_for_report))[0]
                safe_base_name = "".join(c if c.isalnum() or c in (' ', '_') else '_' for c in base_installer_name).rstrip()
                report_prefix = f"{safe_base_name}_report_"

            file_extension = ".json" # Default
            if "Plain Text" in output_format:
                file_extension = ".txt"
            elif "MD5SUM Format" in output_format: 
                file_extension = ".txt" 
            
            checksum_filename = get_next_monitoring_report_filename(persistent_checksum_dir, prefix=report_prefix, extension=file_extension)
            full_checksum_path = os.path.join(persistent_checksum_dir, checksum_filename)

            checksum_data_to_save = {
                "monitored_installer": installer_filename_for_report or "N/A",
                "target_directory": final_install_path_in_checksum, 
                "files_changed_or_new": changes, 
                "timestamp": time.time()
            }
            
            self._log_debug(f"IntegrityVerifier.generate_checksums: Preparing to write checksum file: {full_checksum_path}")
            with open(full_checksum_path, "w", encoding='utf-8') as f: 
                if file_extension == ".json":
                    json.dump(checksum_data_to_save, f, indent=2)
                else: 
                    f.write(f"# Monitoring Report for Installer: {checksum_data_to_save['monitored_installer']}\n")
                    f.write(f"# Target Directory: {checksum_data_to_save['target_directory']}\n")
                    f.write(f"# Report Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(checksum_data_to_save['timestamp']))}\n")
                    f.write("# Format: Checksum  RelativeFilePath (to target directory)\n")
                    f.write("--------------------------------------------------\n")
                    if changes:
                        for rel_path, chksum in changes.items():
                            f.write(f"{chksum}  {rel_path}\n")
                    else:
                        f.write("No changes detected.\n")

            self._log_debug(f"IntegrityVerifier.generate_checksums: Report for {len(changes)} new/modified files saved to '{full_checksum_path}'")
            return True, full_checksum_path 
        except Exception as e: 
            self._log_debug(f"IntegrityVerifier.generate_checksums: Failed to generate checksums: {type(e).__name__} - {str(e)}")
            import traceback
            self._log_debug(traceback.format_exc())
            return False, None

    def write_debug_log_to_file(self, filename="integrity_verifier_operation.log"):
        if not self.debug_log: print(f"No debug log entries to write to {filename}."); return
        try:
            with open(filename, "w", encoding='utf-8') as f:
                f.write("Integrity Verifier Log\n========================\n")
                for entry in self.debug_log:
                    f.write(entry + "\n")
                print(f"Debug log written to {filename}")
        except Exception as e:
            print(f"Failed to write debug log to {filename}: {e}")

if __name__ == "__main__":
    if os.name == 'nt': 
       import multiprocessing
       multiprocessing.freeze_support() 

    cli_verifier = IntegrityVerifier()
    main_log_file = "integrity_verifier_cli.log"
    
    if len(sys.argv) > 1 and sys.argv[1].lower() == "monitor":
        cli_verifier.debug_log = []
        if len(sys.argv) < 3: 
            cli_verifier._log_debug("Error: Installer path required for monitor mode.")
            print("Error: Installer path required for monitor mode.")
            print("Usage: python integrity_verifier.py monitor <path_to_installer.exe>")
            sys.exit(1)
        setup_exe_path = sys.argv[2]
        cli_verifier._log_debug(f"CLI MODE: Monitor Installation of '{setup_exe_path}'")
        
        if not CYTHON_AVAILABLE:
            cli_verifier._log_debug("CRITICAL: Cython module is not available. Aborting monitor mode.")
            print("CRITICAL: Cython module 'integrity_verifier_cy' is required but not found. Cannot proceed.")
            sys.exit(1)

        cli_verifier._log_debug("Step 1: Taking pre-install snapshot...")
        target_monitor_dir = os.path.dirname(setup_exe_path) if os.path.dirname(setup_exe_path) else "."
        cli_verifier.system_drives = [target_monitor_dir] 
        cli_verifier._log_debug(f"CLI: Monitoring target directory set to: {target_monitor_dir}")

        cli_verifier.snapshot_before = cli_verifier.take_system_snapshot()
        
        if cli_verifier.was_manually_stopped: 
            print("\nERROR (CLI): Snapshot taking was aborted.")
            sys.exit(1)
        if not cli_verifier.snapshot_before: 
            print("\nERROR (CLI): Pre-install snapshot failed or resulted in no files. Cannot proceed.")
            sys.exit(1)

        cli_verifier._log_debug(f"Step 2: Monitoring installation of '{setup_exe_path}'...")
        print("\n>>> CLI: Please run the installer now and complete the installation. <<<")
        print(">>> CLI: The tool will wait for the installer process to finish.     <<<")
        monitor_success = cli_verifier.monitor_installation(setup_exe_path)
        
        if monitor_success:
            cli_verifier._log_debug("Installation process monitored successfully.")
            cli_verifier._log_debug("Step 3: Taking post-install snapshot...")
            monitoring_logs = list(cli_verifier.debug_log) 
            cli_verifier.snapshot_after = cli_verifier.take_system_snapshot() 
            cli_verifier.debug_log = monitoring_logs + cli_verifier.debug_log 

            if cli_verifier.was_manually_stopped:
                print("\nERROR (CLI): Post-install snapshot taking was aborted.")
                sys.exit(1)
            if not cli_verifier.snapshot_after:
                print("\nERROR (CLI): Post-install snapshot failed or resulted in no files. Cannot generate checksums.")
                sys.exit(1)

            cli_verifier._log_debug(f"Post-install snapshot complete.")
            cli_verifier._log_debug("Step 4: Generating checksums...")
            cli_verifier.install_path = target_monitor_dir 
            success, report_file_path = cli_verifier.generate_checksums(
                installer_filename_for_report=os.path.basename(setup_exe_path),
                output_base_dir=os.path.dirname(os.path.abspath(__file__)), 
                output_format="JSON Format (.json)" 
            )
            if success and report_file_path: 
                print(f"\nSUCCESS (CLI): Monitoring and checksum generation complete. File: {report_file_path}")
            else: 
                print("\nERROR (CLI): Monitoring succeeded, but checksum generation failed.")
        else: 
            print("\nERROR (CLI): Installation monitoring failed or was aborted.")
    elif len(sys.argv) > 1 and sys.argv[1].lower() == "profile":
        print("Profile mode is for testing snapshot performance. Ensure Cython is compiled.")
        if not CYTHON_AVAILABLE:
            print("CRITICAL: Cython module not available. Profiling snapshot with Cython is not possible.")
            sys.exit(1)
        
        import cProfile
        import pstats
        profiler = cProfile.Profile()
        
        test_scope_paths = [
            r"C:\Program Files", 
            r"C:\Program Files (x86)", 
        ]
        valid_test_scope = [p for p in test_scope_paths if os.path.exists(p) and os.path.isdir(p)]
        if not valid_test_scope:
            print("Error: No valid directories specified in test_scope_paths for profiling. Exiting.")
            sys.exit(1)
            
        cli_verifier.system_drives = valid_test_scope 
        print(f"Starting profiled run (Cython)... Scope: {cli_verifier.system_drives}")

        cli_verifier.debug_log = [] 
        profiler.enable()
        snapshot_result = cli_verifier.take_system_snapshot() 
        profiler.disable()
        
        print(f"Profiled run (Cython) finished. Files in snapshot: {len(snapshot_result)}")
        stats_filename = "profile_stats_cython_only.prof"
        profiler.dump_stats(stats_filename)
        print(f"Profile stats saved to {stats_filename}. You can view with: snakeviz {stats_filename}")
        cli_verifier.write_debug_log_to_file("profile_debug_log_cython_only.log")

    else: 
        print(f"Software Installation Integrity Tool\nUsage:\n  python integrity_verifier.py monitor <path_to_installer.exe>\n  python integrity_verifier.py profile (for profiling take_system_snapshot with Cython)\n\nDetailed log will be in {main_log_file}")
        sys.exit(1)

    if hasattr(cli_verifier, 'debug_log') and cli_verifier.debug_log and (len(sys.argv) <=1 or sys.argv[1].lower() != "profile"): 
        cli_verifier.write_debug_log_to_file(main_log_file)
    elif (len(sys.argv) <=1 or sys.argv[1].lower() != "profile"): 
        print(f"No debug log generated for this CLI run. Check {main_log_file} if it exists.")

