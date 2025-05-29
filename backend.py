#___  ___       _   _           _               
#|  \/  |      | | | |         | |                  /\ o o o\
#| .  . |_ __  | |_| | __ _ ___| |__   ___ _ __    /o \ o o o\_______
#| |\/| | '__| |  _  |/ _` / __| '_ \ / _ \ '__|  <    >------>   o /|
#| |  | | |_   | | | | (_| \__ \ | | |  __/ |      \ o/  o   /_____/o|
#\_|  |_/_(_)  \_| |_/\__,_|___/_| |_|\___|_|       \/______/     |oo|
#                                                         |   o   |o/
#                                                         |_______|/
import random
import os
import subprocess
import json
import shutil 
import re 
import hashlib 
import time
from typing import Optional, Dict, List, Tuple 

script_dir = os.path.dirname(os.path.abspath(__file__))

SIMULATED_DIR_FILES = ["important.dll", "config.xml", "user_manual.pdf", "main_app.exe", "readme.txt", "image_asset.png"]

def calculate_actual_checksum(file_path: str, algorithm_name: str = "SHA256") -> Optional[str]:
    if not os.path.isfile(file_path):
        print(f"Error: File not found for hashing: {file_path}")
        return None
    algo = algorithm_name.lower()
    if algo.startswith("sim-"):
        algo = algo[4:]
    if algo == "md5": hasher = hashlib.md5()
    elif algo == "sha1": hasher = hashlib.sha1()
    elif algo == "sha256": hasher = hashlib.sha256()
    else:
        print(f"Error: Unsupported algorithm '{algorithm_name}'. Using SHA256 as default.")
        hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hasher.update(byte_block)
        return hasher.hexdigest()
    except PermissionError:
        print(f"Error: Permission denied for file {file_path}")
        return None
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}")
        return None

def get_next_checksum_filename(base_dir, prefix="checksum", extension=".json"):
    try:
        os.makedirs(base_dir, exist_ok=True) 
    except OSError as e:
        print(f"Error creating directory {base_dir}: {e}")
        return f"{prefix}1{extension}" 
    existing_files = [f for f in os.listdir(base_dir) if os.path.isfile(os.path.join(base_dir, f))]
    max_num = 0
    safe_extension = re.escape(extension)
    pattern = rf"^{re.escape(prefix)}(\d+){safe_extension}$"
    for f_name in existing_files:
        match = re.match(pattern, f_name)
        if match:
            num = int(match.group(1))
            if num > max_num: max_num = num
    return f"{prefix}{max_num + 1}{extension}"

def generate_checksums_for_folder_contents(folder_path: str, algorithm: str, output_base_dir: str, output_format: str = "JSON Format (.json)") -> Dict:
    logs = [f"Starting checksum generation for folder: {folder_path}"]
    extracted_checksums = {}
    file_count = 0
    
    persistent_checksum_dir = os.path.join(output_base_dir, 'checksum')
    try:
        os.makedirs(persistent_checksum_dir, exist_ok=True)
    except OSError as e:
        logs.append(f"CRITICAL ERROR: Could not create checksum directory '{persistent_checksum_dir}': {e}")
        return {"status": "error", "message": f"Failed to create save directory: {e}", "logs": logs, "json_path": None}

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, folder_path)
            try:
                checksum = calculate_actual_checksum(file_path, algorithm)
                if checksum:
                    extracted_checksums[relative_path] = checksum
                    file_count += 1
                    logs.append(f"  Generated {algorithm} for: {relative_path} -> {checksum}")
                else:
                    logs.append(f"  SKIPPED (hashing failed): {relative_path}")
            except Exception as e:
                logs.append(f"  ERROR generating checksum for {relative_path}: {e}")
    
    logs.append(f"Checksum generation complete for folder. Processed {file_count} files.")

    file_extension = ".json"
    if "Plain Text" in output_format: file_extension = ".txt"
    elif "MD5SUM Format" in output_format: file_extension = ".txt" 
    
    base_filename_prefix = f"{os.path.basename(folder_path)}_contents_checksum"
    safe_prefix = "".join(c if c.isalnum() or c in (' ', '_') else '_' for c in base_filename_prefix).rstrip()
    
    checksum_file_name = get_next_checksum_filename(persistent_checksum_dir, prefix=safe_prefix, extension=file_extension)
    full_checksum_path = os.path.join(persistent_checksum_dir, checksum_file_name)
    
    try:
        with open(full_checksum_path, 'w', encoding='utf-8') as f:
            if file_extension == ".json":
                json.dump({"source_folder": folder_path, 
                           "algorithm": algorithm, 
                           "files": extracted_checksums}, f, indent=4)
            else:
                f.write(f"# Checksum Report for Folder: {folder_path}\n")
                f.write(f"# Algorithm: {algorithm}\n")
                f.write(f"# Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# Format: Checksum  RelativeFilePath\n")
                f.write("--------------------------------------------------\n")
                for rel_path, chksum in extracted_checksums.items():
                    f.write(f"{chksum}  {rel_path}\n")
        logs.append(f"Checksums saved to: {full_checksum_path}")
        return {"status": "success", "message": "Checksum generation for folder successful.", "logs": logs, "json_path": full_checksum_path}
    except Exception as e:
        logs.append(f"ERROR saving {checksum_file_name} to {full_checksum_path}: {e}")
        return {"status": "error", "message": f"Failed to save {checksum_file_name}: {e}", "logs": logs, "json_path": None}


def extract_archive_and_generate_checksums_for_contents(archive_path, temp_output_path, algorithm, output_base_dir, output_format="JSON Format (.json)"):
    logs = []
    if os.path.isdir(archive_path): 
        logs.append(f"Input path '{archive_path}' is a directory. Proceeding with folder checksumming.")
        return generate_checksums_for_folder_contents(archive_path, algorithm, output_base_dir, output_format)

    # Extraction log for 7zip or 7z.exe whatever you call it.
    seven_zip_exe = os.path.join(script_dir, '7-Zip', '7z.exe') 
    persistent_checksum_dir = os.path.join(output_base_dir, 'checksum')
    try:
        os.makedirs(persistent_checksum_dir, exist_ok=True) 
    except OSError as e:
        logs.append(f"CRITICAL ERROR: Could not create checksum directory '{persistent_checksum_dir}': {e}")
        return {"status": "error", "message": f"Failed to create save directory: {e}", "logs": logs, "json_path": None}

    if not os.path.exists(seven_zip_exe):
        logs.append(f"ERROR: 7z.exe not found at {seven_zip_exe}. Please ensure it's in the '7-Zip' subfolder relative to the script's location.")
        return {"status": "error", "message": "7z.exe not found.", "logs": logs, "json_path": None}

    if os.path.exists(temp_output_path):
        try:
            shutil.rmtree(temp_output_path)
            logs.append(f"Cleaned up existing temporary folder: {temp_output_path}")
        except Exception as e:
            logs.append(f"WARNING: Could not clean up existing temporary folder {temp_output_path}: {e}")
    try:
        os.makedirs(temp_output_path, exist_ok=True)
    except OSError as e:
        logs.append(f"CRITICAL ERROR: Could not create temporary extraction directory '{temp_output_path}': {e}")
        return {"status": "error", "message": f"Failed to create temporary directory: {e}", "logs": logs, "json_path": None}

    logs.append(f"Attempting to extract archive '{archive_path}' to '{temp_output_path}'...")
    command = [seven_zip_exe, 'x', archive_path, f'-o{temp_output_path}', '-y']
    try:
        process = subprocess.run(command, check=False, capture_output=True, text=True, errors='replace', creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        if process.returncode != 0:
            logs.append(f"7-Zip Extraction Error (Return Code: {process.returncode}):")
            logs.append(f"STDOUT: {process.stdout.strip()}")
            logs.append(f"STDERR: {process.stderr.strip()}")
            return {"status": "error", "message": "7-Zip extraction failed.", "logs": logs, "json_path": None}
        logs.append(f"7-Zip Extraction successful for '{archive_path}'.")
        if process.stdout: logs.append(f"7-Zip Output:\n{process.stdout.strip()}")
    except FileNotFoundError:
        logs.append(f"ERROR: 7z.exe not found or command incorrect. Path: {seven_zip_exe}")
        return {"status": "error", "message": "7z.exe execution failed.", "logs": logs, "json_path": None}
    except Exception as e:
        logs.append(f"An unexpected error occurred during extraction: {e}")
        return {"status": "error", "message": f"Extraction error: {e}", "logs": logs, "json_path": None}

    logs.append("Generating checksums for extracted contents...")
    extracted_checksums = {}
    file_count = 0
    for root, _, files in os.walk(temp_output_path):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, temp_output_path)
            try:
                checksum = calculate_actual_checksum(file_path, algorithm) 
                if checksum:
                    extracted_checksums[relative_path] = checksum
                    file_count += 1
                    logs.append(f"  Generated {algorithm} for: {relative_path} -> {checksum}")
                else:
                    logs.append(f"  SKIPPED (hashing failed): {relative_path}")
            except Exception as e:
                logs.append(f"  ERROR generating checksum for {relative_path}: {e}")
    
    logs.append(f"Checksum generation complete. Processed {file_count} files.")

    file_extension = ".json"
    if "Plain Text" in output_format: file_extension = ".txt"
    elif "MD5SUM Format" in output_format: file_extension = ".txt" 
    
    archive_basename = os.path.splitext(os.path.basename(archive_path))[0]
    safe_archive_name = "".join(c if c.isalnum() or c in (' ', '_') else '_' for c in archive_basename).rstrip()
    base_filename_prefix = f"{safe_archive_name}_checksum"
    
    checksum_file_name = get_next_checksum_filename(persistent_checksum_dir, prefix=base_filename_prefix, extension=file_extension)
    full_checksum_path = os.path.join(persistent_checksum_dir, checksum_file_name)
    
    try:
        with open(full_checksum_path, 'w', encoding='utf-8') as f:
            if file_extension == ".json":
                json.dump({"archive_source": archive_path, "algorithm": algorithm, "files": extracted_checksums}, f, indent=4)
            else:
                f.write(f"# Checksum Report for Archive: {archive_path}\n")
                f.write(f"# Algorithm: {algorithm}\n")
                f.write(f"# Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# Format: Checksum  RelativeFilePath\n")
                f.write("--------------------------------------------------\n")
                for rel_path, chksum in extracted_checksums.items():
                    f.write(f"{chksum}  {rel_path}\n")
        logs.append(f"Checksums saved to: {full_checksum_path}")
        return {"status": "success", "message": "Extraction and checksum generation successful.", "logs": logs, "json_path": full_checksum_path}
    except Exception as e:
        logs.append(f"ERROR saving {checksum_file_name} to {full_checksum_path}: {e}")
        return {"status": "error", "message": f"Failed to save {checksum_file_name}: {e}", "logs": logs, "json_path": None}

def cleanup_temp_folder(temp_output_path):
    logs = []
    if os.path.exists(temp_output_path):
        try:
            shutil.rmtree(temp_output_path)
            logs.append(f"Successfully cleaned up temporary folder: {temp_output_path}")
            return True, logs
        except Exception as e:
            logs.append(f"ERROR cleaning up temporary folder {temp_output_path}: {e}")
            return False, logs
    else:
        logs.append(f"Temporary folder {temp_output_path} not found for cleanup (already removed or never created).")
        return True, logs 

def parse_checksum_file_content(file_contents):
    parsed_data = []
    try: 
        data = json.loads(file_contents)
        if "files" in data and isinstance(data["files"], dict):
            for filename, checksum_val in data["files"].items():
                parsed_data.append({"filename": filename, "checksum": checksum_val})
            if parsed_data: return parsed_data 
    except json.JSONDecodeError:
        pass 

    lines = file_contents.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "-----------------" in line : 
            continue
        
        if "Checksum (" in line and "): " in line and "File: " in line:
            try:
                parts = line.split("File: ")
                filename_part = parts[1].strip()
                match = re.search(r"Checksum \(.*?\): (\S+)", parts[0])
                if match:
                    checksum_val = match.group(1)
                    filename = filename_part
                    if filename and checksum_val:
                        parsed_data.append({"filename": filename, "checksum": checksum_val})
                        continue 
            except IndexError:
                pass 
        
        parts = line.strip().split(None, 1) 
        if len(parts) == 2:
            checksum_val, filename = parts[0], parts[1]
            if re.match(r"^[a-f0-9]+$", checksum_val, re.IGNORECASE):
                 parsed_data.append({"filename": filename.strip(), "checksum": checksum_val.strip()})
    return parsed_data

def perform_verification_logic(imported_data):
    results = []
    for item in imported_data:
        file_exists_sim = random.random() > 0.2  
        local_checksum = "N/A (Not Hashed in this Sim)"
        status = "PENDING"
        if file_exists_sim:
            matches_sim = random.random() > 0.3 
            if matches_sim:
                local_checksum = item["checksum"] 
                status = "VERIFIED"
            else:
                local_checksum = hashlib.sha256((item["filename"] + "_local_version_alt").encode()).hexdigest()[:16] 
                status = "MISMATCH"
        else:
            status = "FILE NOT FOUND"
        results.append({
            "filename": item["filename"],
            "imported_checksum": item["checksum"],
            "local_checksum": local_checksum,
            "status": status
        })
    return results

def perform_batch_creation_logic(directory_name, algorithm):
    if not directory_name or not os.path.isdir(directory_name):
        print(f"Error: Directory for batch creation not found or invalid: {directory_name}")
        return []

    output_lines = []
    logs = [] 
    logs.append(f"Starting batch checksum creation for directory: {directory_name} using {algorithm}")
    
    for root, _, files in os.walk(directory_name):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            checksum = calculate_actual_checksum(file_path, algorithm)
            if checksum:
                relative_path = os.path.relpath(file_path, directory_name)
                output_lines.append(f"{checksum}  {relative_path}")
                logs.append(f"  Generated {algorithm} for {relative_path} -> {checksum}")
            else:
                logs.append(f"  Failed to hash {file_path}")
                

    return output_lines

