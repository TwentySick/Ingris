import os
import re
import subprocess
import shutil
import yara
import json
import platform

from oletools.olevba import TYPE_OLE, TYPE_OpenXML

from core.velociraptor_api import *
from core.check_virustotal import *

MAGIC_HEADERS = {
    'msi': b'\xD0\xCF\x11\xE0',
    'exe': b'\x4D\x5A',
    'dll': b'\x4D\x5A',
    'sys': b'\x4D\x5A',
    'iso': b'\x43\x44\x30\x30\x31',
    '7z': b'\x37\x7A\xBC\xAF\x27\x1C',
    'zip': b'\x50\x4B\x03\x04',
    'z': b'\x1F\x9D',
    'tar.z': b'\x1F\xA0',
    'lz': b'\x4C\5A\x49\x50',
    'gz': b'\x1F\x8B' 
}
OXML_MAGIC_HEADER = {
    'docx': b'\x50\x4B\x03\x04',                    # include xlsx, pptx
    'doc': b'\xD0\xCF\x11\xE0',                     # include xls, ppt
    'pdf': b'\x25\x50\x44\x46\x2D'
}

yara_rules_path = ""
sigcheck_path = ""
pdfid_path = ""

suspicious_lst = list()

def Scan():

    global yara_rules_path
    global sigcheck_path
    global pdfid_path

    arch = platform.architecture()

    if(arch[0] == '64bit'):
        yara_rules_path = ".\\data\\x64\\yara_rules"
        sigcheck_path = ".\\tools\\x64\\sigcheck64.exe"
        pdfid_path = ".\\tools\\x64\\pdfid\\pdfid.exe"
    elif(arch[0] == '32bit'):
        yara_rules_path = ".\\data\\x32\\yara_rules"
        sigcheck_path = ".\\tools\\x32\\sigcheck.exe"
        pdfid_path = ""


    print("[+] Running FileSystemScan module\t\t\t", end="", flush=True)
    get_info()    
    print("[DONE]")

def get_info():
    sDir = os.path.join("tmp\\FileSystem")

    # Create a folder to store suspected files.
    if(not os.path.exists(sDir)):
        os.makedirs(sDir)

    scan_folder_path = "data\\x64\\scan_folders.txt"

    # Create a copy file to store additional captured files after running the process
    shutil.copy(scan_folder_path, sDir)
    temp = "tmp\\FileSystem\\scan_folders.txt"

    # Finding dll file in IIS
    finding_IIS()

    with open(temp, 'r') as file:
        folders = [line.strip() for line in file.readlines()]
    file.close()

    for path in folders:
        query = f'select OSPath, Name, hash(path=OSPath, hashselect="MD5").MD5 as MD5 from glob(globs="{path}/*")'
        result  = Run_velociraptor_query(query)
        correctSyntax = re.sub(r"\]\[", ",",result)
        parsed = [item for item in eval(correctSyntax) if os.path.isfile(item['OSPath'])]
        try:
            for file_info in parsed:
                file_name = file_info.get("Name")       # Get file name
                file_hash = file_info.get('MD5')        # Get file hash
                file_path = file_info.get('OSPath')     # Get file path
                file_extension = os.path.splitext(file_info.get('Name'))[1]
                # print(f"{file_name} {file_hash}")
                suspicious = Check(sDir, file_hash, file_path, file_name, file_extension)
                susp_file = dict()
                if suspicious != "":
                    susp_file["Name"] = file_name
                    susp_file["MD5"] = file_hash
                    susp_file["File path"] = file_path
                    susp_file["Detected by"] = suspicious
                    suspicious_lst.append(susp_file)
            create_report(sDir, suspicious_lst)
        except Exception as e:
            print(f"\n[!] An error occurred: {e}")

def Check(sDir, file_hash, file_path, file_name, file_extension):

    if is_executable_file(file_path):
        is_suspicious = check_hash_file(sDir, file_path, file_hash, file_name)
        if (is_suspicious == 0):
            if(check_sign_file(sDir, file_path, file_name) == True):
                return "Signature Missing"
        elif(is_suspicious == 1):
            return "Virustotal"
        elif(is_suspicious == 2):
            return "Yara rules"
        else:
            return ""
    
    if is_oxml_file(file_path):
        if(check_marco(sDir, file_path, file_name, file_extension) == True):
            return "Macro"
        
    if (get_script_file(sDir, file_path, file_extension) == True):
        return "Script File"
    return ""

# Get all the script files found
def get_script_file(sDir, file_path, file_extension):
    script_extensions = [".ps1", ".bat", ".cmd"]
    if file_extension in script_extensions:
        save_suspicious_file(sDir, file_path)
        return True

def check_hash_file(sDir, file_path, file_hash, file_name):
    try:
        malicious_count = check_virustotal(file_hash)

        if malicious_count > 3:
            # print(f"\t[-]Detect suspicious hash file: {file_name}")
            save_suspicious_file(sDir, file_path)
            return 1
        else:
            # use YARA rule to find out if have suspicious file
            rules = yara.compile(filepaths={
                f"rule_{i}": f"{yara_rules_path}\\malware\\{file}" 
                for i, file in enumerate(os.listdir(yara_rules_path)) if (file.endswith(".yar") or file.endswith(".yara"))})

            matches = rules.match(file_path)
            if matches:
                # print(f"\t[-]Detect suspicious file with YARA rules: {file_name}")
                save_suspicious_file(sDir, file_path)
                return 2
        return 0
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        return 0

def check_sign_file(sDir, file_path, file_name):
    try:
        # Run sigcheck
        result = subprocess.run([sigcheck_path, "-accepteula", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Check if have error when running
        if result.stderr:
            # print(f"[ERROR] Sigcheck error: {result.stderr}")
            return False
        
        output = result.stdout
        lines = output.splitlines()
        if "Signed" not in lines[6]:
            # print(f"\t[-]Detect suspicious signarute file: {file_name}")
            save_suspicious_file(sDir, file_path)
            return True
        return False
    except Exception as e:
        # print(f"[ERROR] Failed to run Sigcheck for {file_path}: {e}")
        return False

def check_marco(sDir, file_path, file_name, file_extension):   
    if(pdfid_path != ""):     
        try:
            if file_extension == ".pdf":
                #check file pdf
                analyze_pdf = subprocess.check_output([pdfid_path, file_path], stderr=subprocess.DEVNULL, text=True )

                suspicious_keywords = ["/JS", "/JavaScript", "/Launch", "/OpenAction", "/EmbeddedFile"]
                for line in analyze_pdf.splitlines():
                    for keyword in suspicious_keywords:
                        if keyword in line:
                            parts = line.split()
                            if parts and parts[-1].isdigit() and int(parts[-1]) > 0:
                                # print(f"\t[-] Detect suspicious marco file: {file_name}")
                                save_suspicious_file(sDir, file_path)
                                return True
            else:
                # Check file VBA by olevba tool and yara rule
                try:
                    analyze_olevba = subprocess.check_output( ['olevba', file_path], stderr=subprocess.DEVNULL, text=True, encoding='utf-8' )
                    if "No VBA or XLM macros found." not in analyze_olevba:
                        # print(f"\t[-]Detect suspicious marco file: {file_name}")
                        save_suspicious_file(sDir, file_path)
                        return True
                    else:
                        rules = yara.compile(filepaths={
                            f"rule_{i}": f"{yara_rules_path}\\macro\\{file}" 
                            for i, file in enumerate(os.listdir(yara_rules_path)) if (file.endswith(".yar") or file.endswith(".yara"))})
                        
                        matches = rules.match(file_path)
                        if matches:
                            # print(f"\t[-]Detect suspicious file with YARA rules: {file_name}")
                            save_suspicious_file(sDir, file_path)
                            return True
                except Exception as e:
                    pass
            return False
        except Exception as e:
            # print(f"\n[!] An unexpected error occurred scan OXML file: {e}")
            return False
    return False
    
def save_suspicious_file(sDir, file_path):
    folder = sDir + "\\files"
    if(not os.path.exists(folder)):
        os.makedirs(folder)
    new_name = file_path.replace(":", "").replace("\\", "_").replace(".", "_").replace(" ", "_")
    suspicious_file_path = os.path.join(folder, new_name)
    shutil.copyfile(file_path, suspicious_file_path)

def get_file_magic_header(file_path, num_bytes=8):
    # Read first num_bytes of file
    try:
        with open(file_path, 'rb') as file:
            file_signature = file.read(num_bytes)
        return file_signature
    except Exception as e:
        print(f"\n[!] Error reading {file_path}: {e}")
        return None
    
def is_executable_file(file_path):
    # Get magic header of file
    file_signature = get_file_magic_header(file_path)
    if file_signature:
        is_magic_executable = any(file_signature.startswith(magic) for magic in MAGIC_HEADERS.values())
        is_oxml_file = any(file_signature.startswith(magic) for magic in OXML_MAGIC_HEADER.values())
        if is_magic_executable and not is_oxml_file:
            return True
        else:
            return False
        
def is_oxml_file(file_path):
    # Get magic header of file
    file_signature = get_file_magic_header(file_path)
    if file_signature:
        for magic in OXML_MAGIC_HEADER.values():
            if file_signature.startswith(magic):
                return True
    return False

def finding_IIS():
    IIS_file_config = r"C:\Windows\System32\inetsrv\config\applicationHost.config"
    dllsample = "tmp\\dllsample"
    if not os.path.exists(dllsample):
        os.makedirs(dllsample)
    dll_files = []

    try:
        with open(IIS_file_config, 'r', encoding='utf-8') as file:
            for line in file:
                # Regex to get file .dll in IIS
                matches = re.findall(r'(?<!fileExtension=")[\'"]?([\w%\\]+\.dll)[\'"]?', line, re.IGNORECASE)
                for match in matches:
                    # Filter files that have been in system32 to avoid duplicate scan
                    if "System32" not in match:
                        dll_files.append(match)
        
        if dll_files:
            for dll_path in dll_files:
                # Change path %windir%
                dll_path_expanded = os.path.expandvars(dll_path)
                #Copy to tmp
                if os.path.exists(dll_path_expanded):
                    try:
                        shutil.copy2(dll_path_expanded, dllsample)
                    except Exception as e:
                        print(f"\n[!] Error when copy {dll_path_expanded}: {e}")
    except FileNotFoundError:
        # print(f"\n[!] Not found file: {IIS_file_config}")
        return
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return

    # Add path to dllsample into file scan_folders  
    scan_folder_path = "tmp\\FileSystem\\scan_folders.txt"
    with open(scan_folder_path, 'a') as f:
        f.write('\n' + dllsample)

def create_report(sDir, susp_lst):
    report = dict()
    report["suspicious_count"] = len(susp_lst)
    report["suspicious"] = susp_lst
    summary_file_name = sDir + '\\summary.json'
    summary_file = open(summary_file_name, 'w')
    json.dump(report, summary_file, ensure_ascii=False, indent=4)
    summary_file.close()
