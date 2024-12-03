import os, platform, subprocess
import shutil, re
import json

from core.velociraptor_api import *

def check_rules():
    arch = platform.architecture()

    if(arch[0] == '64bit'):
        rules_path = "tools\\x64\\hayabusa\\rules"
        exe_path = "tools\\x64\\hayabusa\\hayabusa-2.19.0-win-x64.exe"
    elif(arch[0] == '32bit'):
        rules_path = "tools\\x32\\hayabusa\\rules"
        exe_path = "tools\\x32\\hayabusa\\hayabusa-2.19.0-win-x86.exe"

    if(not os.path.exists(rules_path)):
        subprocess.run([exe_path, "update-rules", "--quiet", "--rules", rules_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def Scan():
    print("[+] Running EventScan module\t\t\t\t", end="", flush=True)

    check_rules()

    sDir = os.path.join("tmp", "EventLogs")
    if not os.path.exists(sDir):
        os.makedirs(sDir)

    sum_file = os.path.join(sDir, "summary.jsonl")

    artifact = "Windows.EventLogs.Hayabusa"
    query = f"select * from Artifact.{artifact}()"
    Run_velociraptor_query(query)
    result = dict()
    suspicious_lst = list()

    if os.path.exists(sum_file):
        with open(sum_file, "r", encoding="utf-8-sig") as file:
            for line in file:
                event = json.loads(line)

                # Filter event ID related to Defense Evasion
                if "MitreTactics" in event and "Evas" in event["MitreTactics"]:
                    defanged_link = ""
                    status = ""
                    detail_info = event.get("Details", {})
                    cmdline = detail_info.get("Cmdline", "")

                    url_match = re.search(r'(https?://\S+)', cmdline)
                    if url_match:
                        url = url_match.group(0)
                        defanged_link = defang_url(url)
                    
                    cmd_parts = cmdline.split()
                    for part in cmd_parts:
                        if os.path.exists(part):
                            status = "Stored"
                            try:
                                save_suspicious_file(sDir, part)
                            except Exception as e:
                                print(f"Error saving file {part}: {e}") 
                            break
                    else:
                        status = "Missing"

                    # Retain necessary fields
                    filter_event = {
                        "Timestamp": event.get("Timestamp"),
                        "RuleTitle": event.get("RuleTitle"),
                        "Level": event.get("Level"),
                        "EventID": event.get("EventID"),
                        "MitreTactics": event.get("MitreTactics"),
                        "MitreTags": event.get("MitreTags"),
                        "Details": event.get("Details"),
                        "ExtraFieldInfo": event.get("ExtraFieldInfo"),
                        "SuspiciousLink": defanged_link,
                        "Status": status
                    }

                    suspicious_lst.append(filter_event)

        result['suspicious_count'] = len(suspicious_lst)
        result['suspicious'] = suspicious_lst

        # Update summary.jsonl file with new information
        file = open(sum_file,"w")
        json.dump(result, file, indent=4)
        file.close()

    print("[DONE]")
    return result

def save_suspicious_file(sDir, part):
    folder = sDir + "\\results"
    if(not os.path.exists(folder)):
        os.makedirs(folder)
    new_name = part.replace(":", "").replace("\\", "_").replace(".", "_").replace(" ", "_")
    suspicious_file_path = os.path.join(folder, new_name)
    shutil.copy2(part, suspicious_file_path)

def defang_url(url):
    # Defang URL 
    url = re.sub(r"http(s?)://", r"hXXp\1://", url)
    url = re.sub(r"(s?)ftp(s?)://", r"\1fXp\2://", url)
    url = re.sub(r"\.(?=[a-zA-Z]{2,}(?:[/:]|$))", "[.]", url)
    return url

