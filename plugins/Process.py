import re, os, shutil, json

from core.velociraptor_api import *

def scan_injected_process():
	artifact = "Windows.Memory.HollowsHunter"
	query = f"select * from Artifact.{artifact}()"
	Run_velociraptor_query(query)
	
def parsed_susp(cmd, file):
	if(os.path.exists(file)):
		return file 

	return cmd['CurrentDirectory'] + file

def scan_proxy_execution():
	artifact = "Windows.Memory.ProcessInfo"
	query = f"select * from Artifact.{artifact}()"

	# Binary proxy
	suspicious_cmd = {
		"hh.exe":[".chm"],
		"control.exe":[".cpl"],
		"CMSTP.exe":[".inf"],
		"InstallUtil.exe":[".dll"],
		"mshta.exe":[".hta "],
		"msiexec.exe":[".msi", ".dll"],
		"odbcconf.exe":[".dll"],
		"Regsvcs.exe":[".dll"],
		"Regasm.exe":[".dll"],
		"Regsvr32.exe":[".sct", ".dll"],
		"rundll32.exe":[".dll"],
		"mavinject.exe":[".dll"],
		"mmc.exe":[".msc"],
		"mavinject.exe":[".dll"],
		"Register-CimProvider.exe":[".dll"],
		"InfDefaultInstall.exe":[".inf"],
		"diskshadow.exe":[".txt"],
		"wuauclt.exe":[".dll"],
		"wscript.exe":[".vbs"]
	}

	suspicious_lst = list()

	command_line = Run_velociraptor_query(query)
	command_line = eval(command_line)

	# Loop to get each commandline
	for cmd in command_line:

		# Loop to check suspicious command
		for susp_cmd in suspicious_cmd:

			# If command line not contain suspicious keyword
			if(susp_cmd.lower() not in cmd["Exe"].lower()):
				continue
			
			susp_ext = suspicious_cmd[susp_cmd]
			

			# Get suspicious file loaded
			for ext in susp_ext:
				file = re.findall(f"\"([^\"]*\\{ext})\"|([\\S]*\\{ext})", cmd["CommandLine"])

				if(file == []):
					continue

				if(file[0][0] == '' and file[0][1] == ''):
					continue

				if(file[0][0] == ''):
					susp_file = parsed_susp(cmd, file[0][1])
				else:
					susp_file = parsed_susp(cmd, file[0][0])

				susp_cmd_found = dict()
				susp_cmd_found["Pid"] = cmd["Pid"]
				susp_cmd_found["Name"] = cmd["Exe"]
				susp_cmd_found["CommandLine"] = cmd["CommandLine"]
				susp_cmd_found["Suspicious File"] = susp_file

				suspicious_lst.append(susp_cmd_found)
	
	# Create folder to store suspicious file
	temp_dir = "tmp\\process\\suspicious_loaded"
	summary_file_name = temp_dir + "\\summary.json"
	if not os.path.exists(temp_dir):
		os.makedirs(temp_dir)

	# Store suspicious file
	for susp in suspicious_lst:
		susp_process_folder = temp_dir + "\\process_" + str(susp["Pid"])

		if not os.path.exists(susp_process_folder):
			os.makedirs(susp_process_folder)

		if(os.path.exists(susp["Suspicious File"])):
			new_name = susp_process_folder + "\\" + susp["Suspicious File"].replace(":","").replace("\\","_").replace(".","_").replace(" ","_")
			shutil.copyfile(susp["Suspicious File"], new_name)

	# Create report

	# Content
	# suspicious_count
	# suspicious
	# 	pid
	# 	binary_name
	# 	command_line
	# 	suspicious_file

	report = dict()
	report["suspicious_count"] = len(suspicious_lst)
	report["suspicious"] = suspicious_lst

	summary_file = open(summary_file_name, 'w')
	json.dump(report, summary_file, ensure_ascii=False, indent=4)
	summary_file.close()

def Scan():
	print("[+] Running ProcessScan module\t\t\t\t", end = "", flush=True)

	# T1055, T1620 - Process Inject and Reflective Code Loading - Hollow Hunter
	scan_injected_process()

	# T1218, T1216 - System Binary Proxy Execution, System Script Proxy Execution
	scan_proxy_execution()

	print("[DONE]")