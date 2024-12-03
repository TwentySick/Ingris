import os, shutil, pyzipper, jinja2, re, json

def get_content_file_json(fName):
	data = ""
	if(os.path.exists(fName)):
		file = open(fName, 'r')
		data = json.loads(file.read())
		file.close()
	return data

def display(sTime, fTime, mInfo, pHollowHunter, fLoaded, fScanModule, eScanModule, report_file):
	if(mInfo != ""):
		print("\n---------- Machine Info -------------")
		print(f'Host Name\t\t: {''.join(d for d in mInfo['Host Name'])}')
		print(f'OS Name\t\t\t: {''.join(d for d in mInfo['OS Name'])}')
		print(f'OS Version\t\t: {''.join(d for d in mInfo['OS Version'])}')
		print(f'OS Manufacturer\t\t: {''.join(d for d in mInfo['OS Manufacturer'])}')
		print(f'OS Configuration\t: {''.join(d for d in mInfo['OS Configuration'])}')
		print(f'OS Build Type\t\t: {''.join(d for d in mInfo['OS Build Type'])}')
		print(f'System Type\t\t: {''.join(d for d in mInfo['System Type'])}')
		print(f'Domain\t\t\t: {''.join(d for d in mInfo['Domain'])}')
		print(f'Logon Server\t\t: {''.join(d for d in mInfo['Logon Server'])}')
	
	if(eScanModule != "" or pHollowHunter != "" or fLoaded != "" or fScanModule != ""):
		print("\n\n------------- Summary ---------------")
		print(f"- Start time  : {sTime}")
		print(f"- Finish time : {fTime}")
		print()

	if(eScanModule != ""):
		print(f"- Total suspicious activity (EventLogs Scan Module): {eScanModule['suspicious_count']}")

	if(pHollowHunter != "" or fLoaded != ""):

		if(pHollowHunter != "" and fLoaded == ""):
			print(f"- Total suspicious process (Process Scan Module): {pHollowHunter['suspicious_count']}")
		elif(pHollowHunter == "" and fLoaded != ""):
			print(f"- Total suspicious process (Process Scan Module): {fLoaded['suspicious_count']}")
		else:
			print(f"- Total suspicious process (Process Scan Module): {pHollowHunter['suspicious_count'] + fLoaded['suspicious_count']}")

	if(fScanModule != ""):
		print(f"- Total suspicious files (FileSystem Scan Module): {fScanModule["suspicious_count"]}")

	print(f"\n\n===> Report save at {os.path.abspath(report_file)}")

	print("\n-------------------------------------\n")

def save_report_to_file(fName, sDir, sTime, fTime, mInfo, pHollowHunter, fLoaded, fScanModule, eScanModule):
	template = jinja2.Environment(
		loader = jinja2.FileSystemLoader("config\\templates"),
	).get_template("report_template.html")

	# Edit before gen report - Machine information
	for i in range(len(mInfo["Network Card(s)"])):
		# mInfo["Network Card(s)"][i] = d.replace("      ","&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
		mInfo["Network Card(s)"][i] = re.sub(r'^      ','&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;',mInfo["Network Card(s)"][i])

	# Process injected
	if(pHollowHunter != ""):
		for suspicious in pHollowHunter['suspicious']:
			suspicious["Suspicious Module"] = list()
			with open(f"{sDir}\\suspicious\\process\\hollowshunter\\process_{suspicious['pid']}\\scan_report.json") as proc:
				data = eval(proc.read())
				for i in data['scans']:
					for j in i.keys():
						if 'module_file' in i[j]:
							if i[j]['module_file'].replace("\\","").lower() == "C:\\Windows\\System32\\ntdll.dll".replace("\\","").lower(): continue
							# print("Process ID:",suspicious['pid'])
							# print("Process Name:",suspicious['name'])
							# print("Image Fullpath:",data['main_image_path'])
							# print(f"Suspicious Module (Triggered by {j}):",i[j]['module_file'])
							if(i[j]['module_file'] not in suspicious["Suspicious Module"]):
								suspicious["Suspicious Module"].append(i[j]['module_file'])
							suspicious["Image Fullpath"] = data['main_image_path']
			proc.close()

	context = {"start_time": sTime, "finish_time": fTime, "scan_time":fTime - sTime, "machine_info": mInfo, "hollows_hunter": pHollowHunter, "susp_file_loaded": fLoaded, "file_scan_module": fScanModule, "eventlog_scan_module": eScanModule}
	renderedText = template.render(context)

	report_file = open(fName,'w', encoding="utf-8")
	report_file.write(renderedText)
	report_file.close()

def store_evtx(sDir):
	tmp_dir = "tmp"
	dst_dir = sDir + "\\log_files"

	# Copy evtx files
	shutil.copytree(tmp_dir + "\\log_files\\evtx", dst_dir + "\\evtx")

def store_susp(sDir):

	tmp_dir = "tmp"
	dst_dir = sDir + "\\suspicious"
	
	# Copy suspicious files
	# Process module
	if(os.path.exists(tmp_dir + "\\process")):

		shutil.copytree(tmp_dir + "\\process", dst_dir + "\\process")


	# FileSystem module
	if(os.path.exists(tmp_dir + "\\FileSystem")):

		if(not os.path.exists(dst_dir + "\\FileSystem")):
			os.makedirs(dst_dir + "\\FileSystem\\")

		# FileSystem suspicious files		
		if(os.path.exists(tmp_dir + "\\FileSystem\\files")):
			shutil.copytree(tmp_dir + "\\FileSystem\\files", dst_dir + "\\FileSystem\\files")

		# FileSystem summary file
		if(os.path.exists(tmp_dir + "\\FileSystem\\summary.json")):
			shutil.copy2(tmp_dir + "\\FileSystem\\summary.json", dst_dir + "\\FileSystem\\summary.json")

	# EventLogs module
	if(os.path.exists(tmp_dir + "\\EventLogs")):

		if(not os.path.exists(dst_dir + "\\EventLogs")):
			os.makedirs(dst_dir + "\\EventLogs")
		
		# Eventlogs suspicious			
		if(os.path.exists(tmp_dir + "\\EventLogs\\results")):
			shutil.copytree(tmp_dir + "\\EventLogs\\results", dst_dir + "\\EventLogs\\results")

		# Eventlogs summary
		if(os.path.exists(tmp_dir + "\\EventLogs\\summary.jsonl")):
			shutil.copy2(tmp_dir + "\\EventLogs\\summary.jsonl", dst_dir + "\\EventLogs\\summary.jsonl")

	# Zip file
	# password: infected
	zip_file = sDir + '\\suspicious.zip'
	zip_folder_with_password(dst_dir, zip_file)	
	
def zip_folder_with_password(folder_path, zip_filename):

	zip_file = pyzipper.AESZipFile(zip_filename,'w',compression=pyzipper.ZIP_DEFLATED,encryption=pyzipper.WZ_AES)
	zip_file.pwd = b"infected"

	parent_folder = os.path.dirname(folder_path)
	contents = os.walk(folder_path)

	for root, dirs, files in contents:

		 # Include all subfolders, including empty ones.
		for dir_name in dirs:
			absolute_path = os.path.join(root, dir_name)
			relative_path = absolute_path.replace(parent_folder + '\\', '')
			zip_file.write(absolute_path, relative_path)
		for file_name in files:
			absolute_path = os.path.join(root, file_name)
			relative_path = absolute_path.replace(parent_folder + '\\', '')
			zip_file.write(absolute_path, relative_path)

	zip_file.close()
	# print ("'%s' created successfully." % zip_filename)

def create(sDir, mInfo, sTime, fTime):

	print("[+] Saving eventlog files and suspicious files\t\t", end="", flush=True)

	store_evtx(sDir)
	store_susp(sDir)

	print("[DONE]")

	print("[+] Creating report\t\t\t\t\t", end="", flush=True)
	# Get content to display and create report
	hollow_hunter = get_content_file_json(sDir + '\\suspicious\\process\\hollowshunter\\summary.json')
	susp_file_loaded = get_content_file_json(sDir + '\\suspicious\\process\\suspicious_loaded\\summary.json')
	file_scan_report = get_content_file_json(sDir + '\\suspicious\\FileSystem\\summary.json')
	eventlog_scan_report = get_content_file_json(sDir + "\\suspicious\\EventLogs\\summary.jsonl")
	# eventlog_scan_report = get_content_file_json("D:\\Code\\summary.jsonl")

	# Display report
	save_report_to_file(sDir + "\\report\\Report.html", sDir, sTime, fTime, mInfo, hollow_hunter, susp_file_loaded, file_scan_report, eventlog_scan_report)
	
	print("[DONE]")
	display(sTime, fTime, mInfo, hollow_hunter, susp_file_loaded, file_scan_report, eventlog_scan_report, sDir + "\\report\\Report.html")