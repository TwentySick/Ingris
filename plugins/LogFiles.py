import os
import shutil

def GetEventLog():
	path = 'C:\\Windows\\System32\\winevt\\Logs\\'
	sDir = 'tmp\\log_files\\evtx'

	# check exists default path
	if( not os.path.exists(path)):
		print("[!] Event logs doesn't exists with default path: " + path)
		return

	# List file on folder
	files = os.listdir(path)
	
	# Create evtx folder to store
	if(not os.path.exists(sDir)):
		os.makedirs(sDir)

	# copy file (shutil.copy2() will copy all metadata)
	for file in files:
		shutil.copy2(path + file, sDir)

def Get():
	print("[+] Collecting logs files\t\t\t\t", end="", flush=True)

	# Get event log
	GetEventLog()

	# Get access log

	# Get error log

	print("[DONE]")