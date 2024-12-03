from datetime import datetime
import os, ctypes, subprocess, argparse, traceback

import core.preparing
import core.report

import plugins.FileSystem as FileSystem
import plugins.Process as Process
import plugins.LogFiles as LogFiles
import plugins.EventLogs as EventLogs

def showVersion():
	print("v1.0.0")

def get_args():
	core.preparing.display_banner()
	
	parser = argparse.ArgumentParser(description=f"Windows Malware Detection and Hunting Support Tool")
	parser.add_argument("-o", "--out-dir", help="save output to directory", default=str(datetime.now().strftime("%d_%m_%Y")))
	parser.add_argument("-fs", "--file-scan", action="store_true", help="running with FileScan module", default=False)
	parser.add_argument("-ps", "--process-scan", action="store_true", help="running with ProcessScan module", default=False)
	parser.add_argument("-es", "--eventlog-scan", action="store_true", help="running with EventlogScan module", default=False)
	parser.add_argument("-v", "--version", action="store_true", help="show version of tools", default=False)
	args = parser.parse_args()  
	return args

def run(args):

	if(args.version):
		showVersion()
	else:
		file_scan_mode = args.file_scan
		process_scan_mode = args.process_scan
		eventlogs_scan_mode = args.eventlog_scan
		sDir = args.out_dir

		if(args.file_scan == False and args.process_scan == False and args.eventlog_scan == False):
			file_scan_mode = True
			process_scan_mode = True
			eventlogs_scan_mode = True

		start_scan(sDir, file_scan_mode, process_scan_mode, eventlogs_scan_mode)

def start_scan(sDir, fScanMode, pScanMode, eScanMode):
	# prepare
	core.preparing.run(sDir)
	try:
		sTime = datetime.now()

		# Collect infor about machines
		mInfo = core.preparing.get_machine_info()

		# Get log files
		LogFiles.Get()

		# EventLogs scan
		if(eScanMode == True):
			EventLogs.Scan()

		# # Process scan
		if(pScanMode == True):
			Process.Scan()

		# # Filesystem scan
		if(fScanMode == True):
			FileSystem.Scan()

		fTime = datetime.now()
		
		# report
		core.report.create(sDir, mInfo, sTime, fTime)
	except KeyboardInterrupt:
		print("[!] User cancelled the operation.")
	except Exception as e:
		print(traceback.format_exc())
		print(f"[!] An error occurred: {e}")
	finally:
		core.preparing.clean()
		return

def main():
	args = get_args()	
	run(args)

if __name__ == '__main__':
	main()
