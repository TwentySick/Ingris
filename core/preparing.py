import os, ctypes, socket, sys, yaml, platform, subprocess, shutil, re

def display_banner():
	banner = '''

██╗███╗   ██╗ ██████╗ ██████╗ ██╗███████╗
██║████╗  ██║██╔════╝ ██╔══██╗██║██╔════╝
██║██╔██╗ ██║██║  ███╗██████╔╝██║███████╗
██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
██║██║ ╚████║╚██████╔╝██║  ██║██║███████║
╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝
                                                                                                        
                                         - IAP491_G8 -

	'''

	print(banner)

def load_config():

	arch = platform.architecture()

	if(arch[0] == '64bit'):
		file = "config\\config64.yaml"
	elif(arch[0] == '32bit'):
		file = "config\\config32.yaml"

	config_file = open(file,"rt")
	config = yaml.safe_load(config_file)

	return config

def permission_check():
	
	# Call shell32 from windll to check permission
	if(ctypes.windll.shell32.IsUserAnAdmin() != 0):
		return True

	return False

def check_port(port):

	# Get state of port
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	result = sock.connect_ex(('localhost', port))
	sock.close()

	if(result == 0):
		return True

	return False

def prepare_dir(rDir):
	
	global sDir

	root_dir = rDir
	report_dir = root_dir + "\\report"
	sus_dir = root_dir + "\\suspicious"
	log_dir = root_dir + "\\log_files"
	temp_dir = "tmp"

	# Check if root dir not exists
	if not os.path.exists(root_dir):
		os.makedirs(root_dir)
		os.makedirs(report_dir)
		os.makedirs(sus_dir)
		os.makedirs(log_dir)
	else:
		if not os.path.exists(report_dir):
			os.makedirs(report_dir)

		if not os.path.exists(sus_dir):
			os.makedirs(sus_dir)

		if not os.path.exists(log_dir):
			os.makedirs(log_dir)

	if not os.path.exists(temp_dir):
		os.makedirs(temp_dir)

	sDir = sus_dir

def run_server(config):

	global server

	velociraptor_executable = config['velociraptor']
	artifacts_folder = config['artifacts']
	server_config = config['server_config']
	api_config = config['api_config']

	try:
		# Create API Config
		create_api_config_command = [velociraptor_executable, "--config", server_config, "config", "api_client", "--name", "admin", "--role", "administrator", api_config]
		subprocess.run(create_api_config_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

		# Run server
		command = [velociraptor_executable, "--definitions", artifacts_folder, "--config", server_config, "frontend"]
		server = subprocess.Popen(command, shell=True)

		# return server
	except Exception as e:
		print(e)

def clean():

	global server
	global sDir

	print("[+] Cleaning\t\t\t\t\t\t", end="", flush=True)
	if(os.path.exists("tmp")):
		shutil.rmtree("tmp")

	if(os.path.exists(sDir)):
		shutil.rmtree(sDir)

	startupinfo = subprocess.STARTUPINFO()
	startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # Optional: hide window
	process = subprocess.Popen(["taskkill", "/F", "/T", "/PID", str(server.pid)], startupinfo=startupinfo, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	process.wait()

def get_machine_info():
	data = subprocess.Popen(["systeminfo", "/fo", "CSV"], stdout=subprocess.PIPE).stdout.read().decode().strip().split("\r\n")

	ret = dict()
	t = re.findall("\"([^\"]*)\"", data[0])
	d = re.findall("\"([^\"]*)\"", data[1])

	for i in range(len(t)):
		ret[t[i]] = d[i].split(",")

	return ret

def run_redis():
	arch = platform.architecture()

	if(arch[0] == '64bit'):
		redis_server_path = ".\\data\\x64\\redis\\redis-server.exe"
		redis_working_dir = os.path.dirname(redis_server_path)
		redis_server = subprocess.Popen([redis_server_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=redis_working_dir, text=True, env=os.environ)
		return redis_server

	return 
	
def run(rDir):

	print("[+] Preparing\t\t\t\t\t\t", end="", flush=True)

	global server

	# Check port for velociraptor
	if(check_port(8001)):
		print("[!] Port 8001 is already in use")
		sys.exit(1)


	# Check permission 
	if(permission_check() == False):
		print("[!] Need run as administrator")
		sys.exit(1)


	# Preparing dir to store files
	prepare_dir(rDir)

	# Load config
	config = load_config()

	# Run server
	run_redis()
	run_server(config)

	print("[DONE]")
