# Ingris

A Python tool development project to help detect suspicious files.

```cmd
██╗███╗   ██╗ ██████╗ ██████╗ ██╗███████╗
██║████╗  ██║██╔════╝ ██╔══██╗██║██╔════╝
██║██╔██╗ ██║██║  ███╗██████╔╝██║███████╗
██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
██║██║ ╚████║╚██████╔╝██║  ██║██║███████║
╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝

                                         - IAP491_G8 -


usage: main.py [-h] [-o OUT_DIR] [-fs] [-ps] [-es] [-v]

Windows Malware Detection and Hunting Support Tool

options:
  -h, --help            show this help message and exit
  -o OUT_DIR, --out-dir OUT_DIR
                        save output to directory
  -fs, --file-scan      running with FileScan module
  -ps, --process-scan   running with ProcessScan module
  -es, --eventlog-scan  running with EventlogScan module
  -v, --version         show version of tools
  ```


## Recommendation

For the most comprehensive and valuable analysis, we strongly recommend using *Sysmon*, a free system monitor and event logging tool from *Microsoft*. *Sysmon* provides in-depth details about system activity, process creation, network connections, and more, which are invaluable for **Ingris**'s operations.


## Requirements

- **Administrator Privileges:** **Ingris** requires administrator privileges to function correctly. This is because certain functionalities, such as accessing system resources, necessitate elevated permissions.
- **VirusTotal API Key:** **Ingris** requires your VirusTotal API Key. Get your API Key and edit on `config\config.env` file
   - Example: 
      - Your VirusTotal API Key is: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
      - Content of `config\config.env`: 
```API_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa```
- **Port 8001:** **Ingris** utilizes port 8001 for communication. Please ensure that this port is open and not in use by any other applications on your system. If port 8001 is already occupied, you might need to:
  - Stop any conflicting applications: Identify and stop any applications currently using port 8001.
  - Or configure a different port on your own
- **Update Hayabusa Rules:** When you clone this repo to your local machine, you need to update Hayabusa Rules for using EventLogsScan module:
  - Run `tools\x64\hayabusa\hayabusa-2.19.0-win-x64.exe`with option `update-rules` and do the same with `tools\x32\hayabusa\hayabusa-2.19.0-win-x86.exe`
  - Full command:
    - x64: `tools\x64\hayabusa\hayabusa-2.19.0-win-x64.exe update-rules`
    - x32: `tools\x32\hayabusa\hayabusa-2.19.0-win-x86.exe update-rules`

## Downloads

Please download the latest stable version of Ingris with compiled binaries or compile the source code from the [Release](https://github.com/TwentySick/Ingris/releases) page


## Git Cloning

You can `git clone` the repository with the following command and run main.py file:

```
https://github.com/TwentySick/Ingris.git
```

**Note**: With this option, you'll need to have Python 3 and the required dependencies installed on your system. Issue this command to download all dependencies:

```cmd
pip install -r requirements.txt
```


## Thanks
Many thanks to KienTD and AnhDT for collaborating with me to develop this tool.
