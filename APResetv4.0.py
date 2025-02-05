import subprocess
import getpass
import logging
import re
import ipaddress
import os
import platform
import sys

# Configure logging
logging.basicConfig(
    filename="unifi_reset.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Detect OS
OS_TYPE = platform.system()
logging.info(f"OS is: ${OS_TYPE}")

#Check if Admin/sudo, prob a better way to do this, but it works :shrug:
def is_linux_sudo():
    return os.geteuid() == 0

def is_windows_admin():
    try:
        subprocess.check_output("net session", stderr=subprocess.STDOUT, shell=True)
        return True
    except subprocess.CalledProcessError as e:
        return False

def check_privileges():
    if sys.platform == "linux" or sys.platform == "linux2":
        if not is_linux_sudo():
            print("This script requires root privileges (sudo).")
            sys.exit(1)
    elif sys.platform == "win32":
        if not is_windows_admin():
            print("This script requires administrator privileges. Run from admin CMD.")
            sys.exit(1)
    else:
        print("Unsupported platform.")
        sys.exit(1)
check_privileges()


# Checks for arch, then installs depends (seems most arch installs are externally managed. not sure of a better way to do this.)
def install_python_package(package_name):
    try:
        __import__(package_name)
    except ImportError:
        print(f"{package_name} not found. Installing...")

        try:
            with open("/etc/os-release", "r") as f:
                os_release = f.read()
                if "ID_LIKE=arch" in os_release or "ID=arch" in os_release or "arch" in os_release.lower():
                    ARCH_BASED = True
                else:
                    ARCH_BASED = False
        except FileNotFoundError:
            logging.info("os-release file not found. Assuming non-Arch system.")
            ARCH_BASED = False
        #debugger   
        logging.debug(f"Is arch? {ARCH_BASED}")

        if ARCH_BASED:
            # Use pacman to install the package on Arch-based systems
            print(f"Detected Arch-based system. Installing {package_name} using pacman...")
            logging.info(f"Detected Arch-based system. Installing {package_name} using pacman...")
            subprocess.run(["sudo", "pacman", "-S", f"python-{package_name}"], check=True)
        else:
            # Use pip for non-Arch distros
            subprocess.run([sys.executable, "-m", "pip", "install", package_name], check=True)
            logging.info(f"Detected non-Arch system. Installing {package_name} using pip")

#Try to import, if not able, then try to install it using pip or arch based system specific method
while True:
    try:
        import paramiko
        from scapy.all import ARP, Ether, srp, conf
        break
    except ImportError as e:
        missing_package = str(e).split("'")[1]  # Extract missing package name
        print(f"{missing_package} not found. Installing...")
        #subprocess.run(["pip", "install", missing_package])
        install_python_package(missing_package)
        # Restart script after installation
        os.execv(sys.executable, ['python'] + sys.argv)

# Windows-specific: Install Npcap if missing
if OS_TYPE == "Windows":
    NPCAP_DIR = r"C:\\Program Files\\Npcap"
    NPCAP_URL = "https://npcap.com/dist/npcap-1.80.exe"
    INSTALLER_PATH = os.path.join(os.getenv("TEMP"), "npcap-setup.exe")

    def is_npcap_installed():
        return os.path.exists(NPCAP_DIR) and any(os.scandir(NPCAP_DIR))

    if not is_npcap_installed():
        print("Npcap not found. Downloading and installing...")
        logging.info(f"Downloading and installing Npcap.")
        subprocess.run(["curl", "-o", INSTALLER_PATH, NPCAP_URL], check=True)
        subprocess.run([INSTALLER_PATH, "/S"], check=True)
        os.remove(INSTALLER_PATH)
        print("Npcap installation completed. Restart may be required.")

#Linux-specific: Install arp-scan if missing
#Check pkg mgr
if OS_TYPE != "Windows":
    def get_package_manager():
        package_managers = {
            "pacman": "sudo pacman -S --noconfirm --needed",
            "apt": "sudo apt install -y",
            "dnf": "sudo dnf install -y",
            "yum": "sudo yum install -y",
            "zypper": "sudo zypper install -y"
        }

        for pm in package_managers.keys():
            if subprocess.run(["which", pm], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
                return package_managers[pm]

        return None

    #Checker for If installed
    def is_installed(command):
        return subprocess.run(["which", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0

    #PKG installer
    def install_package(package):
        package_manager = get_package_manager()
        if not package_manager:
            print("No supported package manager found. Install the 'arp-scan' package manually.")
            logging.error(f"No supported package manager found. Install the 'arp-scan' package manually.")
            return

        print(f"{package} not found. Installing using {package_manager}...")
        subprocess.run(f"{package_manager} {package}", shell=True, check=True)

    #Check if arp-scan is installed
    if not is_installed("arp-scan"):
        logging.info(f"ARP-SCAN is not installed. Installing using {package_manager}...")
        install_package("arp-scan")
    else:
        logging.info(f"ARP-SCAN is already installed. Skipping installation.")


# Define the list of UniFi OUIs. Add as needed (First 3 octets of MAC)
UNIFI_OUIS = ["60:22:32", "9c:05:d6", "e4:38:83", "fc:ec:da", "74:ac:b9", "74:83:c2"]

#Grab network interfaces
def parse_network_interfaces():
    interfaces = []

    if OS_TYPE == "Windows":
        try:
            result = subprocess.run(["ipconfig"], capture_output=True, text=True, check=True)
            output = result.stdout.splitlines()
            interface = {}

            for line in output:
                line = line.strip()
                if line.endswith(":") and "adapter" in line.lower():
                    if interface:
                        interfaces.append(interface)
                    interface = {"name": line.replace("Ethernet adapter ", "").replace(":", "").strip()}
                elif "IPv4 Address" in line:
                    match = re.search(r"IPv4 Address.*?:\s*(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        interface["ip"] = match.group(1)
                elif "Default Gateway" in line:
                    match = re.search(r"Default Gateway.*?:\s*(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        interface["gateway"] = match.group(1)
                elif "Subnet Mask" in line:
                    match = re.search(r"Subnet Mask.*?:\s*(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        interface["subnet"] = match.group(1)

            if interface:
                interfaces.append(interface)

        except subprocess.CalledProcessError as e:
            print(f"Error running ipconfig: {e}")

    elif OS_TYPE == "Linux":
        try:
            result = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                match = re.search(r"\d+: (\S+).*inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                if match:
                    interface = {
                        "name": match.group(1),
                        "ip": match.group(2),
                        "subnet": match.group(3),
                        "gateway": "N/A"  # Can be fetched via 'ip route' if needed
                    }
                    interfaces.append(interface)

        except subprocess.CalledProcessError as e:
            print(f"Error running 'ip addr show': {e}")

    return interfaces

#Prompts user to select network interface
def select_network_interface():
    interfaces = parse_network_interfaces()

    if not interfaces:
        print("No network interfaces found.")
        return None

    print("Available Network Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i + 1}: {iface['name']} (IP: {iface.get('ip', 'N/A')}, Subnet: {iface.get('subnet', 'N/A')})")

    while True:
        try:
            choice = int(input("Select the interface number to use: "))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                print("Invalid choice. Please select a valid interface number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

#Finds APs on network according to OUIs
def discover_unifi_aps(network):
    print(f"Scanning network {network} for UniFi APs...")

    devices = []
    if OS_TYPE == "Linux":
        try:
            result = subprocess.run(["arp-scan", "-l"], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)", line)
                if match:
                    ip, mac = match.groups()
                    mac_prefix = mac.lower()[:8]
                    if mac_prefix in UNIFI_OUIS:
                        devices.append({"ip": ip, "mac": mac})

        except FileNotFoundError:
            print("arp-scan not found. Falling back to Scapy.")
    
    if not devices:  # Fallback to Scapy
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        for sent, received in answered_list:
            mac_prefix = received.hwsrc.lower()[:8]
            if mac_prefix in UNIFI_OUIS:
                devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices

#SSHs into and resets APs
def reset_unifi_ap(ip, username, password):
    try:
        print(f"Connecting to {ip}...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)

        stdin, stdout, stderr = ssh.exec_command("set-default")
        print(f"Reset command sent to {ip}.")
        logging.info(f"Successfully reset AP at IP: {ip}")
        ssh.close()
    except paramiko.AuthenticationException:
        print(f"Authentication failed for AP at {ip}. Skipping...")
        logging.warning(f"Authentication failed for AP at {ip}")
    except Exception as e:
        print(f"Error resetting AP at {ip}: {e}")
        logging.error(f"Error resetting AP at IP: {ip}: {e}")

def main():
    selected_interface = select_network_interface()
    if not selected_interface:
        print("No valid interface selected. Exiting...")
        return

    network_range = f"{selected_interface['ip']}/{selected_interface['subnet']}"
    username = input("Enter the username: ")
    password = getpass.getpass("Enter the password: ")

    #Confirm one more time, just in case...
    confirmation = input(f"Do you want to scan network {network_range} and reset all found UniFi APs? (yes/no): ").strip().lower()
    if confirmation != "yes":
        print("Aborting reset process.")
        return

    aps = discover_unifi_aps(network_range)
    if not aps:
        print("No UniFi APs found.")
        logging.info("No UniFi APs found.")
        return

    print(f"Found {len(aps)} UniFi AP(s):")
    logging.info(f"Found {len(aps)} UniFi AP(s) on network {network_range}:")
    
    for ap in aps:
        print(f"IP: {ap['ip']}, MAC: {ap['mac']}")
        logging.info(f"Discovered AP - IP: {ap['ip']}, MAC: {ap['mac']}")
        
    for ap in aps:
        reset_unifi_ap(ap["ip"], username, password)


if __name__ == "__main__":
    main()
