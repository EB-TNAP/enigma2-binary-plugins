"""
NetworkBrowser Mount Presets - Common mount options for different operating systems
Simplifies mounting for users by providing tested mount option combinations
"""

# Common mount option presets for different operating systems and use cases
MOUNT_PRESETS = {
	# Modern Ubuntu/Linux with guest access (22.04+)
	"ubuntu_guest": {
		"name": "Ubuntu/Linux (Guest Access)",
		"description": "Modern Ubuntu 22.04+ with guest access",
		"options": "vers=3.0,guest,rw,iocharset=utf8,uid=0,gid=0",
		"username": "",
		"password": "",
		"typical_os": ["ubuntu", "linux", "debian"]
	},
	
	# Ubuntu/Linux with authentication
	"ubuntu_auth": {
		"name": "Ubuntu/Linux (User Auth)",
		"description": "Ubuntu/Linux with username/password",
		"options": "vers=3.0,sec=ntlmssp,rw,iocharset=utf8,uid=0,gid=0",
		"username": "required",
		"password": "required",
		"typical_os": ["ubuntu", "linux", "debian"]
	},
	
	# Windows 10/11 modern
	"windows_modern": {
		"name": "Windows 10/11 (Modern)",
		"description": "Windows 10/11 with SMB3",
		"options": "vers=3.0,sec=ntlmssp,rw,iocharset=utf8",
		"username": "required",
		"password": "required",
		"typical_os": ["windows"]
	},
	
	# Windows legacy (older versions)
	"windows_legacy": {
		"name": "Windows (Legacy)",
		"description": "Older Windows with SMB1/2 support",
		"options": "vers=2.0,sec=ntlm,rw,iocharset=utf8",
		"username": "required", 
		"password": "required",
		"typical_os": ["windows"]
	},
	
	# NAS devices (Synology, QNAP, etc.)
	"nas_device": {
		"name": "NAS Device (Synology/QNAP)",
		"description": "Network Attached Storage devices",
		"options": "vers=2.1,sec=ntlmssp,rw,iocharset=utf8,cache=loose",
		"username": "required",
		"password": "required", 
		"typical_os": ["nas", "synology", "qnap"]
	},
	
	# Generic fallback
	"generic": {
		"name": "Generic/Auto-detect",
		"description": "Generic SMB share with auto-negotiation",
		"options": "rw,iocharset=utf8",
		"username": "optional",
		"password": "optional",
		"typical_os": ["unknown"]
	}
}

def get_preset_for_os(os_type, device_class=None):
	"""Get the best mount preset for a detected operating system"""
	os_type = os_type.lower() if os_type else "unknown"
	device_class = device_class.lower() if device_class else "unknown"
	
	# Ubuntu/Linux detection
	if any(x in os_type for x in ["ubuntu", "linux", "debian"]):
		return "ubuntu_guest"  # Start with guest access, most common
		
	# Windows detection
	elif "windows" in os_type:
		return "windows_modern"  # Default to modern Windows
		
	# NAS detection
	elif any(x in device_class for x in ["nas", "storage"]) or any(x in os_type for x in ["synology", "qnap"]):
		return "nas_device"
		
	# Fallback
	else:
		return "generic"

def get_preset_options(preset_name):
	"""Get mount options for a specific preset"""
	return MOUNT_PRESETS.get(preset_name, MOUNT_PRESETS["generic"])

def get_all_presets():
	"""Get all available presets for selection"""
	presets = []
	for key, preset in MOUNT_PRESETS.items():
		presets.append((key, preset["name"]))
	return presets

def get_preset_description(preset_name):
	"""Get detailed description of a preset"""
	preset = MOUNT_PRESETS.get(preset_name)
	if preset:
		return f"{preset['name']}: {preset['description']}"
	return "Unknown preset"

def suggest_preset_for_device(hostip, hostname, os_info=None):
	"""Suggest the best preset based on device information"""
	if os_info:
		os_type = os_info.get('os_type', 'unknown')
		device_class = os_info.get('device_class', 'unknown')
		return get_preset_for_os(os_type, device_class)
	
	# Fallback to hostname-based detection
	hostname = hostname.lower() if hostname else ""
	if any(x in hostname for x in ["ubuntu", "linux", "debian"]):
		return "ubuntu_guest"
	elif any(x in hostname for x in ["windows", "win", "pc"]):
		return "windows_modern"
	else:
		return "generic"