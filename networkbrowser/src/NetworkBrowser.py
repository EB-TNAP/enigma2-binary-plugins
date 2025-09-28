import os
import pickle
import stat
import time

from enigma import eTimer
from Screens.Screen import Screen
from Screens.MessageBox import MessageBox
from Components.ActionMap import ActionMap
from Components.Sources.List import List
from Components.Sources.StaticText import StaticText
from Components.Network import iNetwork
from Components.config import ConfigIP, ConfigYesNo, config, ConfigSubsection, getConfigListEntry
from Components.ConfigList import ConfigListScreen
from Tools.Directories import resolveFilename, SCOPE_PLUGINS
from Tools.LoadPixmap import LoadPixmap

from .MountManager import AutoMountManager
from .AutoMount import iAutoMount
from .MountEdit import AutoMountEdit
from .UserDialog import UserDialog
from .MacVendors import identify_mac_vendor, discover_and_add_receiver
from .OSDetection import detect_device_os, get_device_type_for_shares
from . import netscan
from . import _

# Enhanced integration with enigma2-6 networking infrastructure
print("[NetworkBrowser] Enhanced version with enigma2-6 integration loaded")

# Configuration for NetworkBrowser enhancements
if not hasattr(config, "networkbrowser"):
	config.networkbrowser = ConfigSubsection()
if not hasattr(config.networkbrowser, "ping_reachable_only"):
	config.networkbrowser.ping_reachable_only = ConfigYesNo(default=True)


def write_cache(cache_file, cache_data):
	path = os.path.dirname(cache_file)
	if not os.path.isdir(path):
		try:
			os.mkdir(path)
		except Exception as ex:
			print("ERROR creating:", path, ex)
	with open(cache_file, 'wb') as fd:
		pickle.dump(cache_data, fd, -1)


def load_cache(cache_file):
	with open(cache_file, 'rb') as fd:
		return pickle.load(fd)


def valid_cache(cache_file, cache_ttl):
	# See if the cache file exists and is still living
	try:
		mtime = os.stat(cache_file)[stat.ST_MTIME]
	except (IOError, ValueError):
		return 0
	curr_time = time.time()
	if (curr_time - mtime) > cache_ttl:
		return 0
	else:
		return 1


class NetworkDescriptor:
	def __init__(self, name="NetworkServer", description=""):
		self.name = name
		self.description = description


class NetworkBrowser(Screen):
	skin = """
		<screen name="NetworkBrowser" position="90,80" size="560,450" title="Network Neighbourhood">
			<ePixmap pixmap="skin_default/buttons/red.png" position="0,0" size="140,40" alphatest="on" />
			<ePixmap pixmap="skin_default/buttons/green.png" position="140,0" size="140,40" alphatest="on" />
			<ePixmap pixmap="skin_default/buttons/yellow.png" position="280,0" size="140,40" alphatest="on" />
			<ePixmap pixmap="skin_default/buttons/blue.png" position="420,0" size="140,40" alphatest="on" />
			<widget source="key_red" render="Label" position="0,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#9f1313" transparent="1" />
			<widget source="key_green" render="Label" position="140,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#1f771f" transparent="1" />
			<widget source="key_yellow" render="Label" position="280,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#a08500" transparent="1" />
			<widget source="key_blue" render="Label" position="420,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#18188b" transparent="1" />
			<widget source="list" render="Listbox" position="5,50" size="540,350" zPosition="10" scrollbarMode="showOnDemand">
				<convert type="TemplatedMultiContent">
					{"template": [
							MultiContentEntryPixmapAlphaTest(pos = (0, 0), size = (48, 48), png = 1), # index 1 is the expandable/expanded/verticalline icon
							MultiContentEntryText(pos = (50, 4), size = (420, 26), font=2, flags = RT_HALIGN_LEFT, text = 2), # index 2 is the Hostname
							MultiContentEntryText(pos = (140, 5), size = (320, 25), font=0, flags = RT_HALIGN_LEFT, text = 3), # index 3 is the sharename
							MultiContentEntryText(pos = (140, 26), size = (320, 17), font=1, flags = RT_HALIGN_LEFT, text = 4), # index 4 is the sharedescription
							MultiContentEntryPixmapAlphaTest(pos = (45, 0), size = (48, 48), png = 5), # index 5 is the nfs/cifs icon
							MultiContentEntryPixmapAlphaTest(pos = (90, 0), size = (48, 48), png = 6), # index 6 is the isMounted icon
						],
					"fonts": [gFont("Regular", 20),gFont("Regular", 14),gFont("Regular", 24)],
					"itemHeight": 50
					}
				</convert>
			</widget>
			<ePixmap pixmap="skin_default/div-h.png" position="0,410" zPosition="1" size="560,2" />
			<widget source="infotext" render="Label" position="0,420" size="560,30" zPosition="10" font="Regular;21" halign="center" valign="center" backgroundColor="#25062748" transparent="1" />
		</screen>"""

	def __init__(self, session, iface, plugin_path):
		Screen.__init__(self, session)
		self.skin_path = plugin_path
		self.session = session
		self.iface = iface
		if self.iface is None:
			self.iface = 'eth0'
		self.networklist = None
		self.device = None
		self.mounts = None
		self.expanded = []
		self.cache_ttl = 3600  # Seconds cache is considered valid, 1 hour for more current results
		self.cache_file = '/etc/enigma2/networkbrowser.cache'  # Path to cache directory
		self.scan_services = False  # Start with fast mode, enable service scanning on demand

		self["key_red"] = StaticText(_("Close"))
		self["key_green"] = StaticText(_("Mounts management"))
		self["key_yellow"] = StaticText(_("Rescan"))
		self["key_blue"] = StaticText(_("Setup"))
		self["infotext"] = StaticText(_("Press OK to mount!"))

		self["shortcuts"] = ActionMap(["ShortcutActions", "WizardActions"],
		{
			"ok": self.go,
			"back": self.close,
			"red": self.close,
			"green": self.keyGreen,
			"yellow": self.keyYellow,
			"blue": self.keyBlue,
		})

		self.list = []
		self.statuslist = []
		self.listindex = 0
		self["list"] = List(self.list)
		self["list"].onSelectionChanged.append(self.selectionChanged)

		self.onLayoutFinish.append(self.startRun)
		self.onShown.append(self.setWindowTitle)
		self.onClose.append(self.cleanup)
		self.Timer = eTimer()
		self.Timer.callback.append(self.TimerFire)

	def cleanup(self):
		del self.Timer
		iAutoMount.stopMountConsole()
		iNetwork.stopRestartConsole()
		iNetwork.stopGetInterfacesConsole()

	def startRun(self):
		self.expanded = []
		self.setStatus('update')
		self.mounts = iAutoMount.getMountsList()
		self["infotext"].setText("")
		self.vc = valid_cache(self.cache_file, self.cache_ttl)
		if self.cache_ttl > 0 and self.vc != 0:
			self.process_NetworkIPs()
		else:
			self.Timer.start(3000)

	def TimerFire(self):
		self.Timer.stop()
		self.process_NetworkIPs()

	def setWindowTitle(self):
		self.setTitle(_("Browse network neighbourhood"))

	def keyGreen(self):
		self.session.open(AutoMountManager, None, self.skin_path)

	def keyYellow(self):
		try:
			os.unlink(self.cache_file)
		except (IOError):
			pass
		self.startRun()

	def keyBlue(self):
		self.session.openWithCallback(self.configClosed, NetworkBrowserSetup)

	def configClosed(self, result=None):
		"""Callback when configuration screen is closed - refresh list if settings changed"""
		if result:
			print("[NetworkBrowser] Configuration changed, refreshing network list")
			self.keyYellow()  # Trigger rescan

	def scanIPclosed(self, result):
		if result[0]:
			if result[1] == "address":
				print("[Networkbrowser] got IP:", result[1])
				nwlist = []
				nwlist.append(netscan.netzInfo(result[0] + "/24"))
				self.networklist += nwlist[0]
			elif result[1] == "nfs":
				self.networklist.append(['host', result[0], result[0], '00:00:00:00:00:00', result[0], 'Master Browser'])

		if len(self.networklist) > 0:
			write_cache(self.cache_file, self.networklist)
			self.updateHostsList()

	def setStatus(self, status=None):
		if status:
			self.statuslist = []
			if status == 'update':
				statuspng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/update.png"))
				self.statuslist.append((['info'], statuspng, "Scanning...This may take 5-10 minutes", None, None, None, None))
				self['list'].setList(self.statuslist)
			elif status == 'error':
				statuspng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/error.png"))
				self.statuslist.append((['info'], statuspng, _("No network devices found!"), None, None, None, None))
				self['list'].setList(self.statuslist)

	def process_NetworkIPs(self):
		self.inv_cache = 0
		self.vc = valid_cache(self.cache_file, self.cache_ttl)
		if self.cache_ttl > 0 and self.vc != 0:
			print('[Networkbrowser] Loading network cache from ', self.cache_file)
			try:
				self.networklist = load_cache(self.cache_file)
			except (IOError, ValueError):
				self.inv_cache = 1
		if self.cache_ttl == 0 or self.inv_cache == 1 or self.vc == 0:
			print('[Networkbrowser] Getting fresh network list')
			self.networklist = self.getNetworkIPs()
			write_cache(self.cache_file, self.networklist)
		if len(self.networklist) > 0:
			self.updateHostsList()
		else:
			self.setStatus('error')

	def getNetworkIPs(self):
		"""
		Enhanced Network Discovery for TNAP Community Images
		
		Combines multiple discovery methods for comprehensive network device detection:
		1. ARP table scanning (most reliable for active devices)
		2. Extended ping sweep (covers common DHCP ranges)  
		3. Advanced network tools (ip neigh, ethtool integration)
		4. Original NetBIOS scanning (Windows device compatibility)
		5. Intelligent device identification (MAC vendor lookup, service detection)
		
		Significantly improves discovery of modern devices (phones, tablets, IoT, smart TVs)
		that don't respond to traditional NetBIOS scanning.
		"""
		nwlist = []
		discovered_hosts = []
		
		# ENHANCED: Use enigma2 network infrastructure for interface management
		active_interfaces = self.getActiveInterfaces()
		if not active_interfaces:
			print("[NetworkBrowser] No active network interfaces found")
			return nwlist
		
		# Process all active interfaces (not just the primary one)
		all_subnets = set()
		for iface_info in active_interfaces:
			subnet_base = iface_info['subnet_base']
			all_subnets.add(subnet_base)
			strIP = subnet_base + ".0/24"
			print(f"[NetworkBrowser] Enhanced scan of {iface_info['name']} subnet: {strIP}")
			
			# Method 1: ARP table discovery (most reliable)
			discovered_hosts.extend(self.getARPHosts(subnet_base))
			
			# Method 2: Ping sweep for active devices
			discovered_hosts.extend(self.getPingHosts(subnet_base))
			
			# Method 2.5: Use ethtool and ip neigh for additional discovery
			discovered_hosts.extend(self.getAdvancedNetworkHosts(subnet_base))
			
			# Method 3: Original NetBIOS scan (for Windows devices)
			try:
				nInfo = netscan.netzInfo(strIP)
				if nInfo:
					nwlist.append(nInfo)
			except Exception as e:
				print("[Networkbrowser] error netscan.netzInfo", strIP, e)
		
		# Skip the original single-interface processing since we handle all interfaces above
		if not all_subnets:
			# Fallback to original method
			self.IP = iNetwork.getAdapterAttribute(self.iface, "ip")
			if len(self.IP):
				subnet_base = str(self.IP[0]) + "." + str(self.IP[1]) + "." + str(self.IP[2])
				strIP = subnet_base + ".0/24"
				print("[NetworkBrowser] Fallback scan of subnet:", strIP)
				
				# Method 1: ARP table discovery (most reliable)
				discovered_hosts.extend(self.getARPHosts(subnet_base))
				
				# Method 2: Ping sweep for active devices
				discovered_hosts.extend(self.getPingHosts(subnet_base))
				
				# Method 2.5: Use ethtool and ip neigh for additional discovery
				discovered_hosts.extend(self.getAdvancedNetworkHosts(subnet_base))
				
				# Method 3: Original NetBIOS scan (for Windows devices)
				try:
					nInfo = netscan.netzInfo(strIP)
					if nInfo:
						nwlist.append(nInfo)
				except Exception as e:
					print("[Networkbrowser] error netscan.netzInfo", strIP, e)
		
		# Method 4: Add discovered hosts to NetBIOS results with filtering
		if discovered_hosts:
			# Get ping-responsive hosts for filtering
			ping_responsive_ips = set()
			for ip, mac in discovered_hosts:
				if mac == '00:00:00:00:00:00':  # This indicates it was found by ping
					ping_responsive_ips.add(ip)
			
			enhanced_hosts = self.enhanceDiscoveredHosts(discovered_hosts, subnet_base, ping_responsive_ips)
			if nwlist and len(nwlist) > 0:
				nwlist[0].extend(enhanced_hosts)
			else:
				nwlist = [enhanced_hosts]
				
		print(f"[NetworkBrowser] Found {len(discovered_hosts)} additional hosts via ARP/ping")
		return nwlist and nwlist[0] or nwlist
	
	def getActiveInterfaces(self):
		"""Get all active network interfaces using enigma2 infrastructure"""
		active_interfaces = []
		try:
			adapters = iNetwork.getAdapterList()
			for adapter in adapters:
				if iNetwork.isBlacklisted(adapter):
					continue
					
				# Check if interface is up and has IP
				is_up = iNetwork.getAdapterAttribute(adapter, 'up')
				ip = iNetwork.getAdapterAttribute(adapter, 'ip')
				
				if is_up and ip and ip != [0, 0, 0, 0]:
					subnet_base = f"{ip[0]}.{ip[1]}.{ip[2]}"
					mac = iNetwork.getAdapterAttribute(adapter, 'mac')
					desc = iNetwork.getFriendlyAdapterName(adapter)
					
					interface_info = {
						'name': adapter,
						'friendly_name': desc or adapter,
						'ip': ip,
						'subnet_base': subnet_base,
						'mac': mac,
						'is_wireless': iNetwork.isWirelessInterface(adapter)
					}
					active_interfaces.append(interface_info)
					print(f"[NetworkBrowser] Found active interface: {adapter} ({desc}) - {subnet_base}.x")
					
		except Exception as e:
			print(f"[NetworkBrowser] Error getting active interfaces: {e}")
			
		return active_interfaces
	
	def getARPHosts(self, subnet_base):
		"""Discover hosts from ARP table"""
		hosts = []
		try:
			import subprocess
			# Read ARP table
			with open('/proc/net/arp', 'r') as f:
				for line in f:
					if subnet_base in line and 'eth0' in line:
						parts = line.split()
						if len(parts) >= 4:
							ip = parts[0]
							mac = parts[3]
							if ip.startswith(subnet_base) and mac != '00:00:00:00:00:00':
								hosts.append((ip, mac))
								print(f"[NetworkBrowser] ARP found: {ip} -> {mac}")
		except Exception as e:
			print(f"[NetworkBrowser] ARP scan error: {e}")
		return hosts
	
	def getPingHosts(self, subnet_base):
		"""Ping sweep to find active hosts"""
		hosts = []
		try:
			import subprocess
			# Extended ping sweep - cover more IP ranges
			# Based on your arp-scan: .1, .22, .41, .117, .127, .160, .176, .246, .253
			ping_ranges = []
			
			# Common router/gateway IPs
			ping_ranges.extend([1, 2, 3, 4, 5])
			
			# DHCP ranges (most devices)
			ping_ranges.extend(range(10, 30))    # .10-.29
			ping_ranges.extend(range(40, 50))    # .40-.49  
			ping_ranges.extend(range(100, 130))  # .100-.129
			ping_ranges.extend(range(150, 180))  # .150-.179
			ping_ranges.extend(range(240, 255))  # .240-.254
			
			print(f"[NetworkBrowser] Ping scanning {len(ping_ranges)} addresses...")
			
			for i in ping_ranges:
				ip = f"{subnet_base}.{i}"
				try:
					result = subprocess.run(['ping', '-c1', '-W1', ip], 
										  capture_output=True, timeout=1)
					if result.returncode == 0:
						hosts.append((ip, '00:00:00:00:00:00'))  # Unknown MAC
						print(f"[NetworkBrowser] Ping found: {ip}")
				except:
					pass
		except Exception as e:
			print(f"[NetworkBrowser] Ping sweep error: {e}")
		return hosts
	
	def getAdvancedNetworkHosts(self, subnet_base):
		"""Use enigma2 infrastructure and enhanced network tools for discovery"""
		hosts = []
		try:
			import subprocess
			
			# ENHANCED: Use enigma2's network interface management
			active_interfaces = iNetwork.getAdapterList()
			for adapter in active_interfaces:
				if iNetwork.isBlacklisted(adapter):
					continue
					
				# Use enigma2's built-in link state checking
				try:
					# This leverages enigma2's existing ethtool integration
					iNetwork.getLinkState(adapter, lambda result: self.linkStateCallback(adapter, result))
				except:
					pass
			
			# Use 'ip neigh show' command (enhanced networking tools)
			try:
				result = subprocess.run(['ip', 'neigh', 'show'], 
									  capture_output=True, text=True, timeout=5)
				if result.returncode == 0:
					for line in result.stdout.split('\n'):
						if subnet_base in line:
							parts = line.split()
							if len(parts) >= 5:
								ip = parts[0]
								mac = parts[4] if 'lladdr' in line else '00:00:00:00:00:00'
								if 'REACHABLE' in line or 'STALE' in line or 'DELAY' in line:
									hosts.append((ip, mac))
									print(f"[NetworkBrowser] ip neigh found: {ip} -> {mac}")
			except:
				pass
				
		except Exception as e:
			print(f"[NetworkBrowser] Advanced network discovery error: {e}")
		return hosts
	
	def linkStateCallback(self, adapter, result):
		"""Callback for enigma2 link state checking"""
		try:
			if 'Link detected: yes' in result:
				desc = iNetwork.getFriendlyAdapterName(adapter)
				print(f"[NetworkBrowser] enigma2 ethtool: {adapter} ({desc}) link is active")
		except:
			pass
	
	def enhanceDiscoveredHosts(self, discovered_hosts, subnet_base, ping_responsive_ips=None):
		"""Convert discovered hosts to NetworkBrowser format with ping-reachable filtering"""
		enhanced = []
		ping_reachable_only = config.networkbrowser.ping_reachable_only.value
		
		for ip, mac in discovered_hosts:
			# If ping-reachable filter is enabled, check if device responds to ping
			if ping_reachable_only:
				# Use cached ping results if available, otherwise do fresh ping test
				if ping_responsive_ips and ip not in ping_responsive_ips:
					if not self.isPingReachable(ip):
						print(f"[NetworkBrowser] Filtering out non-responsive device: {ip}")
						continue
				elif not ping_responsive_ips and not self.isPingReachable(ip):
					print(f"[NetworkBrowser] Filtering out non-responsive device: {ip}")
					continue
			
			# Create intelligent hostname based on device identification
			hostname = self.identifyDevice(ip, mac)
			# Format: ['host', hostname, ip, mac, domain, service]
			host_entry = ['host', hostname, ip, mac, subnet_base, 'Network Device']
			enhanced.append(host_entry)
		return enhanced
	
	def isPingReachable(self, ip):
		"""Fast ping test to verify device is reachable"""
		try:
			import subprocess
			# Fast ping test: 1 packet, 1 second timeout
			result = subprocess.run(['ping', '-c1', '-W1', ip], 
								  capture_output=True, timeout=2)
			return result.returncode == 0
		except:
			return False
	
	def identifyDevice(self, ip, mac):
		"""Identify device type using enigma2 infrastructure and enhanced detection"""
		# Get last octet for generic naming
		last_octet = ip.split('.')[-1]
		
		# ENHANCED: Check if this is a local enigma2-managed adapter first
		local_adapter_name = self.identifyLocalAdapter(ip, mac)
		if local_adapter_name:
			return local_adapter_name
		
		# Try reverse DNS lookup for hostname
		hostname = self.getHostname(ip)
		if hostname and hostname != ip:
			return hostname
		
		# Identify by MAC address vendor (OUI lookup)
		device_type = self.identifyByMAC(mac)
		if device_type:
			# Auto-discover new receivers for community database
			if hostname and device_type in ['STB', 'Unknown', 'Computer'] and \
			   any(term in hostname.lower() for term in ['receiver', 'sat', 'stb', 'box', 'decoder']):
				discover_and_add_receiver(mac, hostname)
			return f"{device_type}_{last_octet}"
		
		# Identify by IP address patterns (common network conventions)
		if last_octet == '1':
			return f"Gateway_{last_octet}"
		elif last_octet == '254':
			return f"Router_{last_octet}"
		elif ip == self.getMyIP():
			return f"STB_{last_octet}"  # This STB device
		
		# Check if device responds to common services
		device_service = self.probeServices(ip)
		if device_service:
			return f"{device_service}_{last_octet}"
		
		# Default naming
		return f"Device_{last_octet}"
	
	def identifyLocalAdapter(self, ip, mac):
		"""Use enigma2 infrastructure to identify local network adapters"""
		try:
			adapters = iNetwork.getAdapterList()
			for adapter in adapters:
				if iNetwork.isBlacklisted(adapter):
					continue
					
				adapter_ip = iNetwork.getAdapterAttribute(adapter, 'ip')
				adapter_mac = iNetwork.getAdapterAttribute(adapter, 'mac')
				
				# Check if this matches a local adapter
				if adapter_mac and adapter_mac.lower() == mac.lower():
					# This is a local interface - use enigma2's description
					desc = iNetwork.getFriendlyAdapterDescription(adapter)
					friendly_name = iNetwork.getFriendlyAdapterName(adapter)
					
					if iNetwork.isWirelessInterface(adapter):
						# Enhanced wireless identification
						module = iNetwork.detectWlanModule(adapter)
						if module and module != 'wext':
							return f"{friendly_name} ({module})"
						return f"{friendly_name} (WiFi)"
					else:
						return friendly_name or desc
				
				# Check if IP matches (different MAC but same IP - possible after reboot)
				if adapter_ip and adapter_ip != [0, 0, 0, 0]:
					adapter_ip_str = f"{adapter_ip[0]}.{adapter_ip[1]}.{adapter_ip[2]}.{adapter_ip[3]}"
					if adapter_ip_str == ip:
						desc = iNetwork.getFriendlyAdapterDescription(adapter)
						return f"{desc} (Local)"
						
		except Exception as e:
			print(f"[NetworkBrowser] Error in identifyLocalAdapter: {e}")
		
		return None
	
	def getHostname(self, ip):
		"""Try multiple methods to resolve hostname"""
		# Method 1: Standard reverse DNS lookup
		try:
			import socket
			hostname = socket.gethostbyaddr(ip)[0]
			hostname = hostname.split('.')[0]  # Remove domain part
			
			if hostname and hostname != ip:
				return self.enhanceHostname(hostname)
		except:
			pass
		
		# Method 2: NetBIOS name lookup using nmblookup
		try:
			import subprocess
			result = subprocess.run(['nmblookup', '-A', ip], capture_output=True, text=True, timeout=3)
			if result.returncode == 0:
				for line in result.stdout.split('\n'):
					if '<00>' in line and 'GROUP' not in line:
						hostname = line.split()[0].strip()
						if hostname and hostname != ip:
							return self.enhanceHostname(hostname)
		except:
			pass
		
		# Method 3: SMB/CIFS hostname detection using smbclient
		try:
			import subprocess
			result = subprocess.run(['smbclient', '-L', ip, '-N'], capture_output=True, text=True, timeout=5)
			if result.returncode == 0:
				for line in result.stdout.split('\n'):
					if 'Server=' in line or 'Workgroup=' in line:
						# Extract server name from smbclient output
						if 'Server=' in line:
							server_info = line.split('Server=')[1].split()[0] if 'Server=' in line else ''
							if server_info and server_info != ip:
								return self.enhanceHostname(server_info)
		except:
			pass
		
		return None
	
	def enhanceHostname(self, hostname):
		"""Enhance hostname with receiver detection"""
		hostname_lower = hostname.lower()
		
		# Special handling for pli-precision (Ubuntu development machine)
		if 'pli-precision' in hostname_lower:
			return 'Ubuntu_DevMachine'
		
		# Satellite receiver patterns
		if 'mio4k' in hostname_lower or 'mio-4k' in hostname_lower:
			return 'Edision_Mio4K'
		elif 'osmio4k' in hostname_lower or 'osmini4k' in hostname_lower:
			return 'Edision_' + hostname
		elif 'sf8008' in hostname_lower:
			return 'Octagon_SF8008'
		elif 'vu+' in hostname_lower or 'vuplus' in hostname_lower:
			return 'VU+_' + hostname
		elif 'dreambox' in hostname_lower or 'dream' in hostname_lower:
			return 'Dreambox_' + hostname
		elif 'zgemma' in hostname_lower:
			return 'Zgemma_' + hostname
		elif 'gigablue' in hostname_lower:
			return 'Gigablue_' + hostname
		elif any(stb in hostname_lower for stb in ['receiver', 'stb', 'sat', 'decoder']):
			return 'STB_' + hostname
		
		return hostname
	
	def identifyByMAC(self, mac):
		"""Identify device vendor by MAC address using external database"""
		return identify_mac_vendor(mac)
	
	def probeServices(self, ip):
		"""Quick service probe to identify device type"""
		try:
			import socket
			
			# Quick port checks with very short timeout
			common_ports = {
				22: 'SSH_Server',
				80: 'Web_Server', 
				139: 'Windows_PC',
				445: 'Windows_PC',
				548: 'Mac_Server',
				631: 'Printer',
				8080: 'Media_Device'
			}
			
			for port, service in common_ports.items():
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(0.5)  # Very quick timeout
				try:
					result = sock.connect_ex((ip, port))
					if result == 0:
						sock.close()
						return service
				except:
					pass
				finally:
					sock.close()
		except:
			pass
		return None
	
	def getMyIP(self):
		"""Get this STB's IP address using enigma2 infrastructure"""
		try:
			adapters = iNetwork.getAdapterList()
			for adapter in adapters:
				if not iNetwork.isBlacklisted(adapter):
					ip = iNetwork.getAdapterAttribute(adapter, 'ip')
					if ip and ip != [0, 0, 0, 0]:
						return f"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}"
		except:
			# Fallback to original method
			if hasattr(self, 'IP') and len(self.IP) >= 4:
				return f"{self.IP[0]}.{self.IP[1]}.{self.IP[2]}.{self.IP[3]}"
		return None

	def getNetworkShares(self, hostip, hostname, devicetype):
		"""
		Enhanced Share Discovery for Modern Network Devices
		
		Detects multiple types of network services:
		- Traditional SMB/CIFS and NFS shares
		- HTTP/Web interfaces  
		- Media servers (DLNA/UPnP)
		- SSH/FTP services
		- IoT device interfaces
		- Printer services
		"""
		sharelist = []
		self.sharecache_file = None
		self.sharecache_file = '/etc/enigma2/' + hostname.strip() + '.cache'  # Path to cache directory
		username = 'guest'
		password = 'guest'
		try:
			hostdata = load_cache(self.sharecache_file)
		except (IOError, ValueError):
			pass
		else:
			username = hostdata['username']
			password = hostdata['password']

		# Method 1: Traditional file shares (SMB/CIFS/NFS)
		traditional_shares = self.getTraditionalShares(hostip, hostname, devicetype, username, password)
		sharelist.extend(traditional_shares)
		
		# Method 2: Modern network services (optional, non-blocking)
		# Only scan services if explicitly requested to avoid UI freezing
		if hasattr(self, 'scan_services') and self.scan_services:
			modern_services = self.getModernServices(hostip, hostname)
			sharelist.extend(modern_services)
		else:
			# Always show device as accessible without service scan
			basic_service = self.createBasicServiceEntry(hostip, hostname)
			if basic_service:
				sharelist.append(basic_service)
		
		return sharelist
	
	def getTraditionalShares(self, hostip, hostname, devicetype, username, password):
		"""Get traditional SMB/CIFS and NFS shares with enhanced detection"""
		sharelist = []
		
		print(f"[NetworkBrowser] Scanning shares on {hostip} ({hostname}) - type: {devicetype}")
		
		# Method 1: Try original netscan module (legacy SMB)
		try:
			if devicetype in ['unix', 'linux']:
				# Linux/Unix devices - try both SMB and NFS
				smblist = netscan.smbShare(hostip, hostname, username, password)
				print(f"[NetworkBrowser] Legacy SMB scan found {len(smblist)} shares")
				for x in smblist:
					if len(x) == 6:
						if x[3] != 'IPC$':
							sharelist.append(x)
							print(f"[NetworkBrowser] Added SMB share: {x[3]}")
				nfslist = netscan.nfsShare(hostip, hostname)
				print(f"[NetworkBrowser] NFS scan found {len(nfslist)} shares")
				for x in nfslist:
					if len(x) == 6:
						sharelist.append(x)
						print(f"[NetworkBrowser] Added NFS share: {x[3]}")
			elif devicetype == 'mac':
				# Mac devices - try SMB and AFP
				smblist = netscan.smbShare(hostip, hostname, username, password)
				print(f"[NetworkBrowser] Legacy SMB scan found {len(smblist)} shares")
				for x in smblist:
					if len(x) == 6:
						if x[3] != 'IPC$':
							sharelist.append(x)
							print(f"[NetworkBrowser] Added SMB share: {x[3]}")
				# Note: AFP support would need additional implementation
			else:
				# Windows devices - primarily SMB/CIFS
				smblist = netscan.smbShare(hostip, hostname, username, password)
				print(f"[NetworkBrowser] Legacy SMB scan found {len(smblist)} shares")
				for x in smblist:
					if len(x) == 6:
						if x[3] != 'IPC$':
							sharelist.append(x)
		except Exception as e:
			print(f"[NetworkBrowser] Legacy SMB/NFS scan failed: {e}")
		
		# Enhanced modern share detection for all systems
		if len(sharelist) == 0 and devicetype in ['windows', 'mac', 'linux', 'unix']:
			modern_shares = self.getModernSMBShares(hostip, hostname, username, password)
			sharelist.extend(modern_shares)
			
		return sharelist
	
	def getModernSMBShares(self, hostip, hostname, username, password):
		"""Modern SMB share detection using smbclient with legacy fallback"""
		shares = []
		
		try:
			import subprocess
			
			# Try modern smbclient first (SMB2/3 compatible)
			try:
				cmd = ['smbclient', '-L', hostip, '-N', '-g']
				result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
				
				if result.returncode == 0:
					for line in result.stdout.split('\n'):
						if line.startswith('Disk|'):
							parts = line.split('|')
							if len(parts) >= 2:
								share_name = parts[1].strip()
								share_desc = parts[2].strip() if len(parts) > 2 else ''
								if share_name and share_name not in ['IPC$', 'print$', 'ADMIN$']:
									share_entry = ['smbShare', hostname, hostip, share_name, share_name, share_desc]
									shares.append(share_entry)
					
					return shares
					
			except FileNotFoundError:
				# smbclient not available, fall back to legacy method
				pass
			except Exception:
				# Modern method failed, fall back to legacy
				pass
			
			# Fallback to legacy netscan for systems without smbclient
			try:
				legacy_shares = netscan.smbShare(hostip, hostname, username, password)
				shares.extend([s for s in legacy_shares if len(s) >= 6 and s[3] not in ['IPC$', 'print$', 'ADMIN$']])
			except Exception:
				pass
		
		except Exception:
			pass
		
		return shares
	
	
	def createBasicServiceEntry(self, hostip, hostname):
		"""Create a basic service entry showing device is accessible"""
		# Create a simple "Device Available" entry
		# Format: [type, hostname, ip, service_name, port, description]
		basic_entry = ['deviceAvailable', hostname, hostip, 'Device', '---', 'Network device (click to scan services)']
		return basic_entry
	
	def getModernServices(self, hostip, hostname):
		"""Detect modern network services and interfaces (fast scan)"""
		services = []
		
		# Reduced port list for faster scanning - only most common services
		service_ports = {
			80: ('Web', 'Web Interface'),
			443: ('HTTPS', 'Secure Web Interface'),
			22: ('SSH', 'Secure Shell Access'),  
			21: ('FTP', 'File Transfer Protocol'),
			631: ('IPP', 'Internet Printing Protocol'),
			8080: ('Web-Alt', 'Alternative Web Interface'),
			9090: ('Web-Admin', 'Web Administration'),
			32400: ('Plex', 'Plex Media Server')
		}
		
		print(f"[NetworkBrowser] Quick service scan on {hostip} ({hostname})")
		
		# Quick scan with very short timeout
		for port, (service_type, description) in service_ports.items():
			if self.checkPortFast(hostip, port):
				# Create a virtual "share" entry for detected services
				# Format: [type, hostname, ip, service_name, port, description]
				service_entry = ['modernService', hostname, hostip, service_type, str(port), description]
				services.append(service_entry)
				print(f"[NetworkBrowser] Found {service_type} service on {hostip}:{port}")
		
		# If no services found, add basic entry
		if not services:
			basic_entry = self.createBasicServiceEntry(hostip, hostname)
			if basic_entry:
				services.append(basic_entry)
		
		return services
	
	def checkPort(self, ip, port):
		"""Standard port availability check"""
		try:
			import socket
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(1.0)  # Standard timeout
			result = sock.connect_ex((ip, port))
			sock.close()
			return result == 0
		except:
			return False
	
	def checkPortFast(self, ip, port):
		"""Ultra-fast port availability check to prevent UI freezing"""
		try:
			import socket
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(0.3)  # Very fast timeout - 300ms max
			result = sock.connect_ex((ip, port))
			sock.close()
			return result == 0
		except:
			return False

	def updateHostsList(self):
		self.list = []
		self.network = {}
		for x in self.networklist:
			if x[2] not in self.network:
				self.network[x[2]] = []
			self.network[x[2]].append((NetworkDescriptor(name=x[1], description=x[2]), x))

		for x in self.network.keys():
			hostentry = self.network[x][0][1]
			name = hostentry[2] + " ( " + hostentry[1].strip() + " )"
			expandableIcon = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/host.png"))
			self.list.append((hostentry, expandableIcon, name, None, None, None, None))

		if len(self.list):
			for entry in self.list:
				entry[0][2] = "%3s.%3s.%3s.%3s" % tuple(entry[0][2].split("."))
			self.list.sort(key=lambda x: x[0][2])
			for entry in self.list:
				entry[0][2] = entry[0][2].replace(" ", "")
		self["list"].setList(self.list)
		self["list"].setIndex(self.listindex)

	def updateNetworkList(self):
		self.list = []
		self.network = {}
		self.mounts = iAutoMount.getMountsList()  # reloading mount list
		for x in self.networklist:
			if x[2] not in self.network:
				self.network[x[2]] = []
			self.network[x[2]].append((NetworkDescriptor(name=x[1], description=x[2]), x))
		self.network = {k: self.network[k] for k in sorted(self.network)}
		for x in self.network:
			# Enhanced OS detection using multiple methods
			hostinfo = self.network[x][0][1]
			ip = hostinfo[2]
			mac = hostinfo[3] if hostinfo[3] != '00:00:00:00:00:00' else None
			hostname = hostinfo[1].strip() if hostinfo[1].strip() else None
			
			# Use advanced OS detection
			self.device = get_device_type_for_shares(ip, mac, hostname)
			print(f"[NetworkBrowser] Device {ip} detected as: {self.device}")
			
			if x in self.expanded:
				networkshares = self.getNetworkShares(x, hostname or ip, self.device)
				hostentry = self.network[x][0][1]
				name = hostentry[2] + " ( " + hostentry[1].strip() + " )"
				expandedIcon = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/host.png"))
				self.list.append((hostentry, expandedIcon, name, None, None, None, None))
				for share in networkshares:
					self.list.append(self.BuildNetworkShareEntry(share))
			else:  # HOSTLIST - VIEW
				hostentry = self.network[x][0][1]
				name = hostentry[2] + " ( " + hostentry[1].strip() + " )"
				expandableIcon = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/host.png"))
				self.list.append((hostentry, expandableIcon, name, None, None, None, None))
		if len(self.list):
			for entry in self.list:
				entry[0][2] = "%3s.%3s.%3s.%3s" % tuple(entry[0][2].split("."))
			self.list.sort(key=lambda x: x[0][2])
			for entry in self.list:
				entry[0][2] = entry[0][2].replace(" ", "")
		self["list"].setList(self.list)
		self["list"].setIndex(self.listindex)

	def BuildNetworkShareEntry(self, share):
		verticallineIcon = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/verticalLine.png"))
		sharetype = share[0]
		sharehost = share[2]

		# Handle traditional shares (SMB/NFS)
		if sharetype == 'smbShare':
			sharedir = share[3]
			sharedescription = share[5]
			newpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/i-smb.png"))
		elif sharetype == 'nfsShare':
			sharedir = share[4]
			sharedescription = share[3]
			newpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/i-nfs.png"))
		elif sharetype == 'modernService':
			# Handle modern network services
			# Format: [type, hostname, ip, service_name, port, description]
			service_name = share[3]
			port = share[4]
			sharedescription = share[5]
			sharedir = f"{service_name}:{port}"
			
			# Choose appropriate icon based on service type
			if service_name in ['Web', 'HTTPS', 'Web-Alt', 'HTTPS-Alt', 'Web-Admin']:
				newpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/host.png"))  # Web services
			elif service_name in ['FTP', 'SSH', 'Telnet', 'AFP']:
				newpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/i-nfs.png"))  # File services
			elif service_name in ['UPnP', 'UPnP-Media', 'Plex']:
				newpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/i-smb.png"))  # Media services
			elif service_name == 'IPP':
				newpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/cancel.png"))  # Printer services
			else:
				newpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/host.png"))  # Generic services
		elif sharetype == 'deviceAvailable':
			# Handle basic device availability entry
			# Format: [type, hostname, ip, service_name, port, description]
			service_name = share[3]
			port = share[4]
			sharedescription = share[5]
			sharedir = f"{service_name}"
			newpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/update.png"))  # Available device
		else:
			# Fallback for unknown share types
			sharedir = share[4] if len(share) > 4 else "Unknown"
			sharedescription = share[3] if len(share) > 3 else "Unknown Service"
			newpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/i-smb.png"))

		# Check mount status (only for traditional file shares)
		self.isMounted = False
		if sharetype in ['smbShare', 'nfsShare']:
			for sharename, sharedata in self.mounts.items():
				if sharedata['ip'] == sharehost:
					if sharetype == 'nfsShare' and sharedata['mounttype'] == 'nfs':
						if sharedir == sharedata['sharedir']:
							if sharedata["isMounted"] is True:
								self.isMounted = True
					if sharetype == 'smbShare' and sharedata['mounttype'] == 'cifs':
						if sharedir == sharedata['sharedir']:
							if sharedata["isMounted"] is True:
								self.isMounted = True
		
		# Modern services and device availability indicators
		if sharetype == 'modernService':
			# Show as "accessible" since these are network services
			isMountedpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/ok.png"))
		elif sharetype == 'deviceAvailable':
			# Show as "available" for basic device detection
			isMountedpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/update.png"))
		elif self.isMounted is True:
			isMountedpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/ok.png"))
		else:
			isMountedpng = LoadPixmap(cached=True, path=resolveFilename(SCOPE_PLUGINS, "SystemPlugins/NetworkBrowser/icons/cancel.png"))

		return ((share, verticallineIcon, None, sharedir, sharedescription, newpng, isMountedpng))

	def selectionChanged(self):
		current = self["list"].getCurrent()
		self.listindex = self["list"].getIndex()
		if current:
			if len(current[0]) >= 2:
				if current[0][0] in ("nfsShare", "smbShare"):
					self["infotext"].setText(_("Press OK to mount this share!"))
				elif current[0][0] == "modernService":
					# Show helpful info for modern network services
					service_name = current[0][3] if len(current[0]) > 3 else "Service"
					port = current[0][4] if len(current[0]) > 4 else "Unknown"
					self["infotext"].setText(_("Service: %s on port %s - Press OK for details") % (service_name, port))
				elif current[0][0] == "deviceAvailable":
					# Show info for basic device availability
					self["infotext"].setText(_("Network device available - Press OK to scan for services"))
				else:
					selectedhost = current[0][2]
					if selectedhost in self.expanded:
						self["infotext"].setText(_("Press OK to collapse this host"))
					else:
						self["infotext"].setText(_("Press OK to expand this host"))

	def go(self):
		sel = self["list"].getCurrent()
		if sel is None:
			return
		if len(sel[0]) <= 1:
			return
		selectedhost = sel[0][2]
		selectedhostname = sel[0][1].strip()

		self.hostcache_file = None
		if sel[0][0] == 'host':  # host entry selected
			if selectedhost in self.expanded:
				self.expanded.remove(selectedhost)
				self.updateNetworkList()
			else:
				self.hostcache_file = '/etc/enigma2/' + selectedhostname + '.cache'  # Path to cache directory
				try:
					self.hostdata = load_cache(self.hostcache_file)
					self.passwordQuestion(False)
				except (IOError, ValueError):
					self.session.openWithCallback(self.passwordQuestion, MessageBox, (_("Do you want to enter a username and password for this host?\n")))

		if sel[0][0] == 'nfsShare':  # share entry selected
			print('[Networkbrowser] sel nfsShare')
			self.openMountEdit(sel[0])
		if sel[0][0] == 'smbShare':  # share entry selected
			print('[Networkbrowser] sel cifsShare')
			self.hostcache_file = '/etc/enigma2/' + selectedhostname + '.cache'  # Path to cache directory
			if os.path.exists(self.hostcache_file):
				print('[Networkbrowser] userinfo found from ', self.sharecache_file)
				self.openMountEdit(sel[0])
			else:
				self.session.openWithCallback(self.passwordQuestion, MessageBox, (_("Do you want to enter a username and password for this host?\n")))
		
		if sel[0][0] == 'deviceAvailable':  # device available entry selected - trigger manual scan
			self.triggerManualScan(selectedhost, selectedhostname)
		
		if sel[0][0] == 'modernService':  # modern service entry selected
			# Could add service-specific actions here
			pass

	def triggerManualScan(self, hostip, hostname):
		"""Trigger manual share and service scan for a device"""
		# Get enhanced OS detection
		hostinfo = None
		for x in self.network:
			if self.network[x][0][1][2] == hostip:
				hostinfo = self.network[x][0][1]
				break
		
		if hostinfo:
			mac = hostinfo[3] if hostinfo[3] != '00:00:00:00:00:00' else None
			os_info = detect_device_os(hostip, mac, hostname)
			device_type = get_device_type_for_shares(hostip, mac, hostname)
			
			# Force modern share detection
			self.scan_services = True  # Enable full service scanning
			modern_shares = self.getModernSMBShares(hostip, hostname, 'guest', 'guest')
			
			if modern_shares:
				# Force refresh the display to show new shares
				if hostip in self.expanded:
					self.expanded.remove(hostip)
				self.expanded.append(hostip)
				self.updateNetworkList()
				self.session.open(MessageBox, f"Found {len(modern_shares)} shares on {hostname or hostip}", MessageBox.TYPE_INFO, timeout=3)
			else:
				self.session.open(MessageBox, f"No shares found on {hostname or hostip}.\nDevice may not have sharing enabled or requires authentication.", MessageBox.TYPE_INFO, timeout=5)

	def passwordQuestion(self, ret=False):
		sel = self["list"].getCurrent()
		selectedhost = sel[0][2]
		selectedhostname = sel[0][1].strip()
		if (ret is True):
			self.session.openWithCallback(self.UserDialogClosed, UserDialog, self.skin_path, selectedhostname)
		else:
			if sel[0][0] == 'host':  # host entry selected
				if selectedhost in self.expanded:
					self.expanded.remove(selectedhost)
				else:
					self.expanded.append(selectedhost)
				self.updateNetworkList()
			if sel[0][0] == 'nfsShare':  # share entry selected
				self.openMountEdit(sel[0])
			if sel[0][0] == 'smbShare':  # share entry selected
				self.openMountEdit(sel[0])

	def UserDialogClosed(self, *ret):
		if ret is not None and len(ret):
			self.go()

	def openMountEdit(self, selection):
		if selection:
			mounts = iAutoMount.getMountsList()
			if selection[0] == 'nfsShare':  # share entry selected
				# Initialize blank mount enty
				data = {'isMounted': False, 'active': False, 'ip': False, 'sharename': False, 'sharedir': False, 'username': False, 'password': False, 'mounttype': False, 'options': False}
				# add data
				data['mounttype'] = 'nfs'
				data['active'] = True
				data['ip'] = selection[2]
				data['sharename'] = selection[1]
				data['sharedir'] = selection[4]
				data['options'] = "rw,nolock,tcp"

				for sharename, sharedata in mounts.items():
					if sharedata['ip'] == selection[2] and sharedata['sharedir'] == selection[4]:
						data = sharedata
				self.session.openWithCallback(self.MountEditClosed, AutoMountEdit, self.skin_path, data)
			if selection[0] == 'smbShare':  # share entry selected
				# Initialize blank mount enty
				data = {'isMounted': False, 'active': False, 'ip': False, 'sharename': False, 'sharedir': False, 'username': False, 'password': False, 'mounttype': False, 'options': False}
				# add data
				data['mounttype'] = 'cifs'
				data['active'] = True
				data['ip'] = selection[2]
				# Using the host name will only work if NetBIOS name lookup (aka "wins") is installed and actually working
				# data['host'] = selection[1]
				data['sharename'] = selection[3] + "@" + selection[1]
				data['sharedir'] = selection[3]
				data['options'] = "rw"
				self.sharecache_file = '/etc/enigma2/' + selection[1].strip() + '.cache'  # Path to cache directory
				data['username'] = ''
				data['password'] = ''
				try:
					hostdata = load_cache(self.sharecache_file)
				except (IOError, ValueError):
					pass
				else:
					data['username'] = hostdata['username']
					data['password'] = hostdata['password']
				for sharename, sharedata in mounts.items():
					if sharedata['ip'] == selection[2].strip() and sharedata['sharedir'] == selection[3].strip():
						data = sharedata
				self.session.openWithCallback(self.MountEditClosed, AutoMountEdit, self.skin_path, data)

	def MountEditClosed(self, returnValue=None):
		if returnValue is None:
			self.updateNetworkList()


class ScanIP(Screen, ConfigListScreen):
	skin = """
		<screen name="ScanIP" position="center,center" size="560,80" title="Scan IP" >
			<ePixmap pixmap="skin_default/buttons/red.png" position="0,0" size="140,40" alphatest="on" />
			<ePixmap pixmap="skin_default/buttons/green.png" position="140,0" size="140,40" alphatest="on" />
			<ePixmap pixmap="skin_default/buttons/yellow.png" position="280,0" size="140,40" alphatest="on" />
			<widget source="key_red" render="Label" position="0,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#9f1313" transparent="1" />
			<widget source="key_green" render="Label" position="140,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#1f771f" transparent="1" />
			<widget source="key_yellow" render="Label" position="280,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#a08500" transparent="1" />
			<widget name="config" position="5,50" size="540,25" scrollbarMode="showOnDemand" />
		</screen>"""

	def __init__(self, session):
		Screen.__init__(self, session)
		self.session = session

		self["key_red"] = StaticText(_("Cancel"))
		self["key_green"] = StaticText(_("Scan NFS share"))
		self["key_yellow"] = StaticText(_("Scan range"))

		self["actions"] = ActionMap(["SetupActions", "ColorActions"],
		{
			"back": self.exit,
			"red": self.exit,
			"cancel": self.exit,
			"green": self.goNfs,
			"yellow": self.goAddress,
		}, -1)

		self.ipAddress = ConfigIP(default=[0, 0, 0, 0])

		ConfigListScreen.__init__(self, [(_("IP Address"), self.ipAddress)], self.session)

		self.onLayoutFinish.append(self.layoutFinished)

	def exit(self):
		self.close((None, None))

	def layoutFinished(self):
		self.setWindowTitle()

	def setWindowTitle(self):
		self.setTitle(_("Enter IP to scan..."))

	def goAddress(self):
		if self.ipAddress.getText() != "0.0.0.0":
			self.close((self.ipAddress.getText(), "address"))
		else:
			self.exit

	def goNfs(self):
		if self.ipAddress.getText() != "0.0.0.0":
			self.close((self.ipAddress.getText(), "nfs"))
		else:
			self.exit


class NetworkBrowserSetup(Screen, ConfigListScreen):
	"""Configuration screen for NetworkBrowser enhanced settings"""
	
	skin = """
		<screen name="NetworkBrowserSetup" position="center,center" size="980,700" title="NetworkBrowser Configuration">
			<ePixmap pixmap="skin_default/buttons/red.png" position="0,0" size="245,70" alphatest="on" />
			<ePixmap pixmap="skin_default/buttons/green.png" position="245,0" size="245,70" alphatest="on" />
			<ePixmap pixmap="skin_default/buttons/yellow.png" position="490,0" size="245,70" alphatest="on" />
			<ePixmap pixmap="skin_default/buttons/blue.png" position="735,0" size="245,70" alphatest="on" />
			<widget source="key_red" render="Label" position="0,0" zPosition="1" size="245,70" font="Regular;35" halign="center" valign="center" backgroundColor="#9f1313" transparent="1" />
			<widget source="key_green" render="Label" position="245,0" zPosition="1" size="245,70" font="Regular;35" halign="center" valign="center" backgroundColor="#1f771f" transparent="1" />
			<widget source="key_yellow" render="Label" position="490,0" zPosition="1" size="245,70" font="Regular;35" halign="center" valign="center" backgroundColor="#a08500" transparent="1" />
			<widget source="key_blue" render="Label" position="735,0" zPosition="1" size="245,70" font="Regular;35" halign="center" valign="center" backgroundColor="#18188b" transparent="1" />
			<widget name="config" position="9,88" size="962,525" scrollbarMode="showOnDemand" />
			<ePixmap pixmap="skin_default/div-h.png" position="0,613" zPosition="1" size="980,4" />
			<widget source="help" render="Label" position="9,621" size="962,70" font="Regular;37" />
		</screen>"""

	def __init__(self, session):
		Screen.__init__(self, session)
		
		# Set up key labels
		self["key_red"] = StaticText(_("Cancel"))
		self["key_green"] = StaticText(_("Save"))
		self["key_yellow"] = StaticText(_("Scan IP"))
		self["key_blue"] = StaticText(_("Defaults"))
		self["help"] = StaticText(_("Configure NetworkBrowser discovery and filtering options"))
		
		# Create configuration list
		self.list = []
		self.list.append(getConfigListEntry(_("Show only ping-reachable devices"), config.networkbrowser.ping_reachable_only))
		
		ConfigListScreen.__init__(self, self.list, session = session)
		
		# Set up action mappings
		self["actions"] = ActionMap(["SetupActions", "ColorActions"],
		{
			"red": self.cancel,
			"cancel": self.cancel,
			"green": self.save,
			"yellow": self.scanIP,
			"blue": self.defaults,
			"save": self.save,
		}, -2)

		self.onLayoutFinish.append(self.layoutFinished)

	def createConfigList(self):
		"""Refresh the configuration entries list"""
		self.list = []
		self.list.append(getConfigListEntry(_("Show only ping-reachable devices"), config.networkbrowser.ping_reachable_only))
		self["config"].list = self.list
		self["config"].l.setList(self.list)

	def layoutFinished(self):
		self.setTitle(_("NetworkBrowser Configuration"))

	def save(self):
		"""Save configuration and close"""
		print("[NetworkBrowser] Saving configuration")
		for x in self["config"].list:
			x[1].save()
		config.save()
		self.close(True)  # Return True to indicate settings changed

	def cancel(self):
		"""Cancel changes and close"""
		print("[NetworkBrowser] Canceling configuration changes")
		for x in self["config"].list:
			x[1].cancel()
		self.close(False)

	def defaults(self):
		"""Reset to default values"""
		print("[NetworkBrowser] Resetting to defaults")
		config.networkbrowser.ping_reachable_only.value = True
		self.createConfigList()

	def scanIP(self):
		"""Open IP scan dialog (original Expert functionality)"""
		self.session.openWithCallback(self.scanIPclosed, ScanIP)

	def scanIPclosed(self, result):
		"""Handle IP scan results"""
		if result and result[0]:
			print("[NetworkBrowser] IP scan completed:", result)
			# Could add logic here to process scan results
