# -*- coding: utf-8 -*-
"""
Operating System Detection for NetworkBrowser
Enhanced Community Edition for TNAP

This module provides comprehensive OS detection for network devices using
multiple detection methods including fingerprinting, service detection,
hostname patterns, and MAC address analysis.
"""

import subprocess
import socket
import time
from .MacVendors import identify_mac_vendor

class OSDetector:
	"""Advanced Operating System Detection for Network Devices"""
	
	def __init__(self):
		"""Initialize the OS detector"""
		self.os_cache = {}  # Cache results for performance
		self.cache_ttl = 300  # 5 minutes cache
	
	def detect_os(self, ip, mac=None, hostname=None):
		"""
		Comprehensive OS detection using multiple methods
		
		Args:
			ip (str): IP address of the device
			mac (str): MAC address (optional)
			hostname (str): Hostname (optional)
			
		Returns:
			dict: {
				'os_type': 'windows|macos|linux|unix|android|ios|unknown',
				'os_version': 'version string or None',
				'confidence': 0-100,
				'detection_method': 'method used',
				'device_class': 'desktop|mobile|server|iot|router|printer|stb'
			}
		"""
		cache_key = f"{ip}_{mac}_{hostname}"
		
		# Check cache first
		if cache_key in self.os_cache:
			cached_time, result = self.os_cache[cache_key]
			if time.time() - cached_time < self.cache_ttl:
				return result
		
		print(f"[OSDetection] Detecting OS for {ip} (MAC: {mac}, Hostname: {hostname})")
		
		# Initialize result
		result = {
			'os_type': 'unknown',
			'os_version': None,
			'confidence': 0,
			'detection_method': 'none',
			'device_class': 'unknown'
		}
		
		# Method 1: Hostname-based detection (fastest, most reliable)
		hostname_result = self._detect_by_hostname(hostname)
		if hostname_result['confidence'] > result['confidence']:
			result = hostname_result
		
		# Method 2: MAC address vendor detection
		mac_result = self._detect_by_mac_vendor(mac)
		if mac_result['confidence'] > result['confidence']:
			result = mac_result
		
		# Method 3: Service fingerprinting
		service_result = self._detect_by_services(ip)
		if service_result['confidence'] > result['confidence']:
			result = service_result
		
		# Method 4: Network fingerprinting (TTL, TCP options)
		network_result = self._detect_by_network_fingerprint(ip)
		if network_result['confidence'] > result['confidence']:
			result = network_result
		
		# Method 5: SMB/NetBIOS detection for Windows
		if result['os_type'] == 'unknown' or result['confidence'] < 70:
			smb_result = self._detect_by_smb(ip)
			if smb_result['confidence'] > result['confidence']:
				result = smb_result
		
		# Cache the result
		self.os_cache[cache_key] = (time.time(), result)
		
		print(f"[OSDetection] Result for {ip}: {result['os_type']} ({result['confidence']}% via {result['detection_method']})")
		return result
	
	def _detect_by_hostname(self, hostname):
		"""Detect OS by hostname patterns"""
		if not hostname:
			return {'os_type': 'unknown', 'confidence': 0, 'detection_method': 'hostname', 'device_class': 'unknown', 'os_version': None}
		
		hostname_lower = hostname.lower()
		
		# Windows patterns
		if any(pattern in hostname_lower for pattern in ['desktop-', 'laptop-', 'pc-', '-pc', 'win10-', 'win11-', 'windows']):
			return {'os_type': 'windows', 'confidence': 85, 'detection_method': 'hostname', 'device_class': 'desktop', 'os_version': None}
		
		# Mac patterns
		if any(pattern in hostname_lower for pattern in ['macbook', 'imac', 'mac-', 'apple-', 'iphone', 'ipad']):
			device_class = 'mobile' if any(x in hostname_lower for x in ['iphone', 'ipad']) else 'desktop'
			os_type = 'ios' if device_class == 'mobile' else 'macos'
			return {'os_type': os_type, 'confidence': 90, 'detection_method': 'hostname', 'device_class': device_class, 'os_version': None}
		
		# Linux/Unix patterns
		if any(pattern in hostname_lower for pattern in ['ubuntu', 'debian', 'fedora', 'centos', 'redhat', 'linux', 'unix']):
			return {'os_type': 'linux', 'confidence': 85, 'detection_method': 'hostname', 'device_class': 'desktop', 'os_version': None}
		
		# Android patterns
		if any(pattern in hostname_lower for pattern in ['android', 'samsung', 'pixel', 'lg-', 'htc-']):
			return {'os_type': 'android', 'confidence': 80, 'detection_method': 'hostname', 'device_class': 'mobile', 'os_version': None}
		
		# Satellite receiver patterns
		if any(pattern in hostname_lower for pattern in ['dreambox', 'vu+', 'edision', 'gigablue', 'zgemma', 'sf8008', 'osmio', 'receiver', 'stb']):
			return {'os_type': 'linux', 'confidence': 90, 'detection_method': 'hostname', 'device_class': 'stb', 'os_version': 'enigma2'}
		
		# Router patterns
		if any(pattern in hostname_lower for pattern in ['router', 'gateway', 'openwrt', 'dd-wrt', 'tomato']):
			return {'os_type': 'linux', 'confidence': 85, 'detection_method': 'hostname', 'device_class': 'router', 'os_version': None}
		
		return {'os_type': 'unknown', 'confidence': 0, 'detection_method': 'hostname', 'device_class': 'unknown', 'os_version': None}
	
	def _detect_by_mac_vendor(self, mac):
		"""Detect OS by MAC address vendor"""
		if not mac:
			return {'os_type': 'unknown', 'confidence': 0, 'detection_method': 'mac', 'device_class': 'unknown', 'os_version': None}
		
		vendor = identify_mac_vendor(mac)
		if not vendor:
			return {'os_type': 'unknown', 'confidence': 0, 'detection_method': 'mac', 'device_class': 'unknown', 'os_version': None}
		
		vendor_lower = vendor.lower()
		
		# Apple devices
		if vendor_lower == 'apple':
			return {'os_type': 'macos', 'confidence': 75, 'detection_method': 'mac', 'device_class': 'desktop', 'os_version': None}
		
		# Microsoft devices (Surface, Xbox)
		if vendor_lower in ['microsoft', 'xbox']:
			os_type = 'xbox' if vendor_lower == 'xbox' else 'windows'
			return {'os_type': os_type, 'confidence': 80, 'detection_method': 'mac', 'device_class': 'desktop', 'os_version': None}
		
		# Satellite receivers
		if vendor_lower in ['edision', 'vu+', 'dreambox', 'octagon', 'gigablue', 'zgemma', 'stb']:
			return {'os_type': 'linux', 'confidence': 85, 'detection_method': 'mac', 'device_class': 'stb', 'os_version': 'enigma2'}
		
		# Android devices
		if vendor_lower in ['samsung', 'lg', 'htc', 'google']:
			return {'os_type': 'android', 'confidence': 70, 'detection_method': 'mac', 'device_class': 'mobile', 'os_version': None}
		
		# Gaming consoles
		if vendor_lower in ['nintendo', 'playstation', 'sony']:
			return {'os_type': 'gaming', 'confidence': 90, 'detection_method': 'mac', 'device_class': 'gaming', 'os_version': None}
		
		# IoT devices
		if vendor_lower in ['raspberrypi']:
			return {'os_type': 'linux', 'confidence': 85, 'detection_method': 'mac', 'device_class': 'iot', 'os_version': 'raspbian'}
		
		# Default based on common vendors
		if vendor_lower in ['intel', 'dell', 'hp']:
			return {'os_type': 'windows', 'confidence': 60, 'detection_method': 'mac', 'device_class': 'desktop', 'os_version': None}
		
		return {'os_type': 'unknown', 'confidence': 0, 'detection_method': 'mac', 'device_class': 'unknown', 'os_version': None}
	
	def _detect_by_services(self, ip):
		"""Detect OS by running services"""
		try:
			services = self._quick_port_scan(ip)
			
			# Enhanced multi-OS detection logic for public enigma2 image
			has_ssh = 22 in services
			has_smb = any(port in services for port in [139, 445])
			has_rpc_endpoint = 135 in services  # Windows RPC endpoint mapper
			has_rdp = 3389 in services
			has_nfs = any(port in services for port in [111, 2049])
			has_afp = 548 in services  # Apple Filing Protocol
			has_bonjour = 5353 in services  # Apple Bonjour
			has_web = any(port in services for port in [80, 443, 8080])
			
			print(f"[OSDetection] Service analysis for {ip}: SSH={has_ssh}, SMB={has_smb}, RPC={has_rpc_endpoint}, RDP={has_rdp}, NFS={has_nfs}, AFP={has_afp}")
			
			# Windows detection - RPC endpoint mapper is Windows-specific
			if has_rpc_endpoint or has_rdp:
				confidence = 85 if has_rdp else 80
				return {'os_type': 'windows', 'confidence': confidence, 'detection_method': 'services', 'device_class': 'desktop', 'os_version': None}
			
			# Mac detection - AFP or Bonjour are strong Mac indicators
			if has_afp or has_bonjour:
				confidence = 85 if has_afp else 75
				return {'os_type': 'macos', 'confidence': confidence, 'detection_method': 'services', 'device_class': 'desktop', 'os_version': None}
			
			# Linux/Unix detection - SSH is strong Linux indicator, especially with SMB (Samba)
			if has_ssh:
				confidence = 80 if has_smb else 75  # SSH + Samba is very likely Linux
				device_class = 'server' if has_nfs else 'desktop'
				return {'os_type': 'linux', 'confidence': confidence, 'detection_method': 'services', 'device_class': device_class, 'os_version': None}
			
			# NFS without SSH suggests Unix/Linux server
			if has_nfs:
				return {'os_type': 'linux', 'confidence': 75, 'detection_method': 'services', 'device_class': 'server', 'os_version': None}
			
			# SMB-only without Windows RPC could be modern Linux with Samba (Ubuntu 22.04 often has SSH disabled)
			if has_smb and not has_rpc_endpoint:
				return {'os_type': 'linux', 'confidence': 70, 'detection_method': 'services', 'device_class': 'desktop', 'os_version': None}
			
			# Web-based devices (routers, IoT, NAS)
			if has_web:
				return {'os_type': 'linux', 'confidence': 50, 'detection_method': 'services', 'device_class': 'router', 'os_version': None}
			
		except Exception as e:
			print(f"[OSDetection] Service scan failed for {ip}: {e}")
		
		return {'os_type': 'unknown', 'confidence': 0, 'detection_method': 'services', 'device_class': 'unknown', 'os_version': None}
	
	def _detect_by_network_fingerprint(self, ip):
		"""Detect OS by network fingerprinting (TTL analysis)"""
		try:
			# Ping to get TTL
			result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
								  capture_output=True, text=True, timeout=3)
			
			if result.returncode == 0:
				# Extract TTL from ping output
				for line in result.stdout.split('\n'):
					if 'ttl=' in line.lower():
						ttl_part = line.lower().split('ttl=')[1].split()[0]
						try:
							ttl = int(ttl_part)
							
							# TTL-based OS detection
							if ttl <= 64:
								if ttl > 60:
									return {'os_type': 'linux', 'confidence': 65, 'detection_method': 'ttl', 'device_class': 'desktop', 'os_version': None}
								else:
									return {'os_type': 'macos', 'confidence': 60, 'detection_method': 'ttl', 'device_class': 'desktop', 'os_version': None}
							elif ttl <= 128:
								return {'os_type': 'windows', 'confidence': 65, 'detection_method': 'ttl', 'device_class': 'desktop', 'os_version': None}
							else:
								return {'os_type': 'router', 'confidence': 70, 'detection_method': 'ttl', 'device_class': 'router', 'os_version': None}
						except ValueError:
							pass
		except Exception as e:
			print(f"[OSDetection] TTL detection failed for {ip}: {e}")
		
		return {'os_type': 'unknown', 'confidence': 0, 'detection_method': 'ttl', 'device_class': 'unknown', 'os_version': None}
	
	def _detect_by_smb(self, ip):
		"""Detect Windows via SMB/NetBIOS"""
		try:
			# Try nmblookup first
			result = subprocess.run(['nmblookup', '-A', ip], 
								  capture_output=True, text=True, timeout=5)
			
			if result.returncode == 0 and '<00>' in result.stdout:
				return {'os_type': 'windows', 'confidence': 80, 'detection_method': 'smb', 'device_class': 'desktop', 'os_version': None}
		
		except FileNotFoundError:
			print("[OSDetection] nmblookup not available for SMB detection")
		except Exception as e:
			print(f"[OSDetection] SMB detection failed for {ip}: {e}")
		
		return {'os_type': 'unknown', 'confidence': 0, 'detection_method': 'smb', 'device_class': 'unknown', 'os_version': None}
	
	def _quick_port_scan(self, ip):
		"""Quick scan of common ports"""
		open_ports = []
		common_ports = [22, 23, 53, 80, 111, 135, 139, 443, 445, 548, 631, 993, 995, 2049, 3389, 5009, 5353, 8080, 8443]
		
		for port in common_ports:
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(0.5)  # Very fast scan
				result = sock.connect_ex((ip, port))
				if result == 0:
					open_ports.append(port)
				sock.close()
			except:
				pass
		
		return open_ports
	
	def get_share_type_for_os(self, os_type):
		"""Get preferred share type for OS"""
		share_preferences = {
			'windows': ['smb', 'cifs'],
			'macos': ['afp', 'smb', 'nfs'],
			'linux': ['nfs', 'smb', 'ssh'],
			'unix': ['nfs', 'smb'],
			'android': ['smb', 'ftp'],
			'ios': ['smb'],
			'unknown': ['smb', 'nfs']
		}
		return share_preferences.get(os_type, ['smb', 'nfs'])


# Global instance for easy import
os_detector = OSDetector()


def detect_device_os(ip, mac=None, hostname=None):
	"""
	Convenience function for OS detection
	
	Args:
		ip (str): IP address
		mac (str): MAC address (optional)
		hostname (str): Hostname (optional)
		
	Returns:
		dict: OS detection result
	"""
	return os_detector.detect_os(ip, mac, hostname)


def get_device_type_for_shares(ip, mac=None, hostname=None):
	"""
	Get device type for share scanning compatibility
	
	Returns:
		str: 'windows', 'mac', 'linux', 'unix' for share scanning
	"""
	result = os_detector.detect_os(ip, mac, hostname)
	
	# Map to traditional share types
	os_type = result['os_type']
	if os_type in ['windows', 'xbox']:
		return 'windows'
	elif os_type in ['macos', 'ios']:
		return 'mac'
	elif os_type in ['linux', 'android']:
		return 'linux'
	else:
		return 'unix'  # Default fallback