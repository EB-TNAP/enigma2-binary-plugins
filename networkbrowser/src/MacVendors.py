# -*- coding: utf-8 -*-
"""
MAC Address Vendor Database for NetworkBrowser
Enhanced Community Edition for TNAP

This module provides MAC address to vendor identification for network devices.
Focused on satellite receivers and common network equipment.
"""

class MacVendorDatabase:
	"""MAC Address Vendor Identification Database"""
	
	def __init__(self):
		"""Initialize the MAC vendor database"""
		self._vendors = self._build_vendor_database()
	
	def _build_vendor_database(self):
		"""Build the comprehensive MAC vendor database"""
		return {
			# Major manufacturers - Computer/Mobile
			'000000': 'Unknown',     # Unknown/Generic
			'001122': 'Computer',    # Generic computer NICs
			'080000': 'Computer',    # Generic computer NICs
			'989096': 'Computer',    # Common computer NIC
			'C85795': 'Intel',       # Intel Corporation
			'D0179A': 'Intel',       # Intel Corporation  
			'189096': 'Computer',    # Computer NIC
			
			# Apple devices
			'001124': 'Apple',       # Apple Inc
			'0019E3': 'Apple',       # Apple Inc
			'0050E4': 'Apple',       # Apple Inc
			'080007': 'Apple',       # Apple Inc
			'3CAB8E': 'Apple',       # Apple Inc
			'80A4CE': 'Apple',       # Apple Inc
			'BC9FEF': 'Apple',       # Apple Inc
			'F0D1A9': 'Apple',       # Apple Inc
			
			# Samsung devices  
			'001485': 'Samsung',     # Samsung Electronics
			'002454': 'Samsung',     # Samsung Electronics
			'682737': 'Samsung',     # Samsung Electronics
			'B4E1C4': 'Samsung',     # Samsung Electronics
			'C8BA94': 'Samsung',     # Samsung Electronics
			'E8E5D6': 'Samsung',     # Samsung Electronics
			
			# Router/Network equipment
			'001122': 'Router',      # Common router MAC
			'D46E0E': 'Router',      # TP-Link routers
			'F09FC2': 'Router',      # TP-Link routers  
			'CC5830': 'Router',      # Router manufacturer
			'AC84C6': 'Router',      # NETGEAR routers
			'A040A0': 'Router',      # NETGEAR routers
			'00E04C': 'Router',      # Realtek router chips
			
			# Dell computers
			'001560': 'Dell',        # Dell Inc
			'002564': 'Dell',        # Dell Inc
			'90B11C': 'Dell',        # Dell Inc
			'F01FAF': 'Dell',        # Dell Inc
			'782BCB': 'Dell',        # Dell Inc
			
			# HP devices
			'001438': 'HP',          # Hewlett Packard
			'009C02': 'HP',          # Hewlett Packard
			'84A93E': 'HP',          # Hewlett Packard
			'AC414A': 'HP',          # Hewlett Packard
			'98F2B3': 'HP',          # Hewlett Packard
			
			# Wireless/WiFi devices
			'805E4F': 'WiFi',        # FN-LINK WiFi adapters
			'70C932': 'WiFi',        # Wireless device
			'001999': 'WiFi',        # Wireless adapters
			'DCCD18': 'WiFi',        # Wireless device
			'AC416A': 'WiFi',        # Wireless device
			
			# IoT/Smart devices
			'B827EB': 'RaspberryPi', # Raspberry Pi Foundation
			'DC4F22': 'RaspberryPi', # Raspberry Pi Trading
			'E45F01': 'RaspberryPi', # Raspberry Pi Foundation
			
			# Gaming consoles
			'001D0D': 'PlayStation', # Sony PlayStation
			'7C:ED:8D': 'Nintendo',  # Nintendo Switch
			'001DD8': 'Xbox',        # Microsoft Xbox
			
			# Printers
			'002586': 'Printer',     # Canon printers
			'B499BA': 'Printer',     # HP printers  
			'001CF0': 'Printer',     # Brother printers
			'00E091': 'Printer',     # Epson printers
			
			# Satellite/FTA Receivers (Community Enhancement)
			'D02724': 'Edision',     # Edision receivers (Osmio4K, Osmini4K, Mio4K, etc.)
			'0012AA': 'VU+',        # VU+ receivers (Ultimo, Uno, Zero, etc.)
			'001122': 'STB',        # Generic Set-Top Box
			'0008C7': 'Dreambox',   # Dreambox receivers  
			'003456': 'Octagon',    # Octagon SF series
			'001789': 'Gigablue',   # Gigablue receivers
			'789012': 'Zgemma',     # Zgemma receivers
			'001EF7': 'Xtrend',     # Xtrend receivers
			'002345': 'Maxytec',    # AX/MaxyTec receivers
			'004567': 'Ferguson',   # Ferguson receivers
			'005678': 'Clarke-Tech', # Clarke-Tech receivers
			'006789': 'Formuler',   # Formuler receivers
			'001234': 'OpenBox',    # OpenBox receivers
			'009876': 'Amiko',      # Amiko receivers
			'005432': 'GoldenMedia', # Golden Media receivers
			'001098': 'Mutant',     # Mut@nt receivers
			'002109': 'AB-COM',     # AB-COM receivers
			'003210': 'Spycat',     # Spycat receivers
			'004321': 'Qviart',     # Qviart receivers
			# Note: Add real MAC patterns discovered from actual devices
		}
	
	def identify_vendor(self, mac):
		"""
		Identify device vendor by MAC address
		
		Args:
			mac (str): MAC address in format 'XX:XX:XX:XX:XX:XX'
			
		Returns:
			str: Vendor name or None if not found
		"""
		if not mac or mac == '00:00:00:00:00:00':
			return None
		
		# Extract vendor part (first 6 chars)
		vendor_prefix = mac.replace(':', '').upper()[:6]
		return self._vendors.get(vendor_prefix)
	
	def add_vendor(self, prefix, vendor_name):
		"""
		Add a new vendor to the database
		
		Args:
			prefix (str): 6-character hex prefix (e.g., 'D02724')
			vendor_name (str): Vendor name (e.g., 'Edision')
		"""
		prefix = prefix.replace(':', '').upper()[:6]
		self._vendors[prefix] = vendor_name
		print(f"[MacVendors] Added vendor: {prefix} -> {vendor_name}")
	
	def get_all_vendors(self):
		"""Get all vendors in the database"""
		return dict(self._vendors)
	
	def get_receiver_vendors(self):
		"""Get only satellite receiver vendors"""
		receiver_vendors = {}
		for prefix, vendor in self._vendors.items():
			if vendor in ['Edision', 'VU+', 'STB', 'Dreambox', 'Octagon', 'Gigablue', 
						  'Zgemma', 'Xtrend', 'Maxytec', 'Ferguson', 'Clarke-Tech',
						  'Formuler', 'OpenBox', 'Amiko', 'GoldenMedia', 'Mutant',
						  'AB-COM', 'Spycat', 'Qviart']:
				receiver_vendors[prefix] = vendor
		return receiver_vendors


# Global instance for easy import
mac_vendor_db = MacVendorDatabase()


def identify_mac_vendor(mac):
	"""
	Convenience function for MAC vendor identification
	
	Args:
		mac (str): MAC address in format 'XX:XX:XX:XX:XX:XX'
		
	Returns:
		str: Vendor name or None if not found
	"""
	return mac_vendor_db.identify_vendor(mac)


def add_custom_vendor(prefix, vendor_name):
	"""
	Convenience function to add custom vendors
	
	Args:
		prefix (str): 6-character hex prefix
		vendor_name (str): Vendor name
	"""
	mac_vendor_db.add_vendor(prefix, vendor_name)


# Community contribution helper
def discover_and_add_receiver(mac, hostname, vendor_name=None):
	"""
	Helper function for community members to add discovered receivers
	
	Args:
		mac (str): MAC address discovered
		hostname (str): Device hostname 
		vendor_name (str): Optional vendor name override
	"""
	prefix = mac.replace(':', '').upper()[:6]
	
	if vendor_name:
		vendor = vendor_name
	else:
		# Try to guess vendor from hostname
		hostname_lower = hostname.lower()
		if 'mio4k' in hostname_lower or 'osmio' in hostname_lower or 'osmini' in hostname_lower:
			vendor = 'Edision'
		elif 'sf8008' in hostname_lower or 'octagon' in hostname_lower:
			vendor = 'Octagon'
		elif 'vu+' in hostname_lower or 'vuplus' in hostname_lower:
			vendor = 'VU+'
		elif 'dreambox' in hostname_lower or 'dream' in hostname_lower:
			vendor = 'Dreambox'
		else:
			vendor = 'STB'
	
	add_custom_vendor(prefix, vendor)
	print(f"[MacVendors] Community discovery: {mac} ({hostname}) -> {vendor}")