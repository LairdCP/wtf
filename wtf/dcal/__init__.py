import dcal_py

class SessionError(Exception):
	"""
	Exception raised when a comm fails to send a command.
	"""
	pass

class CommandError(Exception):
	"""
	Exception raised when a command returns a fail code.
	"""
	pass

class Dcal():
	"""
	communicate with a wb via the DCAL

	"""
	#######################################################################
	# Session Management
	def __init__(self, ip, port=2222, user="libssh", passwd="libssh"):
		self.d = dcal_py.dcal()
		self.ip = ip
		self.port = port
		self.user = user
		self.passwd = passwd
		self.is_open = False

	def open(self):
		if self.d.session_create() != 0:
			raise SessionError("Unable to create session")
		self.d.host(self.ip)
		self.d.port(self.port)
		self.d.user(self.user)
		self.d.pw(self.passwd)
		if self.d.session_open() != 0:
			raise SessionError("Unable to open session")
		self.is_open = True

	def close(self):
		if self.is_open:
			if self.d.session_close() != 0:
				raise SessionError("Error when closing session")
		# if the session is closed, then it's a don't-care.
		self.is_open = False
	#######################################################################
	# Device Information and Status
	def sdk_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		sdk_version = dcal_py.sdk_version()
		ret = self.d.get_sdk_version( sdk_version )
		if ret != 0:
			raise CommandError("Error when doing get_sdk_version: " + ret)
		sdk_dict = {
			'sdk': sdk_version.sdk,
		}
		return sdk_dict

	def chipset_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		chipset_version = dcal_py.chipset_version()
		ret = self.d.get_chipset_version( chipset_version )
		if ret != 0:
			raise CommandError("Error when doing get_chipset_version: " + ret)
		chipset_dict = {
			'chipset': chipset_version.chipset,
		}
		return chipset_dict

	def system_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		system_version = dcal_py.system_version()
		ret = self.d.get_system_version( system_version )
		if ret != 0:
			raise CommandError("Error when doing get_system_version: " + ret)
		system_dict = {
			'sys': system_version.sys,
		}
		return system_dict

	def driver_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		driver_version = dcal_py.driver_version()
		ret = self.d.get_driver_version( driver_version )
		if ret != 0:
			raise CommandError("Error when doing get_driver_version: " + ret)
		driver_dict = {
			'driver': driver_version.driver,
		}
		return driver_dict

	def dcas_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		dcas_version = dcal_py.dcas_version()
		ret = self.d.get_dcas_version( dcas_version )
		if ret != 0:
			raise CommandError("Error when doing get_dcas_version: " + ret)
		dcas_dict = {
			'dcas': dcas_version.dcas,
		}
		return dcas_dict

	def dcal_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		dcal_version = dcal_py.dcal_version()
		ret = self.d.get_dcal_version( dcal_version )
		if ret != 0:
			raise CommandError("Error when doing get_dcal_version: " + ret)
		dcal_dict = {
			'dcal': dcal_version.dcal,
		}
		return dcal_dict

	def firmware_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		firmware_version = dcal_py.firmware_version()
		ret = self.d.get_firmware_version( firmware_version )
		if ret != 0:
			raise CommandError("Error when doing get_firmware_version: " + ret)
		firmware_dict = {
			'firmware': firmware_version.firmware(),
		}
		return firmware_dict

	def supplicant_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		supplicant_version = dcal_py.supplicant_version()
		ret = self.d.get_supplicant_version( supplicant_version )
		if ret != 0:
			raise CommandError("Error when doing get_supplicant_version: " + ret)
		supplicant_dict = {
			'supplicant': supplicant_version.supplicant(),
		}
		return supplicant_dict

	def release_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		release_version = dcal_py.release_version()
		ret = self.d.get_release_version( release_version )
		if ret != 0:
			raise CommandError("Error when doing get_release_version: " + ret)
		release_dict = {
			'release': release_version.release(),
		}
		return release_dict

	def status_pull(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.device_status_pull()
		if ret != 0:
			raise CommandError("Error when doing device_status_pull: " + ret)

	def status_get_settings(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		wb_settings = dcal_py.settings()
		ret = self.d.device_status_get_settings( wb_settings )
		if ret != 0:
			raise CommandError("Error when processing settings: " + ret)
		set_dict = {
			'profilename': wb_settings.profilename(),
			'ssid': wb_settings.ssid(),
			'ssid_len': wb_settings.ssid_len,
			'mac': wb_settings.mac(),
		}
		return set_dict

	def status_get_ccx(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		wb_ccx = dcal_py.ccx()
		ret = self.d.device_status_get_ccx( wb_ccx )
		if ret != 0:
			raise CommandError("Error when processing ccx: " + ret)
		ccx_dict = {
			'ap_ip': wb_ccx.ap_ip(),
			'ap_name': wb_ccx.ap_name(),
			'clientname': wb_ccx.clientname(),
		}
		return ccx_dict

	def status_get_tcp(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		wb_tcp = dcal_py.tcp()
		ret = self.d.device_status_get_tcp( wb_tcp )
		if ret != 0:
			raise CommandError("Error when processing tcp: " + ret)
		tcp_dict = {
			'ipv4': wb_tcp.ipv4(),
			'ipv6': wb_tcp.ipv6(),
		}
		return tcp_dict

	def status_get_connection(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		wb_connection = dcal_py.connection()
		ret = self.d.device_status_get_connection( wb_connection )
		if ret != 0:
			raise CommandError("Error when processing connection: " + ret)
		con_dict = {
			'cardstate': wb_connection.cardstate,
			'channel': wb_connection.channel,
			'rssi': wb_connection.rssi,
			'ap_mac': wb_connection.ap_mac(),
		}
		return con_dict

	def status_get_connection_extended(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		wb_connection_extended = dcal_py.connection_extended()
		ret = self.d.device_status_get_connection_extended( wb_connection_extended )
		if ret != 0:
			raise CommandError("Error when processing connection extended: " + ret)
		con_ext_dict = {
			'bitrate': wb_connection_extended.bitrate,
			'txpower': wb_connection_extended.txpower,
			'dtim': wb_connection_extended.dtim,
			'beaconperiod': wb_connection_extended.beaconperiod
		}
		return con_ext_dict

	#######################################################################
	# WiFi Profile Management
	def wifi_profile_activate_by_name(self, name):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_activate_by_name(name)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_activate_by_name: " + ret)
