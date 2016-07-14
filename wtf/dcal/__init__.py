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
	def version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		wb_version = dcal_py.version()
		ret = self.d.version_pull( wb_version )
		if ret != 0:
			raise CommandError("Error when doing version_pull: " + ret)
		ver_dict = {
			'sdk': wb_version.sdk,
			'chipset': wb_version.chipset,
			'sys': wb_version.sys,
			'driver': wb_version.driver,
			'dcas': wb_version.dcas,
			'dcal': wb_version.dcal,
			'firmware': wb_version.firmware(),
			'supplicant': wb_version.supplicant(),
			'release': wb_version.release()
		}
		return ver_dict

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
