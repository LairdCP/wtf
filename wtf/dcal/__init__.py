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
		sdk_version = dcal_py.generic_uint()
		ret = self.d.get_sdk_version( sdk_version )
		if ret != 0:
			raise CommandError("Error when doing get_sdk_version: ", ret)
		return sdk_version.gen_uint

	def chipset_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		chipset_version = dcal_py.generic_int()
		ret = self.d.get_chipset_version( chipset_version )
		if ret != 0:
			raise CommandError("Error when doing get_chipset_version: ", ret)
		return chipset_version.gen_int

	def system_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		system_version = dcal_py.generic_int()
		ret = self.d.get_system_version( system_version )
		if ret != 0:
			raise CommandError("Error when doing get_system_version: ", ret)
		return system_version.gen_int

	def driver_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		driver_version = dcal_py.generic_uint()
		ret = self.d.get_driver_version( driver_version )
		if ret != 0:
			raise CommandError("Error when doing get_driver_version: ", ret)
		return driver_version.gen_uint

	def dcas_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		dcas_version = dcal_py.generic_uint()
		ret = self.d.get_dcas_version( dcas_version )
		if ret != 0:
			raise CommandError("Error when doing get_dcas_version: ", ret)
		return dcas_version.gen_uint

	def dcal_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		dcal_version = dcal_py.generic_uint()
		ret = self.d.get_dcal_version( dcal_version )
		if ret != 0:
			raise CommandError("Error when doing get_dcal_version: ", ret)
		return dcal_version.gen_uint

	def firmware_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		firmware_version = dcal_py.generic_string()
		ret = self.d.get_firmware_version( firmware_version )
		if ret != 0:
			raise CommandError("Error when doing get_firmware_version: ", ret)
		return firmware_version.gen_string()

	def supplicant_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		supplicant_version = dcal_py.generic_string()
		ret = self.d.get_supplicant_version( supplicant_version )
		if ret != 0:
			raise CommandError("Error when doing get_supplicant_version: ", ret)
		return supplicant_version.gen_string()

	def release_version(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		release_version = dcal_py.generic_string()
		ret = self.d.get_release_version( release_version )
		if ret != 0:
			raise CommandError("Error when doing get_release_version: ", ret)
		return release_version.gen_string()

	def status_pull(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.device_status_pull()
		if ret != 0:
			raise CommandError("Error when doing device_status_pull: ", ret)

	def status_get_settings(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		wb_settings = dcal_py.settings()
		ret = self.d.device_status_get_settings( wb_settings )
		if ret != 0:
			raise CommandError("Error when processing settings: ", ret)
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
			raise CommandError("Error when processing ccx: ", ret)
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
			raise CommandError("Error when processing tcp: ", ret)
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
			raise CommandError("Error when processing connection: ", ret)
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
			raise CommandError("Error when processing connection extended: ", ret)
		con_ext_dict = {
			'bitrate': wb_connection_extended.bitrate,
			'txpower': wb_connection_extended.txpower,
			'dtim': wb_connection_extended.dtim,
			'beaconperiod': wb_connection_extended.beaconperiod
		}
		return con_ext_dict

	#######################################################################
	# WiFi Management
	def wifi_enable(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_enable()
		if ret != 0:
			raise CommandError("Error when doing wifi_enable: ", ret)

	def wifi_disable(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_disable()
		if ret != 0:
			raise CommandError("Error when doing wifi_disable: ", ret)

	#######################################################################
	# WiFi Profile Management
	def wifi_profile_create(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_create()
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_create: ", ret)

	def wifi_profile_pull(self, name):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_pull(name)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_pull: ", ret)

	def wifi_profile_close_handle(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_close_handle()
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_close_handle: ", ret)

	def wifi_profile_push(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_push()
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_push: ", ret)

	def wifi_profile_activate_by_name(self, name):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_activate_by_name(name)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_activate_by_name: ", ret)

	def wifi_profile_delete_from_device(self, name):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_delete_from_device(name)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_delete_from_device: ", ret)

	def wifi_profile_set_profilename(self, name):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_profilename(name)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_activate_by_name: ", ret)

	def wifi_profile_get_profilename(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_profilename = dcal_py.generic_string()
		ret = self.d.wifi_profile_get_profilename( profile_profilename )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_profilename: ", ret)
		return profile_profilename.gen_string()

	def wifi_profile_set_SSID(self, name):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_SSID(name)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_SSID: ", ret)

	def wifi_profile_get_SSID(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_SSID = dcal_py.profile_SSID()
		ret = self.d.wifi_profile_get_SSID( profile_SSID )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_SSID: ", ret)
		profile_SSID_dict = {
			'len': profile_SSID.len,
			'val': profile_SSID.val(),
		}
		return profile_SSID_dict

	def wifi_profile_set_encrypt_std(self, encyption_std):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_encrypt_std(encyption_std)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_encrypt_std: ", ret)

	def wifi_profile_get_encrypt_std(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_encryption_std = dcal_py.generic_int()
		ret = self.d.wifi_profile_get_encrypt_std( profile_encryption_std )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_encrypt_std: ", ret)
		return profile_encryption_std.gen_int

	def wifi_profile_set_encryption(self, encyption):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_encryption(encyption)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_encryption: ", ret)

	def wifi_profile_get_encryption(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_encryption = dcal_py.generic_int()
		ret = self.d.wifi_profile_get_encryption( profile_encryption )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_encryption: ", ret)
		return profile_encryption.gen_int

	def wifi_profile_set_auth(self, auth_type):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_auth(auth_type)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_auth: ", ret)

	def wifi_profile_get_auth(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_auth = dcal_py.generic_int()
		ret = self.d.wifi_profile_get_auth( profile_auth )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_auth: ", ret)
		return profile_auth.gen_int

	def wifi_profile_set_eap(self, eap):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_eap(eap)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_eap: ", ret)

	def wifi_profile_get_eap(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_eap = dcal_py.generic_int()
		ret = self.d.wifi_profile_get_eap( profile_eap )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_eap: ", ret)
		return profile_eap.gen_int

	def wifi_profile_set_psk(self, psk):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_psk(psk)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_psk: ", ret)

	def wifi_profile_psk_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_psk = dcal_py.generic_int()
		ret = self.d.wifi_profile_psk_is_set( profile_psk )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_psk_is_set: ", ret)
		return profile_psk.gen_int

	def wifi_profile_set_user(self, user):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_user(user)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_user: ", ret)

	def wifi_profile_user_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_user = dcal_py.generic_int()
		ret = self.d.wifi_profile_user_is_set( profile_user )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_user_is_set: ", ret)
		return profile_user.gen_int

	def wifi_profile_set_password(self, password):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_password(password)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_password: ", ret)

	def wifi_profile_password_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_password = dcal_py.generic_int()
		ret = self.d.wifi_profile_password_is_set( profile_password )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_password_is_set: ", ret)
		return profile_password.gen_int

	def wifi_profile_set_cacert(self, cacert):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_cacert(cacert)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_cacert: ", ret)

	def wifi_profile_cacert_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_cacert = dcal_py.generic_int()
		ret = self.d.wifi_profile_cacert_is_set( profile_cacert )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_cacert_is_set: ", ret)
		return profile_cacert.gen_int

	def wifi_profile_set_pacfile(self, pacfilename):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_pacfile(pacfilename)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_pacfile: ", ret)

	def wifi_profile_pacfile_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_pacfile = dcal_py.generic_int()
		ret = self.d.wifi_profile_pacfile_is_set( profile_pacfile )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_pacfile_is_set: ", ret)
		return profile_pacfile.gen_int

	def wifi_profile_set_pacpassword(self, pacpassword):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_pacpassword(pacpassword)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_pacpassword: ", ret)

	def wifi_profile_pacpassword_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_pacpassword = dcal_py.generic_int()
		ret = self.d.wifi_profile_pacpassword_is_set( profile_pacpassword )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_pacpassword_is_set: ", ret)
		return profile_pacpassword.gen_int

	def wifi_profile_set_usercert(self, usercert):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_usercert(usercert)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_usercert: ", ret)

	def wifi_profile_usercert_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_usercert = dcal_py.generic_int()
		ret = self.d.wifi_profile_usercert_is_set( profile_usercert )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_usercert_is_set: ", ret)
		return profile_usercert.gen_int

	def wifi_profile_set_usercert_password(self, usercert_password):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_usercert_password(usercert_password)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_usercert_password: ", ret)

	def wifi_profile_usercert_password_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_usercert_password = dcal_py.generic_int()
		ret = self.d.wifi_profile_usercert_password_is_set( profile_usercert_password )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_usercert_password_is_set: ", ret)
		return profile_usercert_password.gen_int

	def wifi_profile_set_wep_key(self, wepkey, index):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_wep_key(wepkey, index)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_wep_key: ", ret)

	def wifi_profile_wep_key_is_set(self, index):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_wep_key = dcal_py.generic_int()
		ret = self.d.wifi_profile_wep_key_is_set( profile_wep_key, index )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_wep_key_is_set: ", ret)
		return profile_wep_key.gen_int

	def wifi_profile_set_wep_txkey(self, txkey):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_wep_txkey(txkey)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_wep_txkey: ", ret)

	def wifi_profile_get_wep_txkey(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_wep_txkey = dcal_py.generic_uint()
		ret = self.d.wifi_profile_get_wep_txkey( profile_wep_txkey )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_wep_txkey: ", ret)
		return profile_wep_txkey.gen_uint

	def wifi_profile_set_clientname(self, clientname):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_clientname(clientname)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_clientname: ", ret)

	def wifi_profile_get_clientname(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_clientname = dcal_py.generic_string()
		ret = self.d.wifi_profile_get_clientname( profile_clientname )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_clientname: ", ret)
		return profile_clientname.gen_string()

	def wifi_profile_set_radiomode(self, radio_mode):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_radiomode(radio_mode)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_radiomode: ", ret)

	def wifi_profile_get_radiomode(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_radiomode = dcal_py.generic_int()
		ret = self.d.wifi_profile_get_radiomode( profile_radiomode )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_radiomode: ", ret)
		return profile_radiomode.gen_int

	def wifi_profile_set_powersave(self, power_save):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_powersave(power_save)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_powersave: ", ret)

	def wifi_profile_get_powersave(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_powersave = dcal_py.generic_int()
		ret = self.d.wifi_profile_get_powersave( profile_powersave )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_powersave: ", ret)
		return profile_powersave.gen_int

	def wifi_profile_set_psp_delay(self, pspdelay):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_psp_delay(pspdelay)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_psp_delay: ", ret)

	def wifi_profile_get_psp_delay(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_pspdelay = dcal_py.generic_uint()
		ret = self.d.wifi_profile_get_psp_delay( profile_pspdelay )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_psp_delay: ", ret)
		return profile_pspdelay.gen_uint

	def wifi_profile_set_txpower(self, txpower):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_txpower(txpower)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_txpower: ", ret)

	def wifi_profile_get_txpower(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_txpower = dcal_py.generic_int()
		ret = self.d.wifi_profile_get_txpower( profile_txpower )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_txpower: ", ret)
		return profile_txpower.gen_int

	def wifi_profile_set_bitrate(self, bit_rate):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_bitrate(bit_rate)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_bitrate: ", ret)

	def wifi_profile_get_bitrate(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_bitrate = dcal_py.generic_int()
		ret = self.d.wifi_profile_get_bitrate( profile_bitrate )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_bitrate: ", ret)
		return profile_bitrate.gen_int

	def wifi_profile_set_autoprofile(self, autoprofile):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_autoprofile(autoprofile)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_autoprofile: ", ret)

	def wifi_profile_get_autoprofile(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_autoprofile = dcal_py.generic_int()
		ret = self.d.wifi_profile_get_autoprofile( profile_autoprofile )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_autoprofile: ", ret)
		return profile_autoprofile.gen_int

	def wifi_profile_printf(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		self.d.wifi_profile_printf()

	#######################################################################
	# system controls
	def wifi_restart(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_restart()
		if ret != 0:
			raise CommandError("Error when doing wifi_restart: ", ret)

	def system_restart(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.system_restart()
		if ret != 0:
			raise CommandError("Error when doing system_restart: ", ret)
