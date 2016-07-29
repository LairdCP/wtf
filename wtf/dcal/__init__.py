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
			raise CommandError("Error when doing get_sdk_version: ", ret)
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
			raise CommandError("Error when doing get_chipset_version: ", ret)
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
			raise CommandError("Error when doing get_system_version: ", ret)
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
			raise CommandError("Error when doing get_driver_version: ", ret)
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
			raise CommandError("Error when doing get_dcas_version: ", ret)
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
			raise CommandError("Error when doing get_dcal_version: ", ret)
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
			raise CommandError("Error when doing get_firmware_version: ", ret)
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
			raise CommandError("Error when doing get_supplicant_version: ", ret)
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
			raise CommandError("Error when doing get_release_version: ", ret)
		release_dict = {
			'release': release_version.release(),
		}
		return release_dict

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
		profile_profilename = dcal_py.profile_profilename()
		ret = self.d.wifi_profile_get_profilename( profile_profilename )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_profilename: ", ret)
		profilename_dict = {
			'profilename_buffer': profile_profilename.profilename(),
		}
		return profilename_dict

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

	def wifi_profile_set_encrypt_std(self, encyption_std):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_encrypt_std(encyption_std)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_encrypt_std: ", ret)

	def wifi_profile_get_encrypt_std(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_encryption_std = dcal_py.profile_encryption_std()
		ret = self.d.wifi_profile_get_encrypt_std( profile_encryption_std )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_encrypt_std: ", ret)
		encryption_std_dict = {
			'encryption_std': profile_encryption_std.encryption_std,
		}
		return encryption_std_dict

	def wifi_profile_set_encryption(self, encyption):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_encryption(encyption)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_encryption: ", ret)

	def wifi_profile_get_encryption(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_encryption = dcal_py.profile_encryption()
		ret = self.d.wifi_profile_get_encryption( profile_encryption )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_encryption: ", ret)
		encryption_dict = {
			'encryption': profile_encryption.encryption,
		}
		return encryption_dict

	def wifi_profile_set_auth(self, auth_type):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_auth(auth_type)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_auth: ", ret)

	def wifi_profile_get_auth(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_auth = dcal_py.profile_auth()
		ret = self.d.wifi_profile_get_auth( profile_auth )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_auth: ", ret)
		auth_dict = {
			'auth': profile_auth.auth,
		}
		return auth_dict

	def wifi_profile_set_eap(self, eap):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_eap(eap)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_eap: ", ret)

	def wifi_profile_get_eap(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_eap = dcal_py.profile_eap()
		ret = self.d.wifi_profile_get_eap( profile_eap )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_eap: ", ret)
		eap_dict = {
			'eap': profile_eap.eap,
		}
		return eap_dict

	def wifi_profile_set_psk(self, psk):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_psk(psk)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_psk: ", ret)

	def wifi_profile_psk_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_psk = dcal_py.profile_psk()
		ret = self.d.wifi_profile_psk_is_set( profile_psk )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_psk_is_set: ", ret)
		psk_dict = {
			'psk': profile_psk.psk,
		}
		return psk_dict

	def wifi_profile_set_user(self, user):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_user(user)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_user: ", ret)

	def wifi_profile_user_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_user = dcal_py.profile_user()
		ret = self.d.wifi_profile_user_is_set( profile_user )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_user_is_set: ", ret)
		user_dict = {
			'user': profile_user.user,
		}
		return user_dict

	def wifi_profile_set_password(self, password):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_password(password)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_password: ", ret)

	def wifi_profile_password_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_password = dcal_py.profile_password()
		ret = self.d.wifi_profile_password_is_set( profile_password )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_password_is_set: ", ret)
		password_dict = {
			'password': profile_password.password,
		}
		return password_dict

	def wifi_profile_set_cacert(self, cacert):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_cacert(cacert)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_cacert: ", ret)

	def wifi_profile_cacert_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_cacert = dcal_py.profile_cacert()
		ret = self.d.wifi_profile_cacert_is_set( profile_cacert )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_cacert_is_set: ", ret)
		cacert_dict = {
			'cacert': profile_cacert.cacert,
		}
		return cacert_dict

	def wifi_profile_set_pacfile(self, pacfilename):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_pacfile(pacfilename)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_pacfile: ", ret)

	def wifi_profile_pacfile_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_pacfile = dcal_py.profile_pacfile()
		ret = self.d.wifi_profile_pacfile_is_set( profile_pacfile )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_pacfile_is_set: ", ret)
		pacfilename_dict = {
			'pacfile': profile_pacfile.pacfile,
		}
		return pacfilename_dict

	def wifi_profile_set_pacpassword(self, pacpassword):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_pacpassword(pacpassword)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_pacpassword: ", ret)

	def wifi_profile_pacpassword_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_pacpassword = dcal_py.profile_pacpassword()
		ret = self.d.wifi_profile_pacpassword_is_set( profile_pacpassword )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_pacpassword_is_set: ", ret)
		pacpassword_dict = {
			'pacpassword': profile_pacpassword.pacpassword,
		}
		return pacpassword_dict

	def wifi_profile_set_usercert(self, usercert):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_usercert(usercert)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_usercert: ", ret)

	def wifi_profile_usercert_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_usercert = dcal_py.profile_usercert()
		ret = self.d.wifi_profile_usercert_is_set( profile_usercert )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_usercert_is_set: ", ret)
		usercert_dict = {
			'usercert': profile_usercert.usercert,
		}
		return usercert_dict

	def wifi_profile_set_usercert_password(self, usercert_password):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_usercert_password(usercert_password)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_usercert_password: ", ret)

	def wifi_profile_usercert_password_is_set(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_usercert_password = dcal_py.profile_usercert_password()
		ret = self.d.wifi_profile_usercert_password_is_set( profile_usercert_password )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_usercert_password_is_set: ", ret)
		usercert_password_dict = {
			'usercert_password': profile_usercert_password.usercert_password,
		}
		return usercert_password_dict

	def wifi_profile_set_wep_key(self, wepkey, index):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_wep_key(wepkey, index)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_wep_key: ", ret)

	def wifi_profile_wep_key_is_set(self, index):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_wep_key = dcal_py.profile_wep_key()
		ret = self.d.wifi_profile_wep_key_is_set( profile_wep_key, index )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_wep_key_is_set: ", ret)
		wep_key_dict = {
			'wep_key': profile_wep_key.wep_key,
		}
		return wep_key_dict

	def wifi_profile_set_wep_txkey(self, txkey):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_wep_txkey(txkey)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_wep_txkey: ", ret)

	def wifi_profile_get_wep_txkey(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_wep_txkey = dcal_py.profile_wep_txkey()
		ret = self.d.wifi_profile_get_wep_txkey( profile_wep_txkey )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_wep_txkey: ", ret)
		clientname_dict = {
			'txkey': profile_wep_txkey.txkey,
		}
		return clientname_dict

	def wifi_profile_set_clientname(self, clientname):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_clientname(clientname)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_clientname: ", ret)

	def wifi_profile_get_clientname(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_clientname = dcal_py.profile_clientname()
		ret = self.d.wifi_profile_get_clientname( profile_clientname )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_clientname: ", ret)
		clientname_dict = {
			'clientname_buffer': profile_clientname.clientname_buffer(),
		}
		return clientname_dict

	def wifi_profile_set_radiomode(self, radio_mode):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_radiomode(radio_mode)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_radiomode: ", ret)

	def wifi_profile_get_radiomode(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_radiomode = dcal_py.profile_radiomode()
		ret = self.d.wifi_profile_get_radiomode( profile_radiomode )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_radiomode: ", ret)
		radiomode_dict = {
			'mode': profile_radiomode.mode,
		}
		return radiomode_dict

	def wifi_profile_set_powersave(self, power_save):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_powersave(power_save)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_powersave: ", ret)

	def wifi_profile_get_powersave(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_powersave = dcal_py.profile_powersave()
		ret = self.d.wifi_profile_get_powersave( profile_powersave )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_powersave: ", ret)
		powersave_dict = {
			'powersave': profile_powersave.powersave,
		}
		return powersave_dict

	def wifi_profile_set_psp_delay(self, pspdelay):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_psp_delay(pspdelay)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_psp_delay: ", ret)

	def wifi_profile_get_psp_delay(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_pspdelay = dcal_py.profile_pspdelay()
		ret = self.d.wifi_profile_get_psp_delay( profile_pspdelay )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_psp_delay: ", ret)
		pspdelay_dict = {
			'pspdelay': profile_pspdelay.pspdelay,
		}
		return pspdelay_dict

	def wifi_profile_set_txpower(self, txpower):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_txpower(txpower)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_txpower: ", ret)

	def wifi_profile_get_txpower(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_txpower = dcal_py.profile_txpower()
		ret = self.d.wifi_profile_get_txpower( profile_txpower )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_txpower: ", ret)
		txpower_dict = {
			'txpower': profile_txpower.txpower,
		}
		return txpower_dict

	def wifi_profile_set_bitrate(self, bit_rate):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_bitrate(bit_rate)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_bitrate: ", ret)

	def wifi_profile_get_bitrate(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_bitrate = dcal_py.profile_bitrate()
		ret = self.d.wifi_profile_get_bitrate( profile_bitrate )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_bitrate: ", ret)
		bitrate_dict = {
			'bitrate': profile_bitrate.bitrate,
		}
		return bitrate_dict

	def wifi_profile_set_autoprofile(self, autoprofile):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_profile_set_autoprofile(autoprofile)
		if ret != 0:
			raise CommandError("Error when doing wifi_profile_set_autoprofile: ", ret)

	def wifi_profile_get_autoprofile(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		profile_autoprofile = dcal_py.profile_autoprofile()
		ret = self.d.wifi_profile_get_autoprofile( profile_autoprofile )
		if ret != 0:
			raise CommandError("Error when processing wifi_profile_get_autoprofile: ", ret)
		autoprofile_dict = {
			'autoprofile': profile_autoprofile.autoprofile,
		}
		return autoprofile_dict

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
