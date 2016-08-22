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

	def device_status_get_ipv4(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ipv4_addr = dcal_py.generic_string()
		ret = self.d.device_status_get_ipv4( ipv4_addr )
		if ret != 0:
			raise CommandError("Error when processing device_status_get_ipv4: ", ret)
		return ipv4_addr.gen_string()

	def device_status_get_ipv6_count(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ipv6_count = dcal_py.generic_int()
		ret = self.d.device_status_get_ipv6_count( ipv6_count )
		if ret != 0:
			raise CommandError("Error when processing device_status_get_ipv6_count: ", ret)
		return ipv6_count.gen_int

	def device_status_get_ipv6_string_at_index(self, index):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ipv6_addr = dcal_py.generic_string()
		ret = self.d.device_status_get_ipv6_string_at_index(index, ipv6_addr )
		if ret != 0:
			raise CommandError("Error when processing device_status_get_ipv6_string_at_index: ", ret)
		return ipv6_addr.gen_string()

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
	# WiFi Global Management
	def wifi_global_create(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_create()
		if ret != 0:
			raise CommandError("Error when doing wifi_global_create: ", ret)

	def wifi_global_pull(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_pull()
		if ret != 0:
			raise CommandError("Error when doing wifi_global_pull: ", ret)

	def wifi_global_close_handle(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_close_handle()
		if ret != 0:
			raise CommandError("Error when doing wifi_global_close_handle: ", ret)

	def wifi_global_push(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_push()
		if ret != 0:
			raise CommandError("Error when doing wifi_global_push: ", ret)

	def wifi_global_set_auth_server(self, server_auth):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_auth_server(server_auth)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_auth_server: ", ret)

	def wifi_global_get_auth_server(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		auth_server = dcal_py.generic_int()
		ret = self.d.wifi_global_get_auth_server( auth_server )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_auth_server: ", ret)
		return auth_server.gen_int

	def wifi_global_set_achannel_mask(self, channel_set_a):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_achannel_mask(channel_set_a)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_achannel_mask: ", ret)

	def wifi_global_get_achannel_mask(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		channel_set_a = dcal_py.generic_uint()
		ret = self.d.wifi_global_get_achannel_mask( channel_set_a )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_achannel_mask: ", ret)
		return channel_set_a.gen_uint

	def wifi_global_set_bchannel_mask(self, channel_set_b):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_bchannel_mask(channel_set_b)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_bchannel_mask: ", ret)

	def wifi_global_get_bchannel_mask(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		channel_set_b = dcal_py.generic_uint()
		ret = self.d.wifi_global_get_bchannel_mask( channel_set_b )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_bchannel_mask: ", ret)
		return channel_set_b.gen_uint

	def wifi_global_set_auto_profile(self, auto_profile):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_auto_profile(auto_profile)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_auto_profile: ", ret)

	def wifi_global_get_auto_profile(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		auto_profile = dcal_py.generic_int()
		ret = self.d.wifi_global_get_auto_profile( auto_profile )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_auto_profile: ", ret)
		return auto_profile.gen_int

	def wifi_global_set_beacon_miss(self, beacon_miss):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_beacon_miss(beacon_miss)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_beacon_miss: ", ret)

	def wifi_global_get_beacon_miss(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		beacon_miss = dcal_py.generic_uint()
		ret = self.d.wifi_global_get_beacon_miss( beacon_miss )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_beacon_miss: ", ret)
		return beacon_miss.gen_uint

	def wifi_global_set_ccx(self, ccx):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_ccx(ccx)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_ccx: ", ret)

	def wifi_global_get_ccx(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ccx = dcal_py.generic_int()
		ret = self.d.wifi_global_get_ccx( ccx )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_ccx: ", ret)
		return ccx.gen_int

	def wifi_global_set_cert_path(self, cert_path):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_cert_path(cert_path)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_cert_path: ", ret)

	def wifi_global_get_cert_path(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		cert_path = dcal_py.generic_string()
		ret = self.d.wifi_global_get_cert_path( cert_path )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_cert_path: ", ret)
		return cert_path.gen_string()

	def wifi_global_set_date_check(self, date_check):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_date_check(date_check)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_date_check: ", ret)

	def wifi_global_get_date_check(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		date_check = dcal_py.generic_int()
		ret = self.d.wifi_global_get_date_check( date_check )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_date_check: ", ret)
		return date_check.gen_int

	def wifi_global_set_def_adhoc_channel(self, def_adhoc_channel):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_def_adhoc_channel(def_adhoc_channel)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_def_adhoc_channel: ", ret)

	def wifi_global_get_def_adhoc_channel(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		def_adhoc_channel = dcal_py.generic_uint()
		ret = self.d.wifi_global_get_def_adhoc_channel( def_adhoc_channel )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_def_adhoc_channel: ", ret)
		return def_adhoc_channel.gen_uint

	def wifi_global_set_fips(self, fips):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_fips(fips)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_fips: ", ret)

	def wifi_global_get_fips(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		fips = dcal_py.generic_int()
		ret = self.d.wifi_global_get_fips( fips )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_fips: ", ret)
		return fips.gen_int

	def wifi_global_set_pmk(self, pmk):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_pmk(pmk)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_pmk: ", ret)

	def wifi_global_get_pmk(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		pmk = dcal_py.generic_int()
		ret = self.d.wifi_global_get_pmk( pmk )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_pmk: ", ret)
		return pmk.gen_int

	def wifi_global_set_probe_delay(self, probe_delay):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_probe_delay(probe_delay)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_probe_delay: ", ret)

	def wifi_global_get_probe_delay(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		probe_delay = dcal_py.generic_uint()
		ret = self.d.wifi_global_get_probe_delay( probe_delay )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_probe_delay: ", ret)
		return probe_delay.gen_uint

	def wifi_global_get_regdomain(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		regdomain = dcal_py.generic_int()
		ret = self.d.wifi_global_get_regdomain( regdomain )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_regdomain: ", ret)
		return regdomain.gen_int

	def wifi_global_set_roam_periodms(self, roam_periodms):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_roam_periodms(roam_periodms)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_roam_periodms: ", ret)

	def wifi_global_get_roam_periodms(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		roam_periodms = dcal_py.generic_uint()
		ret = self.d.wifi_global_get_roam_periodms( roam_periodms )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_roam_periodms: ", ret)
		return roam_periodms.gen_uint

	def wifi_global_set_roam_trigger(self, roam_trigger):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_roam_trigger(roam_trigger)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_roam_trigger: ", ret)

	def wifi_global_get_roam_trigger(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		roam_trigger = dcal_py.generic_uint()
		ret = self.d.wifi_global_get_roam_trigger( roam_trigger )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_roam_trigger: ", ret)
		return roam_trigger.gen_uint

	def wifi_global_set_rts(self, rts):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_rts(rts)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_rts: ", ret)

	def wifi_global_get_rts(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		rts = dcal_py.generic_uint()
		ret = self.d.wifi_global_get_rts( rts )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_rts: ", ret)
		return rts.gen_uint

	def wifi_global_set_scan_dfs_time(self, scan_dfs):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_scan_dfs_time(scan_dfs)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_scan_dfs_time: ", ret)

	def wifi_global_get_scan_dfs_time(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		scan_dfs = dcal_py.generic_uint()
		ret = self.d.wifi_global_get_scan_dfs_time( scan_dfs )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_scan_dfs_time: ", ret)
		return scan_dfs.gen_uint

	def wifi_global_set_ttls_inner_method(self, ttls_inner):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_ttls_inner_method(ttls_inner)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_ttls_inner_method: ", ret)

	def wifi_global_get_ttls_inner_method(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ttls_inner = dcal_py.generic_int()
		ret = self.d.wifi_global_get_ttls_inner_method( ttls_inner )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_ttls_inner_method: ", ret)
		return ttls_inner.gen_int

	def wifi_global_set_uapsd(self, uapsd):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_uapsd(uapsd)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_uapsd: ", ret)

	def wifi_global_get_uapsd(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		uapsd = dcal_py.generic_int()
		ret = self.d.wifi_global_get_uapsd( uapsd )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_uapsd: ", ret)
		return uapsd.gen_int

	def wifi_global_set_wmm(self, wmm):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_wmm(wmm)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_wmm: ", ret)

	def wifi_global_get_wmm(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		wmm = dcal_py.generic_int()
		ret = self.d.wifi_global_get_wmm( wmm )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_wmm: ", ret)
		return wmm.gen_int

	def wifi_global_set_ignore_null_ssid(self, ignore_null_ssid):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_ignore_null_ssid(ignore_null_ssid)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_ignore_null_ssid: ", ret)

	def wifi_global_get_ignore_null_ssid(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ignore_null_ssid = dcal_py.generic_int()
		ret = self.d.wifi_global_get_ignore_null_ssid( ignore_null_ssid )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_ignore_null_ssid: ", ret)
		return ignore_null_ssid.gen_int

	def wifi_global_set_dfs_channels(self, dfs):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.wifi_global_set_dfs_channels(dfs)
		if ret != 0:
			raise CommandError("Error when doing wifi_global_set_dfs_channels: ", ret)

	def wifi_global_get_dfs_channels(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		dfs = dcal_py.generic_int()
		ret = self.d.wifi_global_get_dfs_channels( dfs )
		if ret != 0:
			raise CommandError("Error when processing wifi_global_get_dfs_channels: ", ret)
		return dfs.gen_int

	def wifi_global_printf(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		self.d.wifi_global_printf()

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

	#######################################################################
	# time controls
	def time_set(self, tv_sec, tv_usec):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.time_set(tv_sec, tv_usec)
		if ret != 0:
			raise CommandError("Error when doing time_set: ", ret)

	def time_get(self):
		if not self.is_open:
			raise SessionError("Error session is not open")
		dcal_time = dcal_py.dcal_time()
		ret = self.d.time_get( dcal_time )
		if ret != 0:
			raise CommandError("Error when processing time_get: ", ret)
		time_dict = {
			'tv_sec': dcal_time.tv_sec,
			'tv_usec': dcal_time.tv_usec,
		}
		return time_dict

	def ntpdate(self, server_name):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.ntpdate(server_name)
		if ret != 0:
			raise CommandError("Error when doing ntpdate: ", ret)

	#######################################################################
	# file controls
	def file_push_to_wb(self, local_file_name, remote_file_name):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.file_push_to_wb(local_file_name, remote_file_name)
		if ret != 0:
			raise CommandError("Error when doing file_push_to_wb: ", ret)

	def file_pull_from_wb(self, local_file_name, remote_file_name):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.file_pull_from_wb(local_file_name, remote_file_name)
		if ret != 0:
			raise CommandError("Error when doing file_pull_from_wb: ", ret)

	def fw_update(self, flags):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.fw_update(flags)
		if ret != 0:
			raise CommandError("Error when doing fw_update: ", ret)

	def pull_logs(self, dest_file):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.pull_logs(dest_file)
		if ret != 0:
			raise CommandError("Error when doing pull_logs: ", ret)

	def process_cli_command_file(self, src_file):
		if not self.is_open:
			raise SessionError("Error session is not open")
		ret = self.d.process_cli_command_file(src_file)
		if ret != 0:
			raise CommandError("Error when doing process_cli_command_file: ", ret)
