"""
Test init/teardown and start/stop behavior for each configured node

The basic test suite just makes sure that any configured nodes can be
initialized and shutdown repeatedly without hanging, crashing, etc.
"""
import wtfconfig
import time
import pprint
import unittest

def setUp(self):
	# start with all of the nodes running, but in a clean state
	for n in wtfconfig.nodes:
		n.shutdown()
		n.init_and_login()
	time.sleep(5) # have to let the device settle, or dcas won't be ready for callers

class TestDCAL(unittest.TestCase):

	def test_0001_session(self):
		for n in wtfconfig.nodes:
			n.check_log("Started DCAS")
			n.dcal.open()
			n.check_log("Got good protocol HELLO")
			n.dcal.close()
			n.check_log("thread exiting")

	def test_0002_sdk_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			sdk_version = n.dcal.sdk_version()
			pprint.pprint(sdk_version) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0003_chipset_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			chipset_version = n.dcal.chipset_version()
			pprint.pprint(chipset_version) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0004_system_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			system_version = n.dcal.system_version()
			pprint.pprint(system_version) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0005_driver_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			driver_version = n.dcal.driver_version()
			pprint.pprint(driver_version) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0006_dcas_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			dcas_version = n.dcal.dcas_version()
			pprint.pprint(dcas_version) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0007_dcal_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			dcal_version = n.dcal.dcal_version()
			pprint.pprint(dcal_version) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0008_firmware_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			firmware_version = n.dcal.firmware_version()
			pprint.pprint(firmware_version) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0009_supplicant_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			supplicant_version = n.dcal.supplicant_version()
			pprint.pprint(supplicant_version) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0010_release_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			release_version = n.dcal.release_version()
			pprint.pprint(release_version) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0011_status_settings(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.status_pull()
			setting_dict = n.dcal.status_get_settings()
			pprint.pprint(setting_dict) # only see this if doing ./run -s
			# We don't know our current expected state, so we don't
			# want to validate the garbage that may be returned
			n.dcal.close()

	def test_0012_status_ccx(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.status_pull()
			ccx_dict = n.dcal.status_get_ccx()
			pprint.pprint(ccx_dict) # only see this if doing ./run -s
			# We don't know our current expected state, so we don't
			# want to validate the garbage that may be returned
			n.dcal.close()

	def test_0013_status_tcp(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.status_pull()
			tcp_dict = n.dcal.status_get_tcp()
			pprint.pprint(tcp_dict) # only see this if doing ./run -s
			# We don't know our current expected state, so we don't
			# want to validate the garbage that may be returned
			n.dcal.close()

	def test_0014_status_connection(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.status_pull()
			connection_dict = n.dcal.status_get_connection()
			pprint.pprint(connection_dict) # only see this if doing ./run -s
			# We don't know our current expected state, so we don't
			# want to validate the garbage that may be returned
			n.dcal.close()

	def test_0015_status_connection_extended(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.status_pull()
			connection_extended_dict = n.dcal.status_get_connection_extended()
			pprint.pprint(connection_extended_dict) # only see this if doing ./run -s
			# We don't know our current expected state, so we don't
			# want to validate the garbage that may be returned
			n.dcal.close()

	def test_0016_wifi_disable(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_disable()
			n.dcal.status_pull()
			connection_dict = n.dcal.status_get_connection()
			pprint.pprint(connection_dict)
			n.dcal.close()

			self.failIf(int(connection_dict['cardstate']) != 6,
				"Failed to disable WiFi: " + str(connection_dict['cardstate']))

	def test_0017_wifi_enable(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_enable()
			n.dcal.status_pull()
			connection_dict = n.dcal.status_get_connection()
			pprint.pprint(connection_dict)
			n.dcal.close()

			self.failIf((int(connection_dict['cardstate']) != 1 | int(connection_dict['cardstate']) != 2 | int(connection_dict['cardstate']) != 3),
				"Failed to enable WiFi: " + str(connection_dict['cardstate']))

	def test_0018_status_settings_default_profile(self):
		testProfileName = "Default"
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_activate_by_name(testProfileName)
			n.dcal.status_pull()
			setting_dict = n.dcal.status_get_settings()
			pprint.pprint(setting_dict) # only see this if doing ./run -s
			n.dcal.close()

			self.failIf(setting_dict['profilename'] != testProfileName,
				"Failed to set profile: " + str(setting_dict['profilename']))

	def test_0019_create_open_profile(self):
		newProfileName = "wtf_open"
		SSID = "wtf_open_SSID"
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_SSID(SSID)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_SSID_dict = n.dcal.wifi_profile_get_SSID()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_SSID_dict)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_SSID_dict['val'] != SSID,
				"Failed to set SSID: " + str(profile_SSID_dict['val']))

	def test_0020_create_wep_profile(self):
		newProfileName = "wtf_wep"
		SSID = "wtf_wep_SSID"
		ES_WEP = 1
		WEPKEY = "12345"
		WEPINDEX = 2
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_SSID(SSID)
			n.dcal.wifi_profile_set_encrypt_std(ES_WEP)
			n.dcal.wifi_profile_set_wep_key(WEPKEY, WEPINDEX)
			n.dcal.wifi_profile_set_wep_txkey(WEPINDEX)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_SSID_dict = n.dcal.wifi_profile_get_SSID()
			profile_encryption_std = n.dcal.wifi_profile_get_encrypt_std()
			profile_wep_key = n.dcal.wifi_profile_wep_key_is_set(WEPINDEX)
			profile_wep_txkey = n.dcal.wifi_profile_get_wep_txkey()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_SSID_dict)
			pprint.pprint(profile_encryption_std)
			pprint.pprint(profile_wep_key)
			pprint.pprint(profile_wep_txkey)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_SSID_dict['val'] != SSID,
				"Failed to set SSID: " + str(profile_SSID_dict['val']))

			self.failIf(profile_encryption_std != ES_WEP,
				"Failed to set encryption_std: " + str(profile_encryption_std))

			self.failIf(profile_wep_key != True,
				"Failed to set WEP key: " + str(profile_wep_key))

			self.failIf(profile_wep_txkey != WEPINDEX,
				"Failed to set WEP TX key: " + str(profile_wep_txkey))

	def test_0021_create_wpa2_aes_psk_profile(self):
		newProfileName = "wtf_wpa2_aes_psk"
		SSID = "wtf_wpa2_aes_psk_SSID"
		PSK = "wtf_wpa2_aes_PSK"
		ES_WPA2 = 3
		ENC_AES = 1
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_SSID(SSID)
			n.dcal.wifi_profile_set_encrypt_std(ES_WPA2)
			n.dcal.wifi_profile_set_encryption(ENC_AES)
			n.dcal.wifi_profile_set_psk(PSK)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_SSID_dict = n.dcal.wifi_profile_get_SSID()
			profile_encryption_std = n.dcal.wifi_profile_get_encrypt_std()
			profile_encryption = n.dcal.wifi_profile_get_encryption()
			profile_psk = n.dcal.wifi_profile_psk_is_set()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_SSID_dict)
			pprint.pprint(profile_encryption_std)
			pprint.pprint(profile_encryption)
			pprint.pprint(profile_psk)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_SSID_dict['val'] != SSID,
				"Failed to set SSID: " + str(profile_SSID_dict['val']))

			self.failIf(profile_encryption_std != ES_WPA2,
				"Failed to set encryption_std: " + str(profile_encryption_std))

			self.failIf(profile_encryption != ENC_AES,
				"Failed to set encryption: " + str(profile_encryption))

			self.failIf(profile_psk != True,
				"Failed to set psk: " + str(profile_psk))

	def test_0022_create_wpa2_aes_eapfast_profile(self):
		newProfileName = "wtf_wpa2_eapfast_mschap"
		SSID = "wtf_wpa2_aes_eapfast_SSID"
		ES_WPA2 = 3
		ENC_AES = 1
		EAP_FAST = 2
		USER = "wtf_user"
		PASSWORD = "wtf_password"
		PAC_FILENAME = "wtf_pac.pac"
		PAC_PASSWORD = "wtf_pac_password"
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_SSID(SSID)
			n.dcal.wifi_profile_set_encrypt_std(ES_WPA2)
			n.dcal.wifi_profile_set_encryption(ENC_AES)
			n.dcal.wifi_profile_set_eap(EAP_FAST)
			n.dcal.wifi_profile_set_user(USER)
			n.dcal.wifi_profile_set_password(PASSWORD)
			n.dcal.wifi_profile_set_pacfile(PAC_FILENAME)
			n.dcal.wifi_profile_set_pacpassword(PAC_PASSWORD)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_SSID_dict = n.dcal.wifi_profile_get_SSID()
			profile_encryption_std = n.dcal.wifi_profile_get_encrypt_std()
			profile_encryption = n.dcal.wifi_profile_get_encryption()
			profile_eap = n.dcal.wifi_profile_get_eap()
			profile_user = n.dcal.wifi_profile_user_is_set()
			profile_password = n.dcal.wifi_profile_password_is_set()
			profile_pacfilename = n.dcal.wifi_profile_pacfile_is_set()
			profile_pacprofile_password = n.dcal.wifi_profile_pacpassword_is_set()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_SSID_dict)
			pprint.pprint(profile_encryption_std)
			pprint.pprint(profile_encryption)
			pprint.pprint(profile_eap)
			pprint.pprint(profile_user)
			pprint.pprint(profile_password)
			pprint.pprint(profile_pacfilename)
			pprint.pprint(profile_pacprofile_password)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_SSID_dict['val'] != SSID,
				"Failed to set SSID: " + str(profile_SSID_dict['val']))

			self.failIf(profile_encryption_std != ES_WPA2,
				"Failed to set encryption_std: " + str(profile_encryption_std))

			self.failIf(profile_encryption != ENC_AES,
				"Failed to set encryption: " + str(profile_encryption))

			self.failIf(profile_eap != EAP_FAST,
				"Failed to set eap: " + str(profile_eap))

			self.failIf(profile_user != True,
				"Failed to set user: " + str(profile_user))

			self.failIf(profile_password != True,
				"Failed to set password: " + str(profile_password))

			self.failIf(profile_pacfilename != True,
				"Failed to set PAC filename: " + str(profile_pacfilename))

			self.failIf(profile_pacprofile_password != True,
				"Failed to set PAC password: " + str(profile_pacprofile_password))

	def test_0023_create_wpa2_aes_mschap_profile(self):
		newProfileName = "wtf_wpa2_aes_mschap"
		SSID = "wtf_wpa2_aes_mschap_SSID"
		ES_WPA2 = 3
		ENC_AES = 1
		EAP_PEAPMSCHAP = 3
		USER = "wtf_user"
		PASSWORD = "wtf_password"
		CACERT = "wtf_cacert"
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_SSID(SSID)
			n.dcal.wifi_profile_set_encrypt_std(ES_WPA2)
			n.dcal.wifi_profile_set_encryption(ENC_AES)
			n.dcal.wifi_profile_set_eap(EAP_PEAPMSCHAP)
			n.dcal.wifi_profile_set_user(USER)
			n.dcal.wifi_profile_set_password(PASSWORD)
			n.dcal.wifi_profile_set_cacert(CACERT)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_SSID_dict = n.dcal.wifi_profile_get_SSID()
			profile_encryption_std = n.dcal.wifi_profile_get_encrypt_std()
			profile_encryption = n.dcal.wifi_profile_get_encryption()
			profile_eap = n.dcal.wifi_profile_get_eap()
			profile_user = n.dcal.wifi_profile_user_is_set()
			profile_password = n.dcal.wifi_profile_password_is_set()
			profile_cacert = n.dcal.wifi_profile_cacert_is_set()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_SSID_dict)
			pprint.pprint(profile_encryption_std)
			pprint.pprint(profile_encryption)
			pprint.pprint(profile_eap)
			pprint.pprint(profile_user)
			pprint.pprint(profile_password)
			pprint.pprint(profile_cacert)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_SSID_dict['val'] != SSID,
				"Failed to set SSID: " + str(profile_SSID_dict['val']))

			self.failIf(profile_encryption_std != ES_WPA2,
				"Failed to set encryption_std: " + str(profile_encryption_std))

			self.failIf(profile_encryption != ENC_AES,
				"Failed to set encryption: " + str(profile_encryption))

			self.failIf(profile_eap != EAP_PEAPMSCHAP,
				"Failed to set eap: " + str(profile_eap))

			self.failIf(profile_user != True,
				"Failed to set user: " + str(profile_user))

			self.failIf(profile_password != True,
				"Failed to set password: " + str(profile_password))

			self.failIf(profile_cacert != True,
				"Failed to set usercert password: " + str(profile_cacert))

	def test_0024_create_wpa2_aes_eap_tls_profile(self):
		newProfileName = "wtf_wpa2_aes_eap_tls"
		SSID = "wtf_wpa2_aes_eap_tls_SSID"
		ES_WPA2 = 3
		ENC_AES = 1
		EAP_EAPTLS = 5
		USER = "wtf_user"
		USERCERT = "wtf_user.pfx"
		USERCERT_PASSWORD = "wtf_user_password"
		PASSWORD = "wtf_password"
		CACERT = "wtf_cacert"
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_SSID(SSID)
			n.dcal.wifi_profile_set_encrypt_std(ES_WPA2)
			n.dcal.wifi_profile_set_encryption(ENC_AES)
			n.dcal.wifi_profile_set_eap(EAP_EAPTLS)
			n.dcal.wifi_profile_set_user(USER)
			n.dcal.wifi_profile_set_usercert(USERCERT)
			n.dcal.wifi_profile_set_usercert_password(USERCERT_PASSWORD)
			n.dcal.wifi_profile_set_cacert(CACERT)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_SSID_dict = n.dcal.wifi_profile_get_SSID()
			profile_encryption_std = n.dcal.wifi_profile_get_encrypt_std()
			profile_encryption = n.dcal.wifi_profile_get_encryption()
			profile_eap = n.dcal.wifi_profile_get_eap()
			profile_user = n.dcal.wifi_profile_user_is_set()
			profile_usercert = n.dcal.wifi_profile_usercert_is_set()
			profile_usercert_profile_password = n.dcal.wifi_profile_usercert_password_is_set()
			profile_cacert = n.dcal.wifi_profile_cacert_is_set()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_SSID_dict)
			pprint.pprint(profile_encryption_std)
			pprint.pprint(profile_encryption)
			pprint.pprint(profile_eap)
			pprint.pprint(profile_user)
			pprint.pprint(profile_usercert)
			pprint.pprint(profile_usercert_profile_password)
			pprint.pprint(profile_cacert)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_SSID_dict['val'] != SSID,
				"Failed to set SSID: " + str(profile_SSID_dict['val']))

			self.failIf(profile_encryption_std != ES_WPA2,
				"Failed to set encryption_std: " + str(profile_encryption_std))

			self.failIf(profile_encryption != ENC_AES,
				"Failed to set encryption: " + str(profile_encryption))

			self.failIf(profile_eap != EAP_EAPTLS,
				"Failed to set eap: " + str(profile_eap))

			self.failIf(profile_user != True,
				"Failed to set user: " + str(profile_user))

			self.failIf(profile_usercert != True,
				"Failed to set usercert: " + str(profile_usercert))

			self.failIf(profile_usercert_profile_password != True,
				"Failed to set usercert password: " + str(profile_usercert_profile_password))

			self.failIf(profile_cacert != True,
				"Failed to set usercert password: " + str(profile_cacert))

	def test_0025_set_clientname(self):
		newProfileName = "wtf_clientname"
		CLIENTNAME = "wtf_clientname"
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_clientname(CLIENTNAME)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_clientname = n.dcal.wifi_profile_get_clientname()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_clientname)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_clientname != CLIENTNAME,
				"Failed to set clientname: " + str(profile_clientname))

	def test_0026_set_radiomode(self):
		newProfileName = "wtf_radiomode"
		RADIOMODE_BG = 1;
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_radiomode(RADIOMODE_BG)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_radiomode = n.dcal.wifi_profile_get_radiomode()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_radiomode)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_radiomode != RADIOMODE_BG,
				"Failed to set radiomode: " + str(profile_radiomode))

	def test_0027_set_powersave(self):
		newProfileName = "wtf_powersave"
		POWERSAVE_OFF = 0;
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_powersave(POWERSAVE_OFF)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_powersave = n.dcal.wifi_profile_get_powersave()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_powersave)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_powersave != POWERSAVE_OFF,
				"Failed to set powersave: " + str(profile_powersave))

	def test_0028_set_psp_delay(self):
		newProfileName = "wtf_psp_delay"
		PSPDELAY = 201;
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_psp_delay(PSPDELAY)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_pspdelay = n.dcal.wifi_profile_get_psp_delay()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_pspdelay)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_pspdelay != PSPDELAY,
				"Failed to set pspdelay: " + str(profile_pspdelay))

	def test_0029_set_txpower(self):
		newProfileName = "wtf_txpower"
		TXPOWER = 10;
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_txpower(TXPOWER)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_txpower = n.dcal.wifi_profile_get_txpower()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_txpower)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_txpower != TXPOWER,
				"Failed to set txpower: " + str(profile_txpower))

	def test_0030_set_bitrate(self):
		newProfileName = "wtf_bitrate"
		BITRATE = 22;
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_bitrate(BITRATE)
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_bitrate = n.dcal.wifi_profile_get_bitrate()
			pprint.pprint(profile_profilename)
			pprint.pprint(profile_bitrate)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_profilename != newProfileName,
				"Failed to set profile name: " + str(profile_profilename))

			self.failIf(profile_bitrate != BITRATE,
				"Failed to set bitrate: " + str(profile_bitrate))

	def test_0031_set_autoprofile(self):
		newProfileName = "wtf_autoprofile"
		ON = 1;
		OFF = 0;
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_create()
			n.dcal.wifi_profile_set_profilename(newProfileName)
			n.dcal.wifi_profile_set_autoprofile(ON);
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_autoprofile_on = n.dcal.wifi_profile_get_autoprofile()
			pprint.pprint(profile_autoprofile_on)
			n.dcal.wifi_profile_set_autoprofile(OFF);
			n.dcal.wifi_profile_push()
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_pull(newProfileName)
			profile_profilename = n.dcal.wifi_profile_get_profilename()
			profile_autoprofile_off = n.dcal.wifi_profile_get_autoprofile()
			pprint.pprint(profile_autoprofile_off)
			n.dcal.wifi_profile_close_handle()
			n.dcal.wifi_profile_delete_from_device(newProfileName)
			n.dcal.close()

			self.failIf(profile_autoprofile_on != ON,
				"Failed to set autoprofile: " + str(profile_autoprofile_on))

			self.failIf(profile_autoprofile_off != OFF,
				"Failed to set autoprofile: " + str(profile_autoprofile_off))

	def test_0032_wifi_restart(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_restart()
			time.sleep(5) #Wait to check if WiFi is backup otherwise we get an error
			n.dcal.status_pull()
			connection_dict = n.dcal.status_get_connection()
			pprint.pprint(connection_dict)
			n.dcal.close()

			self.failIf((int(connection_dict['cardstate']) != 1 | int(connection_dict['cardstate']) != 2 | int(connection_dict['cardstate']) != 3),
				"Failed to disable WiFi: " + str(connection_dict['cardstate']))

	def test_0033_system_restart(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.system_restart()
			n.init_and_login()
			n.check_log("Started DCAS")
			n.dcal.open()
			n.dcal.status_pull()
			connection_dict = n.dcal.status_get_connection()
			pprint.pprint(connection_dict)
			n.dcal.close()

			self.failIf((int(connection_dict['cardstate']) != 1 | int(connection_dict['cardstate']) != 2 | int(connection_dict['cardstate']) != 3),
				"Failed to enable WiFi: " + str(connection_dict['cardstate']))
