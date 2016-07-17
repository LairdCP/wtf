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
			sdk_dict = n.dcal.sdk_version()
			pprint.pprint(sdk_dict) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0003_chipset_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			chipset_dict = n.dcal.chipset_version()
			pprint.pprint(chipset_dict) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0004_system_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			system_dict = n.dcal.system_version()
			pprint.pprint(system_dict) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0005_driver_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			driver_dict = n.dcal.driver_version()
			pprint.pprint(driver_dict) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0006_dcas_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			dcas_dict = n.dcal.dcas_version()
			pprint.pprint(dcas_dict) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0007_dcal_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			dcal_dict = n.dcal.dcal_version()
			pprint.pprint(dcal_dict) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0008_firmware_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			firmware_dict = n.dcal.firmware_version()
			pprint.pprint(firmware_dict) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0009_supplicant_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			supplicant_dict = n.dcal.supplicant_version()
			pprint.pprint(supplicant_dict) # only see this if doing ./run -s
			# So we don't break just because we're running against
			# different releases, we don't check the return
			n.dcal.close()

	def test_0010_release_version(self):
		for n in wtfconfig.nodes:
			n.dcal.open()
			release_dict = n.dcal.release_version()
			pprint.pprint(release_dict) # only see this if doing ./run -s
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

	def test_0016_status_settings_default_profile(self):
		testProfileName = "Default"
		for n in wtfconfig.nodes:
			n.dcal.open()
			n.dcal.wifi_profile_activate_by_name(testProfileName)
			n.dcal.status_pull()
			setting_dict = n.dcal.status_get_settings()
			pprint.pprint(setting_dict) # only see this if doing ./run -s
			n.dcal.close()

			self.failIf(setting_dict['profilename'] != testProfileName,
				"Failed to set profile: " + testProfileName)
