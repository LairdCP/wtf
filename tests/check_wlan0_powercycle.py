"""
Test wlan0 comes up after boot

This test purposely sets the WIFI_CHIP_PWD_L pin to 0 to force the ath6003 into
reset before the kernel boot to make sure that the kernel and ath6kl driver will
properly enable it. If the driver takes proper control of the GPIO, it will take
the chip out of reset and the wireless will  enumerate on the sdio bus and the
driver will probe and setup wlan0 properly.

"""

import wtfconfig
import time
import random
import wtf.node as node
from nose.tools import nottest

def setUp(self):
	# start with all of the nodes shutdown
	for n in wtfconfig.nodes:
		n.shutdown()

class Test_wlan0_reboot():

	def test_wlan0_afterboot(self):
		for n in wtfconfig.nodes:
			n.shutdown()
			n.init_to_uboot()
			n.uboot_mw(0xfffff410, 0x10000000, 'l')
			n.uboot_mw(0xfffff434, 0x10000000, 'l')
			n.uboot_boot()
			n.login()
			n.check_wlan0_exist()

	# Below shouldn't be run.  Remove the @nottest decoration to utilize it.
	# The purpose of this "test" is to reboot the wb until it finds the fail condition and
	# leave the wb in that state for further inspection. This is a tool to utilize in the
	# event you need to get a rare reboot-state problem to happen.
	@nottest
	def test_wlan0_reboot_untilfail(self):
		runNum = 0
		testFail = 0
		while True:
			runNum = runNum + 1
 			print "\n====================================================================="
 			print "Reboot cycle run {}".format(runNum)
			for n in wtfconfig.nodes:
				try:
					n.shutdown()
					n.init_and_login()
					n.check_wlan0_exist()

				except KeyboardInterrupt:
					print "User requested exit, done"
					exit()
				except node.VerificationError as err:
					print 'wlan0 did not come up'
					exit()
				except:
					if testFail < 5:
						print 'random test failure, restarting'
						testFail += 1
						break
					else:
						print 'ERROR: to many failures in a row, dying'
						raise
				else:
					testFail = 0

