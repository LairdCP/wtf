"""
Test init/teardown and start/stop behavior for each configured node

The basic test suite just makes sure that any configured nodes can be
initialized and shutdown repeatedly without hanging, crashing, etc.
"""

import wtfconfig
import time
import random
import wtf.node as node

def setUp(self):
	# start with all of the nodes setup to be sure to boot from kernel and rootfs a
	# and then make sure we start from a power-off condition
	print "stress_fw_update doing setup"
	for n in wtfconfig.nodes:
		n.shutdown()
# 		n.init_to_uboot()
# 		time.sleep(1)
# 		n.uboot_set_boot_a()
# 		time.sleep(5)   # sleeping really shouldn't be necessary, but since we're pulling power, be conservative
# 		n.shutdown()

class TestFW_Stress():

	def test_uboot_update(self):
		runNum = 0
		testFail = 0
		random.seed(127)
		while True:
			runNum = runNum + 1
			t = random.randrange(5)
 			print "\n====================================================================="
 			print "Uboot Flash test run {} started; t={}".format(runNum, t)
			for n in wtfconfig.nodes:
				try:
					n.shutdown()
					n.init_to_uboot()
					n.uboot_flash()
					n.uboot_boot()

					# Wait a short amount of time and power cycle it
					time.sleep(t)
					n.shutdown()

					# Check it
					n.init_and_login()
					time.sleep(5)
					n.checkfs()

				except KeyboardInterrupt:
					print "User requested exit, done"
					exit()
				except node.VerificationError as err:
					print 'checkfs failed: {}'.format(err)
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

			print "Flash test run {} OK".format(runNum)
			if runNum == 600:
				break
