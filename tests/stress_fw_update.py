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
	# start with all of the nodes shutdown
	print "stress_fw_update doing setup"
	for n in wtfconfig.nodes:
		n.shutdown()

class TestFW_Stress():

	def test_fw_update(self):
		runNum = 0
		testFail = 0
		random.seed(127)
		while True:
			runNum = runNum + 1
			t = random.randrange(5)
 			print "\n====================================================================="
 			print "Flash test run {} started; t={}".format(runNum, t)
			for n in wtfconfig.nodes:
				try:
					n.shutdown()
					n.init_and_login()
					n.wait_check('ip addr show dev eth0 | grep inet')
					n.fw_update('http://192.168.0.18/fw/t1/fw.txt')
					n.reboot()

					# Wait a short amount of time and power cycle it
					time.sleep(t)
					n.shutdown()

					# Check it
					n.init_and_login()
					time.sleep(10)
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
			if runNum == 30:
				break
