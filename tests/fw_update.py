"""
Test init/teardown and start/stop behavior for each configured node

The basic test suite just makes sure that any configured nodes can be
initialized and shutdown repeatedly without hanging, crashing, etc.
"""

import wtfconfig

def setUp(self):
	# start with all of the nodes shutdown
	print "doing setup"
	for n in wtfconfig.nodes:
		n.shutdown()

class TestBasic():

	def test_01_fw_update(self):
		for n in wtfconfig.nodes:
			n.init_and_login()
			n.wait_check('ip addr show dev eth0 | grep inet')
			n.fw_update('http://192.168.0.18/fw/t1/fw.txt')
			n.reboot()
			n.login()
			n.checkfs()
	
