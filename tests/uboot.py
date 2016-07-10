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

	def test_01_init_uboot(self):
		print "doing test_init_uboot"
		for n in wtfconfig.nodes:
			n.shutdown()
			n.init_to_uboot()

	def test_02_boot_uboot(self):
		print "doing test_boot_uboot"
		for n in wtfconfig.nodes:
			n.shutdown()
			n.init_to_uboot()
			n.uboot_boot()
	
	def test_03_flash_uboot(self):
		print "doing test_flash_uboot"
		for n in wtfconfig.nodes:
			n.shutdown()
			n.init_to_uboot()
			n.uboot_flash()
			n.uboot_boot()
	
	def test_04_login(self):
		for n in wtfconfig.nodes:
			n.login()

	def test_05_check_fs(self):
		for n in wtfconfig.nodes:
			n.checkfs()
