"""
Test init/teardown and start/stop behavior for each configured node

The basic test suite just makes sure that any configured nodes can be
initialized and shutdown repeatedly without hanging, crashing, etc.
"""

import wtfconfig
import time

class TestPower():

	def setUp(self):
		# start with all of the nodes powered down
		for n in wtfconfig.power:
			n.off()
			time.sleep(1)

	def test_init_shutdown(self):
		for n in wtfconfig.power:
			n.on()
			time.sleep(1)
			n.off()
			time.sleep(1)
			n.on()
			time.sleep(1)
			n.off()
