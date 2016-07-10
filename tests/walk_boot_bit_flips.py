"""
Test init/teardown and start/stop behavior for each configured node

The basic test suite just makes sure that any configured nodes can be
initialized and shutdown repeatedly without hanging, crashing, etc.
"""

import wtfconfig
import time
import random
import wtf.node as node

from pprint import pprint
import inspect

def setUp(self):
	# start with all of the nodes setup to be sure to boot from kernel and rootfs a
	# and then make sure we start from a power-off condition
	print "walk_boot_bit_flips doing setup"
	for n in wtfconfig.nodes:
		print "setup {}".format(n)
		n.shutdown()
		n.init_to_uboot()

NANDSetup = {
	'start': 0x20000,
	'size': 0x80000,
	'oob_size': 64,
	'page_size': 2048,
	'num_sectors': 4,
}

BUFFER_ADDR = 0x22000000


def is_erased(node, address, size, oob_size):
	is_allffs = True
	for i in range(oob_size):
		byte = node.uboot_mr(address+size+i)
		if( byte != 0xff ):
			is_allffs = False
			break
	return is_allffs

def find_byte(node, start_addr, limit):
	t = random.randrange(limit-1)
	byte = 0x00
	address = start_addr + t
	checked = 0
	while (checked < limit):
		byte = node.uboot_mr(address)
		if not (byte == 0x00):
			break;
		checked += 1
		address += 1
		if address >= start_addr + limit:
			address = start_addr
	print "        found good byte {:x} at {:x}".format(byte, address)
	return (byte, address)

def flip_bit(byte):
	print "        Flip bit on byte: {:x}".format(byte)
	for i in range(8):
		if byte & (0x1 << i) :
			byte &= ~(0x1 << i)
			break
	print "           to byte {:x}".format(byte)
	return byte

class TestWalkBootBitflips():

	def test_uboot_update(self):
		print "\n====================================================================="
		runNum = 0
		testFail = 0
		random.seed(127)
		sector_size = NANDSetup['page_size'] / NANDSetup['num_sectors']
		# Setup should have already ensured we're rebooted to the uboot prompt.

		# First, flip bits in all pages on all nodes
		for page in range(NANDSetup['start'], NANDSetup['start']+NANDSetup['size'], NANDSetup['page_size']):
			print " page: {:x}".format( page )
			for n in wtfconfig.nodes:
				try:
					n.uboot_nand_readraw(page, BUFFER_ADDR)
					if( is_erased(n, BUFFER_ADDR, NANDSetup['page_size'], NANDSetup['oob_size']) ):
						print "    page is erased"
						continue
					for sector in range(NANDSetup['num_sectors']):
						print "    sector: {}".format(sector);
						(byte, found_address) = find_byte(n, BUFFER_ADDR+(sector*sector_size), sector_size)
						if byte == 0x00:
							# problem, all bytes in sector are 0, so we just need to skip this sector
							print "    All bytes in page {} sector {} are zero, skipping".format(page, sector)
							continue
						byte = flip_bit(byte)
						n.uboot_mw(found_address, byte)
					n.uboot_nand_writeraw(page, BUFFER_ADDR)

				except KeyboardInterrupt:
					print "User requested exit, done"
					exit()

		# Second, validate by rebooting
		for n in wtfconfig.nodes:
			try:
				time.sleep(1)
				n.shutdown()
				n.init_to_uboot()
			except KeyboardInterrupt:
				print "User requested exit, done"
				exit()
