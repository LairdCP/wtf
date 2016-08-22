import wtf.node as node
import re, sys
import wtf.power
import time

class WBBase(node.NodeBase):
	"""
	client STA

	This represents the platform-independent client STA that should be used by tests.

	Real STAs should extend this class and implement the actual STA functions.
	"""

	def __init__(self, comm):
		"""
		Create an STA with the supplied comm channel.
		"""
		node.NodeBase.__init__(self, comm=comm)

	def scan(self):
		"""
		scan for wireless networks

		Return a list of APConfigs representing the APs in the neighborhood.
		"""
		raise node.UnimplementedError("scan not implemented!")

class WB45(WBBase):
	"""
	Represent WB unit
	"""

	def __init__(self, comm, driver, iface, power = None, dcal = None):
		self.driver = driver
		self.iface = iface
		self.power = power
		self.dcal = dcal
		self.loggedIn = False
		self.uboot = False
		self.initialized = False
		self.verbosity = 1
		self.name = "WBBase"
		WBBase.__init__(self, comm)

	def debug(self, s, level=1):
		if level < self.verbosity:
			print self.name + "- " + s

	def init(self):
		if self.power is not None:
			self.power.on();
		(r, output) = self.comm.wait_for('summit login:')
		if r == 1:
			raise node.ActionFailureError('Unable to find login prompt')
		self.initialized = True

	def init_to_uboot(self):
		if self.power is not None:
			self.power.on();
		(r, output) = self.comm.wait_for('Hit any key to stop autoboot')
		if r == 1:
			raise node.ActionFailureError('Unable to find autoboot prompt')
		self.comm._send_cmd('','U-Boot> ')
		self.debug("In uboot")
		self.uboot = True


	def init_and_login(self):
		self.init()
		self.login()

	def shutdown(self):
		if self.power is not None:
			self.power.off();
		self.initialized = False
		self.loggedIn = False

	def login(self):
		if self.initialized != True:
			raise node.UninitializedError('Not initialized')
		(r, o) = self.comm._send_cmd('','summit login: ')
		if len(o) <= 0:
			raise node.ActionFailureError('Unable to find login prompt')
		self.comm._send_cmd('root','Password: ')
		self._cmd_or_die('summit')
		self.loggedIn = True

	def checkfs(self):
		if self.loggedIn != True:
			raise node.UninitializedError('Not logged in')
		(r, o) = self.comm.send_cmd('find / -name \\* -type f -print -xdev -exec cat \'{}\' >/dev/null \\;')
		if r != 0:
			output = ""
			for l in o:
				output += "{}\n".format(l)
			raise node.ActionFailureError("Failed to \"find\" r= {} o: \n".format(r) + output)
		matching = [s for s in o if "UBIFS error" in s]
		if len(matching) > 0:
			output = ""
			for l in o:
				output += "{}\n".format(l)
			raise node.VerificationError("Found " + str(len(matching)) + " UBIFS errors: \n" +  output)

	def check_wlan0_exist(self):
		if self.loggedIn != True:
			raise node.UninitializedError('Not logged in')
		time.sleep(5)
		(r, o) = self.comm.send_cmd('ifconfig -a | grep wlan0')
		if r != 0:
			output = ""
			for l in o:
				output += "{}\n".format(l)
			raise node.VerificationError("wlan0 not found\n")

	def fw_update(self, url):
		if self.loggedIn != True:
			raise node.UninitializedError('Not logged in')
		o = self._cmd_or_die('fw_update -xntr -f ' + url)

	def fw_update_tm(self, state):
		if self.loggedIn != True:
			raise node.UninitializedError('Not logged in')
		if state == True:
			o = self._cmd_or_die('touch /etc/default/fw_update.test')
		elif state == False:
			o = self._cmd_or_die('rm /etc/default/fw_update.test')
		else:
			raise node.ActionFailureError("Unknown state entered: " + str(state))

	def wait_check(self, cmd):
		if self.loggedIn != True:
			raise node.UninitializedError('Not logged in')
		for t in range(10):
			(r, o) = self.comm.send_cmd(cmd)
			if r == 0:
				break
			self.debug("Wait check; t={}".format(t))
			time.sleep(1)
		else:
			raise node.ActionFailureError("Timed out waiting on \"" + cmd + "\"")

	def reboot(self):
		if self.loggedIn != True:
			raise node.UninitializedError('Not logged in')
		(r, o) = self.comm._send_cmd('reboot', 'summit login: ')
		if len(o) <= 0:
			raise node.ActionFailureError("Failed to find login prompt after reboot")
		self.loggedIn = False

	def init_wifi(self):
		self._cmd_or_die("modprobe " + self.driver)

	def shutdown_wifi(self):
		self.stop()
		self._cmd_or_die("modprobe -r " + self.driver)

	def uboot_flash(self):
		if self.uboot != True:
			raise node.UninitializedError("Not in uboot prompt")
		self._cmd_uboot_or_die('dhcp && set serverip 192.168.0.18')
		self._cmd_uboot_or_die('nand erase 0x000e0000 0x00280000')
		self._cmd_uboot_or_die('tftp kernel.bin && nand write 0x22000000 0x000e0000 ${filesize}')
		self._cmd_uboot_or_die('tftp rootfs.bin && nand erase 0x005e0000 0x02600000')
		self._cmd_uboot_or_die('nand write.trimffs 0x22000000 0x005e0000 ${filesize}')

	def uboot_set_boot_a(self):
		if self.uboot != True:
			raise node.UninitializedError("Not in uboot prompt")
		self._cmd_uboot_or_die("setenv bootargs 'console=ttyS0,115200 loglevel=4 rw noinitrd mem=64M rootfstype=ubifs root=ubi0:rootfs ubi.mtd=6'")
		self._cmd_uboot_or_die("setenv bootcmd 'nand read 0x22000000 0x000E0000 0x00280000; run _mtd; bootm'")
		self._cmd_uboot_or_die('saveenv')

	def uboot_boot(self):
		(r, output) = self.comm._send_cmd('boot', 'summit login: ')
		self.initialized = True

	def uboot_nand_readraw(self, page, buff_address):
		if self.uboot != True:
			raise node.UninitializedError("Not in uboot prompt")
		self._cmd_uboot_or_die("nand read.raw 0x{:x} 0x{:x} 1".format(buff_address, page))

	def uboot_nand_writeraw(self, page, buff_address):
		if self.uboot != True:
			raise node.UninitializedError("Not in uboot prompt")
		self._cmd_uboot_or_die("nand write.raw 0x{:x} 0x{:x} 1".format(buff_address, page))

	def uboot_mr(self, address, length='b'):
		if self.uboot != True:
			raise node.UninitializedError("Not in uboot prompt")
		o = self._cmd_uboot_or_die("md.{} 0x{:x} 1".format(length, address))
		vals = o[0].split(' ')
		return int(vals[1], 16)

	def uboot_mw(self, address, byte, length='b'):
		if self.uboot != True:
			raise node.UninitializedError("Not in uboot prompt")
		self._cmd_uboot_or_die("mw.{} 0x{:x} 0x{:x}".format(length, address, byte))

	def _cmd_uboot_or_die(self, cmd, verbosity=None, prompt='U-Boot> '):
		if verbosity == None:
			verbosity = self.comm.verbosity
		elif verbosity > self.comm.verbosity:
			verbosity = self.comm.verbosity
		if verbosity > 0:
			print self.comm.name + ": " + cmd
		(r, o) = self.comm._send_cmd(cmd, prompt)
		if verbosity > 1:
			for l in o:
				print self.name + ": " + l
		if r != 0:
			raise node.ActionFailureError("Failed to \"" + cmd + "\"")
		return o

	#######################################################################
	## User-space validations

	def check_log(self, pattern):
		if self.loggedIn != True:
			raise node.UninitializedError('Not logged in')
		self._cmd_or_die('logread | grep \'' + pattern + "'")
