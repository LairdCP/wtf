import requests
import logging
import time

class FailError(Exception):
	"""
	Exception raised when routines are called prior to initialization.
	"""
	pass

class PowerBase():
	"""
	A power control unit

	wtf needs a way to power devices on and off.  There's a ton of controllable power
	switches, so this is a base class for that.
	"""
	verbosity = 0
	name = ""
	def __init__(self):
		pass

	def on(self, delay=1, verbosity=None):
		"""
		Turn the device ON
		"""
		self._on()
		time.sleep(delay)

	def off(self, delay=1, verbosity=None):
		"""
		Turn the device OFF
		"""
		self._off()
		time.sleep(delay)

	def cycle(self, verbosity=None):
		"""
		Turn the device cycle the device if it's on
		"""
		self._cycle()

	def state(self):
		"""
		Query the state of the device
		"""
		return self._state()

class WebPowerSwitch(PowerBase):
	"""
	use a WebPowerSwtich from Digital Loggers Inc

	The console on the other end must at least be able to 'echo $?' so we can
	get the return code.
	"""
	def __init__(self, address, outlet=1, state=None, auth=('test', 'summit')):
		PowerBase.__init__(self)
		if self.verbosity >= 2:
			pass
		elif self.verbosity >= 1:
			logging.getLogger('urllib3').setLevel(logging.WARNING)
			logging.getLogger('requests').setLevel(logging.WARNING)
		else:
			logging.getLogger('urllib3').setLevel(logging.ERROR)
			logging.getLogger('requests').setLevel(logging.ERROR)

		self.address = address
		self.outlet = outlet
		self.auth = auth
		self.state = "unknown" # Don't care, we don't know what the initial state might be
		if state == None:
			pass
		elif state.lower() == "off":
			self._off()
		elif state.lower() == "on":
			self._on()

	def _off(self):
		r = self._switch("OFF")
		self.state = "off"

	def _on(self):
		r = self._switch("ON")
		self.state = "on"

	def _cycle(self):
		if self.state == "on":
			self._switch("CCL");

	def _switch(self, value):
		url = 'http://' + self.address + '/outlet?' + str(self.outlet) + "=" + value
		r = requests.request('GET', url, auth=self.auth)
		print "Turning " + value + " " + str(self.outlet) + ":",r.status_code
		if r.status_code != 200:
			raise FailError("Unable to connect: " + str(r.status_code))

	def _state(self):
		return self.state
