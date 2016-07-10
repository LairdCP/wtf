import wtf.node.ap
import wtf.node.sta
import wtf.node.wb
import wtf.comm
import wtf.power

# create AP configurations that match the APs in your vicinity
# ap_serial = wtf.comm.Serial(port="/dev/ttyUSB1",
#							  prompt="[root@localhost dev]# ")
# ap_serial.name = "AP"
# ap_serial.verbosity = 1
# ap = wtf.node.ap.Hostapd(ap_serial, "libertas_tf_sdio", "wlan0")

sta_serial = wtf.comm.Serial(port="/dev/ttyUSB0",
							 prompt="# ")
sta_power = wtf.power.WebPowerSwitch('192.168.0.50', 4)
sta_serial.name = "WB45-D"
# Verbosity 0 for nothing, 1 output commands, 2 both commands and returned text
sta_serial.verbosity = 2
sta = wtf.node.wb.WB45(sta_serial, "ath6kl_sdio", "wlan0", sta_power)
sta.verbosity = 0
sta.name = "WB45-D"

# tell wtf about all of your nodes
nodes = [ sta ]

# tell wtf which test suites you want to run
suites = [ "walk_boot_bit_flips" ]
