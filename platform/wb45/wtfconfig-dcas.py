import wtf.node.ap
import wtf.node.sta
import wtf.node.wb
import wtf.comm
import wtf.power
import wtf.dcal

# create AP configurations that match the APs in your vicinity
# ap_serial = wtf.comm.Serial(port="/dev/ttyUSB1",
#							  prompt="[root@localhost dev]# ")
# ap_serial.name = "AP"
# ap_serial.verbosity = 1
# ap = wtf.node.ap.Hostapd(ap_serial, "libertas_tf_sdio", "wlan0")

sta_power = wtf.power.WebPowerSwitch('192.168.0.50', 6)

sta_serial = wtf.comm.Serial(port="/dev/ttyUSB5", prompt="# ")
sta_serial.name = "WB45-2"
sta_serial.verbosity = 4

dcal = wtf.dcal.Dcal( "192.168.0.66" )

sta = wtf.node.wb.WB45(sta_serial, "ath6kl_sdio", "wlan0", sta_power, dcal)

# tell wtf about all of your nodes
nodes = [ sta ]

# tell wtf which test suites you want to run
suites = [ "dcas" ]
