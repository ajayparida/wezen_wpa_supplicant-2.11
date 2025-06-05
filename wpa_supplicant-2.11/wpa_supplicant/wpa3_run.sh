./wpa_cli -i wlan0 remove_network 0
sleep 2
./wpa_cli -i wlan0 add_network 0
sleep 5
./wpa_cli -i wlan0 set_network 0 ssid '"TPLINK_UMAC_6G"'
sleep 2
./wpa_cli -i wlan0 set_network 0 bssid C2:2F:D0:D1:7A:B1
sleep 2
./wpa_cli -i wlan0 set_network 0 key_mgmt SAE
sleep 2
./wpa_cli -i wlan0 set_network 0 sae_password '"12345678"'
sleep 2
./wpa_cli -i wlan0 set_network 0 ieee80211w 2
sleep 2
./wpa_cli -i wlan0 set_network 0 scan_ssid 1
sleep 2
./wpa_cli -i wlan0 enable_network 0
sleep 2
./wpa_cli -i wlan0 select_network 0

