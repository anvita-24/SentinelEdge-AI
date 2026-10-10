# SentinelEdge runbooks

## credential_attack
Repeated failed authentication against a device indicates brute force or credential stuffing. Confirm failed_auth spikes and source IPs in auth events. Rotate device credentials immediately; isolate the device if attempts persist or originate from outside the site network. Rotation and isolation are critical actions requiring admin approval.

## data_exfiltration
Outbound bytes far above the device-type baseline suggest data theft or a compromised device acting as a relay. Isolate the device from the network, rotate credentials, and review the destination of outbound traffic. Check other devices of the same type and site for the same pattern.

## message_flood
Message rate far above baseline with elevated CPU indicates a spoofed or misbehaving publisher flooding the MQTT broker. Throttle telemetry on the device first; isolate if the flood continues. Verify the device identity and firmware hash.

## cpu_hijack
Sustained CPU spike together with rising temperature and extra outbound traffic is consistent with cryptomining malware or a runaway process. Isolate the device, then roll back firmware to the last known-good version and restart after approval.

## overheating
Temperature well above baseline with only mild CPU increase points to a hardware or cooling fault rather than an attack. Throttle telemetry to reduce load, restart the device, and schedule an on-site inspection if it recurs.

## signal_interference
Sharp RSSI drop with collapsing message rate indicates radio jamming, an obstructed antenna or a failing radio. Restart the device; if it recurs across devices at one site, escalate as possible RF jamming.

## battery_drain
Battery level dropping much faster than baseline suggests a firmware bug, excess transmissions or tampering. Throttle telemetry to extend runtime and schedule replacement or firmware review.

## memory_leak
Steadily rising memory with moderate CPU growth indicates a software leak. Restart the device to recover and roll back firmware if the leak returns after restart.

## unknown_anomaly
The pattern matches no known runbook. Throttle telemetry, collect more data, and escalate to an operator for manual review.
