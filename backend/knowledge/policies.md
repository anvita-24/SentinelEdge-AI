# Operations policy

## approval_policy
Critical actions (isolate_device, rotate_credentials, firmware_rollback) require approval from an admin who is different from the requester (two-person rule). Non-critical actions (throttle_telemetry, restart_device) may be executed by operators directly. Every command is HMAC-signed and recorded in the append-only audit log.

## escalation
Three or more devices showing the same anomaly category within 24 hours is treated as a coordinated or fleet-wide event and must be escalated to the security on-call.
