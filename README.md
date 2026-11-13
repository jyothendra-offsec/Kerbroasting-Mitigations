# Kerberoasting and AS-REP Roasting Lab

A lab case study on weak service-account passwords, accounts without Kerberos preauthentication, and directory permissions that can expand exposure. The [technical report](report.md) records the observations. Lab ticket material is omitted from the current report.

| Finding | Remediation to evaluate | Retest |
| --- | --- | --- |
| Weak service-account passwords | Use managed service accounts where supported. Rotate weak secrets and restrict account privileges. | Confirm the service still operates and the retired credential no longer authenticates. |
| Preauthentication disabled | Require Kerberos preauthentication except for documented exceptions. | Confirm affected accounts require preauthentication after the change. |
| Broad write access over an account | Review the effective ACL and remove delegation that the service does not need. | Verify the same low-privilege principal no longer has the write access. |

Use ticket-request telemetry and directory change logs to support the investigation. A ticket request by itself does not establish that a password was recovered. Confirm any authentication claim with separate evidence from the authorized lab.
