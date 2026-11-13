# Kerberos Exposure Assessment

The authorized training exercise examined service-account ticket exposure, disabled Kerberos preauthentication, and write access delegated over another directory account.

| Observation | What the exercise established | What to retest |
| --- | --- | --- |
| Service-account tickets | Weak credentials were recoverable from tickets in the lab | Rotate the credential and repeat the controlled validation |
| Directory delegation | A low-privilege identity had a write relationship to another account | Confirm the effective ACL after removing the unnecessary delegation |
| Preauthentication | One lab account permitted an authentication response without preauthentication | Verify the corrected account policy and documented exceptions |

Separate discovery, password recovery, authentication, and privilege in the evidence log. Record the principal, target, timestamps, and relevant directory or authentication events for each claim. Keep original lab artifacts in a private evidence store.

This public report summarizes the lab observations. The current files omit credential values and ticket material. Earlier revisions and screenshots require separate review.
