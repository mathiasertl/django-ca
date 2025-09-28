###########
2.5.0 (TBR)
###########

********
REST API
********

* The deprecated endpoint `/ca/{ca_serial}/revoke/{certificate_serial}/` for revoking certificates was
  removed (deprecated since ``django-ca==2.3.0``). Use `/ca/{ca_serial}/certs/{certificate_serial}/revoke/`
  instead.