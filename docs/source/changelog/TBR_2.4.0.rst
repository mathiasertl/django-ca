###########
2.4.0 (TBR)
###########

************
Command-line
************

* **BACKWARDS INCOMPATIBLE:**  :command:`manage.py regenerate_ocsp_keys`: Removed the ``--key-type``,
  ``--key-size``, ``--elliptic-curve``, ``--profile``, ``algorithm`` and ``--expires`` parameters (deprecated
  since ``django-ca~=2.3.0``).
* **BACKWARDS INCOMPATIBLE:**  :command:`manage.py resign_cert`: Removed the ``--ca``, ``--subject``,
  ``--profile``, ``--algorithm``, ``--ocsp-responder``, ``--ca-issuer``, ``--policy-identifier``,
  ``--certification-practice-statement``, ``--user-notice``, ``--crl-full-name``,
  ``--issuer-alternative-name``, ``--extended-key-usage``, ``--key-usage``, ``--ocsp-no-check``,
  ``--subject-alternative-name`` and ``--tls-feature``, as well as all arguments to mark extensions as (not)
  critical (deprecated since ``django-ca~=2.3.0``).

  If you want to resign a certificate with other parameters, simply sign a new one with the same CSR.

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for ``pydantic~=2.10.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=3.2.0``, ``acme~=3.3.0`` and ``acme~=4.0.0``.
