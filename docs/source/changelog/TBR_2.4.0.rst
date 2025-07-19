###########
2.4.0 (TBR)
###########

************
Command-line
************

* **BACKWARDS INCOMPATIBLE:**  :command:`manage.py regenerate_ocsp_keys`: Removed the ``--key-type``,
  ``--key-size``, ``--elliptic-curve``, ``--profile``, ``algorithm`` and ``--expires`` parameters (deprecated
  in 2.3.0).

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for ``pydantic~=2.10.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=3.2.0``, ``acme~=3.3.0`` and ``acme~=4.0.0``.
