If you want to run docker(-compose) as a regular user, you need to add your user to the ``docker`` group and
log in again:

.. code-block:: console

   user@host:~$ sudo adduser `id -un` docker
   user@host:~$ sudo su `id -un`
