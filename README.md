libbtbb
=======

This is the Bluetooth baseband decoding library, forked from the GR-Bluetooth 
project.  It can be used to extract Bluetooth packet and piconet information 
from Ubertooth devices as well as GR-Bluetooth/USRP.

This code is incomplete, it is still under active development.  Patches and 
bug reports should be submitted to the bug tracker on SurceForge:
http://sourceforge.net/p/libbtbb/tickets/

This software has been developed and tested on Linux, it should work on other 
platforms but this has yet to be tested.


Build Instructions
==================

Libbtbb can be built and installed as follows:
    $ mkdir build
    $ cd build
    $ cmake ..
    $ make
    $ make install

This will install the library to /usr/local/lib and the headers to 
/usr/local/include, to install to different locations use:
    $ cmake -DINSTALL_DIR=/path/to/install -DINCLUDE_DIR=/path/to/include ..

