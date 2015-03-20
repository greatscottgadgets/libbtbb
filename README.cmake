CMake Settings
==============
The following are flags that may be of use when configuing this project.

 * DISABLE_PYTHON
  * A boolean flag for building and installing btaptap python tool.

 * USE_PCAP
  * USE_PCAP=ON - Build with pcap support, the build will fail if
    libpcap is not found.
  * USE_PCAP=OFF - Disable pcap support will be disabled.
  * If left undefined pcap support will be enabled if libpcap is present.
