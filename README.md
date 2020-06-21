HelloAmdHvPkg
==============

HelloAmdHvPkg is a type-1 research hypervisor for AMD processors. The hope is to help researchers learn implementation required for the operating system start up under AMD-V (SVM: Secure Virtual Machine).

A demo clip can be found on [Youtube](https://youtu.be/20RVwcbKf-s).

System Requirements
--------------------

- AMD-V (SVM) supported processors
- 64bit UEFI-based, xAPIC system
- Tested against Windows 10 and Ubuntu to boot

Tested on few baremetal and VMware. No other virtualization software is tested and supported.

Building
---------

1. Set up edk2 build environment
2. Copy `HelloAmdHvPkg` as `edk2\HelloAmdHvPkg`
3. On the edk2 build command prompt, run the below command:
    ```
    > edksetup.bat
    > build -t VS2019 -a X64 -b NOOPT -p HelloAmdHvPkg\HelloAmdHvPkg.dsc
    ```

Also, pre-compiled binary file is available at the Release page.

Resources
----------

- [uber eXtensible Micro-Hypervisor Framework](https://github.com/uberspark/uberxmhf)
- [Bitvisor](https://github.com/matsu/bitvisor)
