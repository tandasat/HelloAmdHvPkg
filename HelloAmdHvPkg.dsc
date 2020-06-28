[Defines]
  DSC_SPECIFICATION              = 1.28
  PLATFORM_NAME                  = HelloAmdHvPkg
  PLATFORM_GUID                  = 192d6442-1dbd-4cc0-86f8-cf5fbf7a802d
  PLATFORM_VERSION               = 1.00
  OUTPUT_DIRECTORY               = Build/HelloAmdHvPkg
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT

[Components]
  HelloAmdHvPkg/Applications/LogDump/LogDump.inf
  HelloAmdHvPkg/Drivers/HelloAmdHvDxe/HelloAmdHvDxe.inf

[LibraryClasses]
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiCpuLib|UefiCpuPkg/Library/BaseUefiCpuLib/BaseUefiCpuLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiRuntimeLib|MdePkg/Library/UefiRuntimeLib/UefiRuntimeLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsicSev.inf
  LocalApicLib|UefiCpuPkg/Library/BaseXApicX2ApicLib/BaseXApicX2ApicLib.inf
  TimerLib|MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  !if $(TARGET) == RELEASE
    DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  !else
    !ifdef $(DEBUG_ON_SERIAL_PORT)
      SerialPortLib|PcAtChipsetPkg/Library/SerialIoLib/SerialIoLib.inf
      DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
    !else
      DebugLib|MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
    !endif
  !endif

[LibraryClasses.common.DXE_RUNTIME_DRIVER]
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf

[LibraryClasses.common.UEFI_APPLICATION]
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf

[PcdsFixedAtBuild]
  # Enable EDK2 debug features based on the TARGET configuration.
  # https://github.com/tianocore/tianocore.github.io/wiki/EDK-II-Debugging
  !if $(TARGET) == RELEASE
    # No debug code such as DEBUG() / ASSERT(). They will be removed.
    gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x0
    gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x0
  !else
    # Define DEBUG_ERROR | DEBUG_VERBOSE | DEBUG_INFO | DEBUG_WARN to enable
    # logging at those levels. Also, define DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED
    # and such. Assertion failure will call CpuDeadLoop.
    gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80400042
    gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x2f
  !endif
