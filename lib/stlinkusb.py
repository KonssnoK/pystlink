import usb.core
import usb.util
from . import stlinkex #Use relative import
import time

class StlinkUsbConnector():
    STLINK_CMD_SIZE_V2 = 16

    DEV_TYPES = [
        {
            'version': 'V2',
            'idVendor': 0x0483,
            'idProduct': 0x3748,
            'outPipe': 0x02,
            'inPipe': 0x81,
        }, {
            'version': 'V2-1',
            'idVendor': 0x0483,
            'idProduct': 0x374b,
            'outPipe': 0x01,
            'inPipe': 0x81,
        }
    ]

    def __init__(self, dbg=None, address=None):
        self._dbg = dbg
        self._dev_type = None
        self._xfer_counter = 0
        devices = usb.core.find(find_all=True)
        for dev in devices:
            for dev_type in StlinkUsbConnector.DEV_TYPES:
                if dev.idVendor == dev_type['idVendor'] and dev.idProduct == dev_type['idProduct']:
                    if address:
                        if str(dev.address) != address:
                            self._dbg.verbose("Skipping ST-Link at address %s, searching %s"%(dev.address, address))
                            continue
                    self._dev = dev
                    self._dev_type = dev_type
                    self._dbg.verbose("Successfully connected to ST-Link/%s" % dev_type['version'])
                    return
        raise stlinkex.StlinkException('ST-Link/V2 is not connected')

    @property
    def version(self):
        return self._dev_type['version']

    @property
    def xfer_counter(self):
        return self._xfer_counter

    def _write(self, data, tout=200):
        self._dbg.debug("  USB > %s" % ' '.join(['%02x' % i for i in data]))
        self._xfer_counter += 1
        count = self._dev.write(self._dev_type['outPipe'], data, tout)
        if count != len(data):
            raise stlinkex.StlinkException("Error, only %d Bytes was transmitted to ST-Link instead of expected %d" % (count, len(data)))

    def _read(self, size, tout=200):
        read_size = size
        if read_size < 64:
            read_size = 64
        elif read_size % 4:
            read_size += 3
            read_size &= 0xffc
        data = self._dev.read(self._dev_type['inPipe'], read_size, tout).tolist()
        self._dbg.debug("  USB < %s" % ' '.join(['%02x' % i for i in data]))
        return data[:size]

    def xfer(self, cmd, data=None, rx_len=None, retry=3, tout=200):
        prev = ""
        while (True):
            try:
                if len(cmd) > self.STLINK_CMD_SIZE_V2:
                    raise stlinkex.StlinkException("Error too many Bytes in command: %d, maximum is %d" % (len(cmd), self.STLINK_CMD_SIZE_V2))
                # pad to 16 bytes
                cmd += [0] * (self.STLINK_CMD_SIZE_V2 - len(cmd))
                self._write(cmd, tout)
                if data:
                    self._write(data, tout)
                #We wait 1ms to ensure a slow USB channel finished writing on the bus.
                #Without this errors like reading 0 instead of real value of the register could occur.
                time.sleep(0.001)
                if rx_len:
                    return self._read(rx_len)
            except usb.core.USBError as e:
                if retry:
                    if ("reaping" in e.strerror) or ("timeout" in e.strerror):
                        self._dbg.info("Error in LibUSB. Trying to recover it...")
                        self._dev.reset()
                        time.sleep(1)
                    prev += str(e) #Store the first occurred error, which is the most meaningful
                    retry -= 1
                    continue
                raise stlinkex.StlinkException("USB Error: %s\n Previous:\n%s" % (e, prev))
            return None

    def unmount_discovery(self):
        import platform
        if platform.system() != 'Darwin' or self.version != 'V2-1':
            return
        import subprocess
        p = subprocess.Popen(
            ['diskutil', 'info', 'DISCOVERY'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        p.wait()
        out, err = p.communicate()
        out = out.decode(encoding='UTF-8').strip()
        is_mounted = False
        is_mbed = False
        for line in out.splitlines():
            param = line.split(':', 1)
            if param[0].strip() == 'Mounted' and param[1].strip() == 'Yes':
                is_mounted = True
            if param[0].strip() == 'Device / Media Name' and param[1].strip().startswith('MBED'):
                is_mbed = True
        if is_mounted and is_mbed:
            print("unmounting DISCOVERY")
            p = subprocess.Popen(
                ['diskutil', 'unmount', 'DISCOVERY'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p.wait()

    def dispose(self):
        """ Dispose the device and detach from libusb
        """
        if self._dev:
            self._dev._finalize_object()