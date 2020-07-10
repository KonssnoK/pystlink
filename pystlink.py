import sys
import argparse
import time
import lib.stlinkusb
import lib.stlinkv2
import lib.stm32
import lib.stm32fp
import lib.stm32fs
import lib.stm32l0
import lib.stm32l4
import lib.stm32h7
import lib.stm32devices
import lib.stlinkex
import lib.dbg
import lib.srec

VERSION_STR = "pystlink v0.0.0 (ST-LinkV2)"

DESCRIPTION_STR = VERSION_STR + """
(c)2015 by pavel.revak@gmail.com
https://github.com/pavelrevak/pystlink
"""

ACTIONS_HELP_STR = """
list of available actions:
  dump:core              print all core registers (halt core)
  dump:{reg}             print core register (halt core)
  dump:{addr}:{size}     print content of memory
  dump:sram[:{size}]     print content of SRAM memory
  dump:flash[:{size}]    print content of FLASH memory
  dump:{addr}            print content of 32 bit memory register
  dump16:{addr}          print content of 16 bit memory register
  dump8:{addr}           print content of 8 bit memory register

  set:{reg}:{data}     set register (halt core)
  set:{addr}:{data}    set 32 bit memory register
  set:flash:{addr}:{data}    set 32 bit flash memory (works only on erased memory or writing 0)

  read:{addr}:{size}:{file}      read memory with size into file
  read:sram[:{size}]:{file}      read SRAM into file
  read:flash[:{size}]:{file}     read FLASH into file

  fill:{addr}:{size}:{pattern}   fill memory with a pattern
  fill:sram[:{size}]:{pattern}   fill SRAM memory with a pattern

  write:{file.srec}     write SREC file into memory
  write:{addr}:{file}   write binary file into memory
  write:sram:{file}     write binary file into SRAM memory

  flash:erase            complete erase FLASH memory aka mass erase
  flash[:erase][:verify]:{file.srec}     erase + flash SREC file + verify
  flash[:erase][:verify][:{addr}]:{file} erase + flash binary file + verify
  flash:check:{file.srec}     verify flash against SREC file
  flash:check[:{addr}]:{file} verify flash {at addr} against binary file

  reset                  reset core
  reset:halt             reset and halt core
  halt                   halt core
  step                   step core
  run                    run core

  sleep:{seconds}        sleep (float) - insert delay between commands

  (numerical values can be in different formats, like: 42, 0x2a, 0o52, 0b101010)

examples:
  pystlink.py --help
  pystlink.py -v --cpu STM32F051R8
  pystlink.py -q --cpu STM32F03 dump:flash dump:sram
  pystlink.py dump:0x08000000:256
  pystlink.py set:0x48000018:0x00000100 dump:0x48000014
  pystlink.py read:sram:256:aaa.bin read:flash:bbb.bin
  pystlink.py -r reset:halt set:pc:0x20000010 dump:pc core:step dump:all
  pystlink.py flash:erase:verify:app.bin
  pystlink.py flash:erase flash:verify:0x08010000:boot.bin
  pystlink.py -n 2
  pystlink.py -s
"""


class PyStlink():
    CPUID_REG = 0xe000ed00

    def __init__(self):
        self._start_time = time.time()
        self._connector = None
        self._stlink = None
        self._driver = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._connector:
            self._connector.dispose()

    def find_mcus_by_core(self):
        if (self._hard):
            self._core.core_hard_reset_halt()
        else:
            self._core.core_halt()

        parts = set([]) #Store all the part_no we find while waiting
        i = 0
        while True:
            cpuid = self._stlink.get_debugreg32(PyStlink.CPUID_REG)
            if cpuid == 0:
                if i == 100:
                    raise stlib.stlinkex.StlinkException('Not connected to CPU')
                else:
                    time.sleep(0.1)
                    i+=1
                    continue

            partno = 0xfff & (cpuid >> 4)
            for mcu_core in stlib.stm32devices.DEVICES:
                if mcu_core['part_no'] == partno:
                    self._dbg.verbose("CPUID:  %08x" % cpuid)
                    self._mcus_by_core = mcu_core
                    if i > 0:
                        self._dbg.warning("CPUID: found after %d0ms. PART_NO: %s"%(i, str(parts)))
                    return

            #We loop only if we didn't find anything
            parts.add(partno)
            time.sleep(0.01)
            i+=1

            #But we can't loop forever
            if i == 10000:
                self._dbg.verbose("CPUID:  %08x" % cpuid)
                raise stlib.stlinkex.StlinkException('PART_NO: timeout while trying to read from device with PART_NO: %s'%(str(parts)))

                return


    def find_mcus_by_devid(self):
        # STM32H7 hack: this MCU has ID-CODE on different address than STM32F7
        i = 0
        while True:
            devid = 0x000
            idcode_regs = self._mcus_by_core['idcode_reg']
            if isinstance(self._mcus_by_core['idcode_reg'], int):
                idcode_regs = [idcode_regs]
            for idcode_reg in idcode_regs:
                idcode = self._stlink.get_debugreg32(idcode_reg)
                devid = 0xfff & idcode
                for mcu_devid in self._mcus_by_core['devices']:
                    if mcu_devid['dev_id'] == devid:
                        self._dbg.verbose("IDCODE: %08x" % idcode)
                        self._mcus_by_devid = mcu_devid
                        if i > 0:
                            self._dbg.warning("DEV_ID: found after %d0ms" % i)
                        return
            #We loop only if we didn't find anything
            time.sleep(0.01)
            i += 1

            #But we can't loop forever
            if i >= 1000:
                self._dbg.verbose("IDCODE: %08x" % idcode)
                raise stlib.stlinkex.StlinkException('DEV_ID: 0x%03x is not supported' % devid)
                    return

    def find_mcus_by_flash_size(self):
        i = 0
        while True:
            self._flash_size = self._stlink.get_debugreg16(self._mcus_by_devid['flash_size_reg'])
            self._mcus = []
            for mcu in self._mcus_by_devid['devices']:
                if mcu['flash_size'] == self._flash_size:
                    self._mcus.append(mcu)
                    if i > 0:
                        self._dbg.warning("FLASH_SIZE found after %d0ms." % i)

            if self._mcus:
                return

            #We loop only if we didn't find anything
            time.sleep(0.01)
            i += 1

            #But we can't loop forever
            if i >= 1000:
                raise stlib.stlinkex.StlinkException('Connected CPU with DEV_ID: 0x%03x and FLASH size: %dKB is not supported. Check Protection' % (
                    self._mcus_by_devid['dev_id'], self._flash_size
                ))

        return

    def fix_cpu_type(self, cpu_type):
        cpu_type = cpu_type.upper()
        # now support only STM32
        if cpu_type.startswith('STM32'):
            # change character on 10 position to 'x' where is package size code
            if len(cpu_type) > 9:
                cpu_type = list(cpu_type)
                cpu_type[9] = 'x'
                cpu_type = ''.join(cpu_type)
            return cpu_type
        raise lib.stlinkex.StlinkException('"%s" is not STM32 family' % cpu_type)

    def filter_detected_cpu(self, expected_cpus):
        cpus = []
        for detected_cpu in self._mcus:
            for expected_cpu in expected_cpus:
                expected_cpu = self.fix_cpu_type(expected_cpu)
                if detected_cpu['type'].startswith(expected_cpu):
                    cpus.append(detected_cpu)
                    break
        if not cpus:
            raise lib.stlinkex.StlinkException('Connected CPU is not %s but detected is %s %s' % (
                ','.join(expected_cpus),
                'one of' if len(self._mcus) > 1 else '',
                ','.join([cpu['type'] for cpu in self._mcus]),
            ))
        self._mcus = cpus

    def find_sram_eeprom_size(self):
        # if is found more MCUS, then SRAM and EEPROM size
        # will be used the smallest of all (worst case)
        self._sram_size = min([mcu['sram_size'] for mcu in self._mcus])
        self._eeprom_size = min([mcu['eeprom_size'] for mcu in self._mcus])
        self._dbg.info("SRAM:   %dKB" % self._sram_size)
        if self._eeprom_size:
            self._dbg.info("EEPROM: %dKB" % self._eeprom_size)
        if len(self._mcus) > 1:
            diff = False
            if self._sram_size != max([mcu['sram_size'] for mcu in self._mcus]):
                diff = True
                self._dbg.warning("Detected CPUs have different SRAM sizes.")
            if self._eeprom_size != max([mcu['eeprom_size'] for mcu in self._mcus]):
                diff = True
                self._dbg.warning("Detected CPUs have different EEPROM sizes.")
            if diff:
                self._dbg.warning("Is recommended to select certain CPU with --cpu {cputype}. Now is used the smallest memory size.")

    def load_driver(self):
        flash_driver = self._mcus_by_devid['flash_driver']
        if flash_driver == 'STM32FP':
            self._driver = lib.stm32fp.Stm32FP(self._stlink, dbg=self._dbg)
        elif flash_driver == 'STM32FPXL':
            self._driver = lib.stm32fp.Stm32FPXL(self._stlink, dbg=self._dbg)
        elif flash_driver == 'STM32FS':
            self._driver = lib.stm32fs.Stm32FS(self._stlink, dbg=self._dbg)
        elif flash_driver == 'STM32L0':
            self._driver = lib.stm32l0.Stm32L0(self._stlink, dbg=self._dbg)
        elif flash_driver == 'STM32L4':
            self._driver = lib.stm32l4.Stm32L4(self._stlink, dbg=self._dbg)
        elif flash_driver == 'STM32H7':
            self._driver = lib.stm32h7.Stm32H7(self._stlink, dbg=self._dbg)
        else:
            self._driver = self._core

    def detect_cpu(self, expected_cpus, unmount=False):
        self._connector = lib.stlinkusb.StlinkUsbConnector(dbg=self._dbg, serial=self._serial, index = self._index)
        if unmount:
            self._connector.unmount_discovery()
        self._stlink = lib.stlinkv2.Stlink(self._connector, dbg=self._dbg)
        self._dbg.info("DEVICE: ST-Link/%s" % self._stlink.ver_str)
        self._dbg.info("SUPPLY: %.2fV" % self._stlink.target_voltage)
        self._dbg.verbose("COREID: %08x" % self._stlink.coreid)
        if self._stlink.coreid == 0:
            raise lib.stlinkex.StlinkException('Not connected to CPU')
        self._core = lib.stm32.Stm32(self._stlink, dbg=self._dbg)
        self.find_mcus_by_core()
        self._dbg.info("CORE:   %s" % self._mcus_by_core['core'])
        self.find_mcus_by_devid()
        self.find_mcus_by_flash_size()
        if expected_cpus:
            # filter detected MCUs by selected MCU type
            self.filter_detected_cpu(expected_cpus)
        self._dbg.info("MCU:    %s" % '/'.join([mcu['type'] for mcu in self._mcus]))
        self._dbg.info("FLASH:  %dKB" % self._flash_size)
        self.find_sram_eeprom_size()
        self.load_driver()

    def print_buffer(self, addr, data, bytes_per_line=16):
        #When used as a library the buffer is returned directly to the caller, no need to dump it
        if self._dbg.is_library_quiet():
            return

        prev_chunk = []
        same_chunk = False
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            if prev_chunk != chunk:
                print('%08x  %s%s  %s' % (
                    addr,
                    ' '.join(['%02x' % d for d in chunk]),
                    '   ' * (16 - len(chunk)),
                    ''.join([chr(d) if d >= 32 and d < 127 else '.' for d in chunk]),
                ))
                prev_chunk = chunk
                same_chunk = False
            elif not same_chunk:
                print('*')
                same_chunk = True
            addr += len(chunk)
        print('%08x' % addr)

    def store_file(self, addr, data, filename):
        with open(filename, 'wb') as f:
            f.write(bytes(data))
            self._dbg.info("Saved %d Bytes into %s file" % (len(data), filename))

    def read_file(self, filename):
        if filename.endswith('.srec'):
            srec = lib.srec.Srec()
            srec.encode_file(filename)
            size = sum([len(i[1]) for i in srec.buffers])
            self._dbg.info("Loaded %d Bytes from %s file" % (size, filename))
            return srec.buffers
        with open(filename, 'rb') as f:
            data = list(f.read())
            self._dbg.info("Loaded %d Bytes from %s file" % (len(data), filename))
            return [(None, data)]
        raise lib.stlinkex.StlinkException("Error reading file")

    def dump_mem(self, addr, size):
        print("08x %d" % addr, size)
        data = self._driver.get_mem(addr, size)
        self.print_buffer(addr, data)

    def cmd_dump(self, params):
        cmd = params[0]
        params = params[1:]
        r = []
        if cmd == 'core':
            # dump all core registers
            self._driver.core_halt()
            #Return what we read for calling application
            for reg, val in self._driver.get_reg_all():
                print("  %3s: %08x" % (reg, val))
                r.append(val)
        elif self._driver.is_reg(cmd):
            # dump core register
            self._driver.core_halt()
            reg = cmd.upper()
            val = self._driver.get_reg(reg)
            print("  %3s: %08x" % (reg, val))
            #Return what we read for calling application
            r = val
        elif cmd == 'flash':
            size = int(params[0], 0) if params else self._flash_size * 1024
            data = self._driver.get_mem(self._driver.FLASH_START, size)
            self.print_buffer(self._driver.FLASH_START, data)
            #Return what we read for calling application
            r = data
        elif cmd == 'sram':
            size = int(params[0], 0) if params else self._sram_size * 1024
            data = self._driver.get_mem(self._driver.SRAM_START, size)
            self.print_buffer(self._driver.SRAM_START, data)
            #Return what we read for calling application
            r = data
        elif params:
            # dump memory from address with size
            addr = int(cmd, 0)
            data = self._driver.get_mem(addr, int(params[0], 0))
            self.print_buffer(addr, data)
            #Return what we read for calling application
            r = data
        else:
            # dump 32 bit register at address
            addr = int(cmd, 0)
            val = self._stlink.get_debugreg32(addr)
            print('  %08x: %08x' % (addr, val))
            #Return what we read for calling application
            r = val
        return r

    def cmd_read(self, params):
        cmd = params[0]
        file_name = params[-1]
        params = params[1:-1]
        if cmd == 'flash':
            addr = self._driver.FLASH_START
            size = int(params[0], 0) if params else self._flash_size * 1024
        elif cmd == 'sram':
            addr = self._driver.SRAM_START
            size = int(params[0], 0) if params else self._sram_size * 1024
        elif params:
            addr = int(cmd, 0)
            size = int(params[0], 0)
        else:
            raise lib.stlinkex.StlinkExceptionBadParam()
        data = self._driver.get_mem(addr, size)
        self.store_file(addr, data, file_name)

    def cmd_set(self, params):
        # Check for flash address
        flash = False
        if params and params[0] == 'flash':
            flash = True
            params = params[1:]
        #Get the address/registry name
        cmd = params[0]
        params = params[1:]
        if not params:
            raise lib.stlinkex.StlinkExceptionBadParam('Missing argument')
        data = int(params[0], 0)

        if flash:
            addr = int(cmd, 0)
            self._driver.flash_write(addr, stlib.stlinkv2.Stlink.to_bytes('little', data))
        elif self._driver.is_reg(cmd):
            self._driver.core_halt()
            reg = cmd.upper()
            self._driver.set_reg(reg, data)
        else:
            addr = int(cmd, 0)
            self._stlink.set_debugreg32(addr, data)

    def cmd_fill(self, params):
        cmd = params[0]
        value = int(params[-1], 0)
        params = params[1:-1]
        if cmd == 'sram':
            size = int(params[0], 0) if params else self._sram_size * 1024
            self._driver.fill_mem(self._driver.SRAM_START, size, value)
        elif params:
            self._driver.fill_mem(int(cmd, 0), int(params[0], 0), value)
        else:
            raise lib.stlinkex.StlinkExceptionBadParam()

    def cmd_write(self, params):
        mem = self.read_file(params[-1])
        params = params[:-1]
        if len(mem) == 1 and mem[0][0] is None:
            data = mem[0][1]
            if len(params) != 1:
                raise lib.stlinkex.StlinkExceptionBadParam('Address is not set')
            if params[0] == 'sram':
                addr = self._driver.SRAM_START
                if len(data) > self._sram_size * 1024:
                    raise lib.stlinkex.StlinkExceptionBadParam('Data are bigger than SRAM')
            else:
                addr = int(params[0], 0)
            self._driver.set_mem(addr, data)
            return
        if params:
            raise lib.stlinkex.StlinkException('Address for write is set by file')
        for addr, data in mem:
            self._driver.set_mem(addr, data)

    def cmd_flash(self, params):
        erase = False
        verify = False
        write = True
        if params[0] == 'erase':
            params = params[1:]
            if not params:
                self._flash_size = self._stlink.get_debugreg16(self._mcus_by_devid['flash_size_reg'])
                self._driver.flash_erase_all(self._flash_size)
                return
            erase = True
        elif params[0] == 'check':
            write = False
            verify = True
            params = params[1:]
        mem = self.read_file(params[-1])
        params = params[:-1]
        if params and params[0] == 'verify':
            verify = True
            params = params[1:]
        start_addr = lib.stm32.Stm32.FLASH_START
        if len(mem) == 1 and mem[0][0] is None:
            if params:
                start_addr = int(params[0], 0)
                params = params[1:]
        if params:
            raise lib.stlinkex.StlinkExceptionBadParam('Address for write is set by file')
        #We first do all erases and then all writes, or we could erase something we already wrote!
        if erase:
            for addr, data in mem:
                if addr is None:
                    addr = start_addr
                self._driver.flash_erase(addr, len(data), erase_sizes=self._mcus_by_devid['erase_sizes'])
        if write:
            #Now we can write anything we want
            for addr, data in mem:
                if addr is None:
                    addr = start_addr
                self._driver.flash_write(addr, data)
                self._driver.core_reset_halt()
                time.sleep(0.1)
        if verify:
            self._driver.core_halt()
            for addr, data in mem:
                if addr is None:
                    addr = start_addr
                self._driver.flash_verify(addr, data)
        self._driver.core_run()

    def cmd_optbyte(self, params):
        # optbyte:write:all:reset
        # optbyte:read:2:set
        if len(params) != 3:
            raise stlib.stlinkex.StlinkExceptionBadParam('Usage: optbyte:operation:sector:enable. Example: optbyte:write:2:set')

        isRead = 0
        #Read parameters
        if params[0] == 'erase':
            #Erase the whole OPT area
            self._driver.optbyte_erase()
            return
        elif params[0] == 'read':
            isRead = 1
        elif params[0] != 'write':
            raise stlib.stlinkex.StlinkExceptionBadParam('Only <write> <read> <erase> options allowed')

        params = params[1:]
        sector = params[0]
        params = params[1:]
        if sector >= 32 or sector < 0:
            raise stlib.stlinkex.StlinkExceptionBadParam('Sector not in range [0-31]')
        enable = params[0]
        params = params[1:]
        if not (enable == 'set' or enable == 'reset'):
            raise stlib.stlinkex.StlinkExceptionBadParam('Wrong enable flag. [set][reset]')
        
        if enable == 'set':
            enable = 1
        else:
            enable = 0

        #TODO: Support multiple sectors
        sectors = []
        sectors[0] = sector

        if isRead:
            #Read protection operation
            raise stlib.stlinkex.StlinkExceptionBadParam('Not supported yet')
        else:
            #Flash already unlocked at driver creation
            #Unlock option byte write protection
            self._driver.unlock_optbytes()
            #Write protection operation
            self._driver.optbyte_write(sectors, enable)
            #Lock back
            self._driver.lock_optbytes()

        return

    def cmd(self, param):
        cmd = param[0]
        params = param[1:]
        r = []

        if cmd == 'dump' and params:
            r = self.cmd_dump(params)
        elif cmd == 'dump16' and params:
            addr = int(params[0], 0)
            reg = self._stlink.get_debugreg16(addr)
            print('  %08x: %04x' % (addr, reg))
        elif cmd == 'dump8' and params:
            addr = int(params[0], 0)
            reg = self._stlink.get_debugreg8(addr)
            print('  %08x: %02x' % (addr, reg))
        elif cmd == 'read' and params:
            self.cmd_read(params)
        elif cmd == 'set' and params:
            self.cmd_set(params)
        elif cmd == 'write' and params:
            self.cmd_write(params)
        elif cmd == 'fill' and params:
            self.cmd_fill(params)
        elif cmd == 'flash' and params:
            self.cmd_flash(params)
        elif cmd == 'optbyte' and params:
            self.cmd_optbyte(params)
        elif cmd == 'reset':
            if params:
                if params[0] == 'halt':
                    self._driver.core_reset_halt()
                else:
                    raise lib.stlinkex.StlinkExceptionBadParam()
            else:
                self._driver.core_reset()
        elif cmd == 'halt':
            self._driver.core_halt()
        elif cmd == 'step':
            self._driver.core_step()
        elif cmd == 'run':
            self._driver.core_run()
        elif cmd == 'sleep' and len(params) == 1:
            time.sleep(float(params[0]))
        else:
            raise lib.stlinkex.StlinkExceptionBadParam()

        #Return operation result
        return r


    def start(self, inargs=None):
        parser = argparse.ArgumentParser(prog='pystlink', formatter_class=argparse.RawTextHelpFormatter, description=DESCRIPTION_STR, epilog=ACTIONS_HELP_STR)
        group_verbose = parser.add_argument_group(title='set verbosity level').add_mutually_exclusive_group()
        group_verbose.set_defaults(verbosity=1)
        group_verbose.add_argument('-lq', '--libraryquiet', action='store_const', dest='verbosity', const=stlib.dbg.Verbosity.lq)
        group_verbose.add_argument('-q', '--quiet', action='store_const', dest='verbosity', const=stlib.dbg.Verbosity.q)
        group_verbose.add_argument('-i', '--info', action='store_const', dest='verbosity', const=stlib.dbg.Verbosity.i, help='default')
        group_verbose.add_argument('-v', '--verbose', action='store_const', dest='verbosity', const=stlib.dbg.Verbosity.v)
        group_verbose.add_argument('-d', '--debug', action='store_const', dest='verbosity', const=stlib.dbg.Verbosity.d)
        parser.add_argument('-V', '--version', action='version', version=VERSION_STR)
        parser.add_argument('-c', '--cpu', action='append', help='set expected CPU type [eg: STM32F051, STM32L4]')
        parser.add_argument('-r', '--no-run', action='store_true', help='do not run core when program end (if core was halted)')
        parser.add_argument('-u', '--no-unmount', action='store_true', help='do not unmount DISCOVERY from ST-Link/V2-1 on OS/X platform')
        parser.add_argument('-s', '--serial', dest='serial', help='Use Stlink with given serial number')
        parser.add_argument('-n', '--num-index', type=int, dest='index', default=0, help='Use Stlink with given index')
        parser.add_argument('-H', '--hard', action='store_true', help='Reset device with NRST')
        group_actions = parser.add_argument_group(title='actions')
        group_actions.add_argument('action', nargs='*', help='actions will be processed sequentially')
        if inargs is not None:
            inargs = inargs.split()
        args = parser.parse_args(args=inargs)
        self._dbg = lib.dbg.Dbg(args.verbosity)
        self._serial = args.serial
        self._index = args.index
        self._hard = args.hard
        runtime_status = 0
        r = []

        #Do stuff
        try:
            self.detect_cpu(args.cpu, not args.no_unmount)
            if args.action and self._driver is None:
                raise lib.stlinkex.StlinkExceptionCpuNotSelected()
            for action in args.action:
                self._dbg.verbose('CMD: %s' % action)
                try:
                    rs = self.cmd(action.split(':'))
                    r.append(rs)
                except lib.stlinkex.StlinkExceptionBadParam as e:
                    raise e.set_cmd(action)
        except (lib.stlinkex.StlinkExceptionBadParam, lib.stlinkex.StlinkException) as e:
            self._dbg.error(e)
            runtime_status = 1
        except KeyboardInterrupt:
            self._dbg.error('Keyboard interrupt')
            runtime_status = 1
        except (ValueError, OverflowError, FileNotFoundError, Exception) as e:
            self._dbg.error('Parameter error: %s' % e)
            if args.verbosity >= 3:
                raise e
            runtime_status = 1
        if self._stlink:
            try:
                if self._driver:
                    if not args.no_run:
                        self._driver.core_nodebug()
                    else:
                        self._dbg.warning('CPU may stay in halt mode', level=1)
                self._stlink.leave_state()
                self._stlink.clean_exit()
            except lib.stlinkex.StlinkException as e:
                self._dbg.error(e)
                runtime_status = 1
            self._dbg.verbose('DONE in %0.2fs' % (time.time() - self._start_time))
        if runtime_status:
            sys.exit(runtime_status)

        #Force flushing at the end of the call (useful if using as package)
        sys.stderr.flush()
        return r

if __name__ == "__main__":
    pystlink = PyStlink()
    pystlink.start()
