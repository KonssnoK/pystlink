import time
from . import stm32 #Use relative import
from . import stlinkex #Use relative import


class Flash():
    FLASH_REG_BASE = 0x40022000
    FLASH_REG_BASE_STEP = 0x40
    FLASH_KEYR_INDEX = 0x04
    FLASH_OPTKEYR_INDEX = 0x08
    FLASH_SR_INDEX = 0x0c
    FLASH_CR_INDEX = 0x10
    FLASH_AR_INDEX = 0x14
    FLASH_KEYR_REG = FLASH_REG_BASE + FLASH_KEYR_INDEX
    FLASH_OPTKEYR_REG = FLASH_REG_BASE + FLASH_OPTKEYR_INDEX
    FLASH_SR_REG = FLASH_REG_BASE + FLASH_SR_INDEX
    FLASH_CR_REG = FLASH_REG_BASE + FLASH_CR_INDEX
    FLASH_AR_REG = FLASH_REG_BASE + FLASH_AR_INDEX

    FLASH_CR_LOCK_BIT = 0x00000080
    FLASH_CR_PG_BIT = 0x00000001
    FLASH_CR_PER_BIT = 0x00000002
    FLASH_CR_MER_BIT = 0x00000004
    FLASH_CR_STRT_BIT = 0x00000040
    FLASH_CR_OPTWRE_BIT = 0x00000200
    FLASH_SR_BUSY_BIT = 0x00000001
    FLASH_SR_ERLYBSY_BIT = 0x00000002
    FLASH_SR_PGERR_BIT = 0x00000004
    FLASH_SR_WRPRTERR_BIT = 0x00000010
    FLASH_SR_EOP_BIT = 0x00000020

    def __init__(self, driver, stlink, dbg, bank=0):
        self._driver = driver
        self._stlink = stlink
        self._dbg = dbg
        self._stlink.read_target_voltage()
        reg_bank = Flash.FLASH_REG_BASE + Flash.FLASH_REG_BASE_STEP * bank
        Flash.FLASH_KEYR_REG = reg_bank + Flash.FLASH_KEYR_INDEX
        Flash.FLASH_SR_REG = reg_bank + Flash.FLASH_SR_INDEX
        Flash.FLASH_CR_REG = reg_bank + Flash.FLASH_CR_INDEX
        Flash.FLASH_AR_REG = reg_bank + Flash.FLASH_AR_INDEX
        if self._stlink.target_voltage < 2.0:
            raise stlinkex.StlinkException('Supply voltage is %.2fV, but minimum for FLASH program or erase is 2.0V' % self._stlink.target_voltage)
        self.unlock()

    def clear_sr(self):
        # clear errors
        sr = self._stlink.get_debugreg32(Flash.FLASH_SR_REG)
        self._stlink.set_debugreg32(Flash.FLASH_SR_REG, sr)

    def unlock(self):
        self._driver.core_reset_halt()
        self.clear_sr()
        # programing locked
        if self._stlink.get_debugreg32(Flash.FLASH_CR_REG) & Flash.FLASH_CR_LOCK_BIT:
            # unlock keys
            self._stlink.set_debugreg32(Flash.FLASH_KEYR_REG, 0x45670123)
            self._stlink.set_debugreg32(Flash.FLASH_KEYR_REG, 0xcdef89ab)
        else:
            print("UNLOCK: FLASH already unlocked!? FLASH_CR:%s"%hex(self._stlink.get_debugreg32(Flash.FLASH_CR_REG)))
        # programing locked
        if self._stlink.get_debugreg32(Flash.FLASH_CR_REG) & Flash.FLASH_CR_LOCK_BIT:
            raise stlinkex.StlinkException('Error unlocking FLASH')

    def lock(self):
        self._stlink.set_debugreg32(Flash.FLASH_CR_REG, Flash.FLASH_CR_LOCK_BIT)
        self._driver.core_reset_halt()

    def unlock_optbytes(self):
        self._driver.core_reset_halt()

        #Unlock option bytes
        if self._stlink.get_debugreg32(Flash.FLASH_CR_REG) & Flash.FLASH_CR_OPTWRE_BIT:
            #unlock using keys
            self._stlink.set_debugreg32(Flash.FLASH_OPTKEYR_REG, 0x45670123)
            self._stlink.set_debugreg32(Flash.FLASH_OPTKEYR_REG, 0xcdef89ab)
        else:
            print("UNLOCK: OPTION BYTES already unlocked!? FLASH_CR:%s"%hex(self._stlink.get_debugreg32(Flash.FLASH_CR_REG)))

        if self._stlink.get_debugreg32(Flash.FLASH_CR_REG) & Flash.FLASH_CR_OPTWRE_BIT:
            raise stlinkex.StlinkException('Error unlocking OPTION BYTES')
        return

    def lock_optbytes(self):
        self._stlink.set_debugreg32(Flash.FLASH_CR_REG, Flash.FLASH_CR_OPTWRE_BIT)
        self._driver.core_reset_halt()
        return

    def erase_all(self):
        self._stlink.set_debugreg32(Flash.FLASH_CR_REG, Flash.FLASH_CR_MER_BIT)
        self._stlink.set_debugreg32(Flash.FLASH_CR_REG, Flash.FLASH_CR_MER_BIT | Flash.FLASH_CR_STRT_BIT)
        self.wait_busy(2, 'Erasing FLASH')

    def erase_page(self, page_addr):
        self._stlink.set_debugreg32(Flash.FLASH_CR_REG, Flash.FLASH_CR_PER_BIT)
        self._stlink.set_debugreg32(Flash.FLASH_AR_REG, page_addr)
        self._stlink.set_debugreg32(Flash.FLASH_CR_REG, Flash.FLASH_CR_PER_BIT | Flash.FLASH_CR_STRT_BIT)
        self.wait_busy(0.2)

    def erase_pages(self, flash_start, erase_sizes, addr, size):
        page_addr = flash_start
        #Compute real page start and end address
        erase_mask = -1
        addr_end = addr + size
        if len(erase_sizes) == 1:
            # Current support just for single sized page flash memories
            erase_mask = ~(erase_sizes[0] - 1)
            addr_end = ((addr + size) & erase_mask)
            if (addr + size) > addr_end:
                addr_end += erase_sizes[0]

        self._dbg.bargraph_start('Erasing FLASH [0x%08X-0x%08X]'%(addr & erase_mask, addr_end), value_min=addr, value_max=addr + size)
        #Do erase
        while True:
            for page_size in erase_sizes:
                if addr < page_addr + page_size:
                    self._dbg.bargraph_update(value=page_addr)
                    self.erase_page(page_addr)
                page_addr += page_size
                if addr + size < page_addr:
                    self._dbg.bargraph_done()
                    return

    def wait_busy(self, wait_time, bargraph_msg=None):
        end_time = time.time()
        if bargraph_msg:
            self._dbg.bargraph_start(bargraph_msg, value_min=time.time(), value_max=end_time + wait_time)
        # all times are from data sheet, will be more safe to wait 2 time longer
        end_time += wait_time * 2
        while time.time() < end_time:
            if bargraph_msg:
                self._dbg.bargraph_update(value=time.time())
            status = self._stlink.get_debugreg32(Flash.FLASH_SR_REG)
            if not status & Flash.FLASH_SR_BUSY_BIT:
                self.end_of_operation(status)
                if bargraph_msg:
                    self._dbg.bargraph_done()
                return
            time.sleep(wait_time / 20)
        raise stlinkex.StlinkException('Operation timeout')

    def wait_for_breakpoint(self, wait_time):
        end_time = time.time() + wait_time
        while time.time() < end_time and not self._stlink.get_debugreg32(stm32.Stm32.DHCSR_REG) & stm32.Stm32.DHCSR_STATUS_HALT_BIT:
            time.sleep(wait_time / 20)
        self.end_of_operation(self._stlink.get_debugreg32(Flash.FLASH_SR_REG))

    def end_of_operation(self, status):
        if status != Flash.FLASH_SR_EOP_BIT:
            if status & Flash.FLASH_SR_WRPRTERR_BIT:
                self._dbg.info("WRPRTERR: Writing page without UNLOCK?")
            if status & Flash.FLASH_SR_PGERR_BIT:
                self._dbg.info("PGERR: Writing page without ERASE?")
            if status & Flash.FLASH_SR_ERLYBSY_BIT:
                self._dbg.info("ERLYBSY set -> ?")
            raise stlinkex.StlinkException('Error writing FLASH with status (FLASH_SR) %08x' % status)
        self._stlink.set_debugreg32(Flash.FLASH_SR_REG, status)


# support all STM32F MCUs with page access to FLASH
# (STM32F0xx, STM32F1xx and also STM32F3xx)
class Stm32FP(stm32.Stm32):
    OPTIONBYTE_REG_BASE = 0x1FFFF800
    OPTIONBYTE_WRP01_INDEX = 0x00000008
    OPTIONBYTE_WRP23_INDEX = 0x0000000C

    OPTIONBYTE_WRP01_REG = OPTIONBYTE_REG_BASE + OPTIONBYTE_WRP01_INDEX
    OPTIONBYTE_WRP23_REG = OPTIONBYTE_REG_BASE + OPTIONBYTE_WRP23_INDEX

    def _flash_erase_all(self, bank=0):
        flash = Flash(self, self._stlink, self._dbg, bank=bank)
        flash.erase_all()
        flash.lock()

    def flash_erase_all(self, flash_size):
        self._dbg.debug('Stm32FP.flash_erase_all()')
        self._flash_erase_all()

    def _flash_write(self, addr, data, erase=False, erase_sizes=None, bank=0):
        # align data
        if len(data) % 2:
            data.extend([0xff] * (2 - len(data) % 2))
        flash = Flash(self, self._stlink, self._dbg, bank=bank)
        if erase:
            if erase_sizes:
                flash.erase_pages(self.FLASH_START, erase_sizes, addr, len(data))
            else:
                flash.erase_all()
        self._dbg.bargraph_start('Writing FLASH [0x%08X-0x%08X]'%(addr, addr + len(data)), value_min=addr, value_max=addr + len(data))
        self._stlink.set_debugreg32(Flash.FLASH_CR_REG, Flash.FLASH_CR_PG_BIT)
        while(data):
            self._dbg.bargraph_update(value=addr)
            block = data[:self._stlink.STLINK_MAXIMUM_TRANSFER_SIZE]
            data = data[self._stlink.STLINK_MAXIMUM_TRANSFER_SIZE:]
            if min(block) != 0xff:
                self._stlink.set_mem16(addr, block)
            addr += len(block)
        flash.wait_busy(0.001)
        flash.lock()
        self._dbg.bargraph_done()

    def _flash_erase(self, addr, datalen, erase_sizes=None, bank=0):
        """ Init Flash, call flash erase operation, lock flash
        """
        flash = Flash(self, self._stlink, self._dbg, bank=bank)
        if erase_sizes:
            flash.erase_pages(self.FLASH_START, erase_sizes, addr, datalen)
        else:
            flash.erase_all()
        #flash is unlocked upon initialization
        flash.lock()


    def flash_write(self, addr, data, erase=False, erase_sizes=None):
        self._dbg.debug('Stm32FP.flash_write(%s, [data:%dBytes], erase=%s, erase_sizes=%s)' % (('0x%08x' % addr) if addr is not None else 'None', len(data), erase, erase_sizes))
        if addr is None:
            addr = self.FLASH_START
        elif addr % 2:
            raise stlinkex.StlinkException('Start address is not aligned to half-word')
        self._flash_write(addr, data, erase=erase, erase_sizes=erase_sizes)

    def flash_erase(self, addr, datalen, erase_sizes=None):
        """ Erase pages from starting address for a given len (rounded up to page size)
        """
        self._dbg.debug('Stm32FP.flash_erase(%s, [data:%dBytes], erase_sizes=%s)' % (('0x%08x' % addr) if addr is not None else 'None', datalen, erase_sizes))
        if addr is None:
            addr = self.FLASH_START
        elif addr % 2:
            raise stlinkex.StlinkException('Start address is not aligned to half-word')
        self._flash_erase(addr, datalen, erase_sizes=erase_sizes)

    def optbyte_erase(self):
        """ Erase the whole OPT area
        """
        #TODO
        # (1) Set the OPTER bit in the FLASH_CR register to enable option byte        erasing */
        # (2) Set the STRT bit in the FLASH_CR register to start the erasing */
        # (3) Wait until the BSY bit is reset in the FLASH_SR register */
        # (4) Check the EOP flag in the FLASH_SR register */
        # (5) Clear EOP flag by software by writing EOP at 1 */
        # (6) Reset the PER Bit to disable the page erase */ 
        return

    def optbyte_write(self, sectors, enable):
        """ Disable or enable option bytes for the given sectors (Write protection)
            WRP bits from 0 to 31 are protecting the Flash memory by sector of 4 kB.
            For STM32F030xC bit 31 is protecting the last 132 kB.
        """
        self._dbg.debug('Stm32FP.optbyte_write()') #TODO Finish

        WRP = []
        #Get current settings
        WRP[0] = self._stlink.get_debugreg32(Stm32FP.OPTIONBYTE_WRP01_REG)
        WRP[1] = self._stlink.get_debugreg32(Stm32FP.OPTIONBYTE_WRP23_REG)

        #Compute values to set
        for s in sectors:
            if enable:
                #Clear the bit to write-protect and set the complementary
                if s < 8:
                    WRP[0] &= ~(1 << s)
                    WRP[0] |= (1 << s) << 8
                if s < 16:
                    WRP[0] &= ~((1 << s) << 16)
                    WRP[0] |= (1 << s) << 24
                elif s < 24:
                    WRP[1] &= ~(1 << s)
                    WRP[1] |= (1 << s) << 8
                else:
                    WRP[1] &= ~((1 << s) << 16)
                    WRP[1] |= (1 << s) << 24
            else:
                #Set the bit to disable protection and clear the complementary
                if s < 8:
                    WRP[0] |= (1 << s)
                    WRP[0] &= ~((1 << s) << 8)
                if s < 16:
                    WRP[0] |= (1 << s) << 16
                    WRP[0] &= ~((1 << s) << 24)
                elif s < 24:
                    WRP[1] |= (1 << s)
                    WRP[1] &= ~((1 << s) << 8)
                else:
                    WRP[1] |= (1 << s) << 16
                    WRP[1] &= ~((1 << s) << 24)

        #TODO
        #Since we don't know how write protection works in other MCUs we put the implementation here
        #Hopefully it can be moved in the general Flash class

        #Set PG bit in FLASH_CR
        self._stlink.set_debugreg32(Flash.FLASH_CR_REG, Flash.FLASH_CR_PG_BIT)
        #Set desired value in the OPT registers
        self._stlink.set_debugreg32(Stm32FP.OPTIONBYTE_WRP01_REG, WRP[0])
        self._stlink.set_debugreg32(Stm32FP.OPTIONBYTE_WRP23_REG, WRP[1])
        #Wait for BSY flag in FLASH_SR
        while True:
            status = self._stlink.get_debugreg32(Flash.FLASH_SR_REG)
            if not status & Flash.FLASH_SR_BUSY_BIT:
                break
            time.sleep(0.001)
        #Check EOP flag in FLASH_SR
        #This is end_of_operation from Flash class -> Use that instead of code
        if status != Flash.FLASH_SR_EOP_BIT:
            if status & Flash.FLASH_SR_WRPRTERR_BIT:
                self._dbg.info("WRPRTERR: Writing page without UNLOCK?")
            if status & Flash.FLASH_SR_PGERR_BIT:
                self._dbg.info("PGERR: Writing page without ERASE?")
            if status & Flash.FLASH_SR_ERLYBSY_BIT:
                self._dbg.info("ERLYBSY set -> ?")
            raise stlinkex.StlinkException('Error writing FLASH with status (FLASH_SR) %08x' % status)
        #Clear EOP flag in FLASH_CR
        self._stlink.set_debugreg32(Flash.FLASH_SR_REG, status)
        #Reset PG bit in FLASH_CR
        flash_cr = self._stlink.get_debugreg32(Flash.FLASH_CR_REG) & ~Flash.FLASH_CR_PG_BIT
        self._stlink.set_debugreg32(Flash.FLASH_CR_REG, flash_cr)
        


# support STM32F MCUs with page access to FLASH and two banks
# (STM32F1xxxF and STM32F1xxxG) (XL devices)
class Stm32FPXL(Stm32FP):
    BANK_SIZE = 512 * 1024

    def flash_erase_all(self, flash_size):
        self._dbg.debug('Stm32F1.flash_erase_all()')
        self._flash_erase_all(bank=0)
        self._flash_erase_all(bank=1)

    def flash_write(self, addr, data, erase=False, erase_sizes=None):
        self._dbg.debug('Stm32F1.flash_write(%s, [data:%dBytes], erase=%s, erase_sizes=%s)' % (('0x%08x' % addr) if addr is not None else 'None', len(data), erase, erase_sizes))
        if addr is None:
            addr = self.FLASH_START
        elif addr % 2:
            raise stlinkex.StlinkException('Start address is not aligned to half-word')
        if (addr - self.FLASH_START) + len(data) <= Stm32FPXL.BANK_SIZE:
            self._flash_write(addr, data, erase=erase, erase_sizes=erase_sizes, bank=0)
        elif (addr - self.FLASH_START) > Stm32FPXL.BANK_SIZE:
            self._flash_write(addr, data, erase=erase, erase_sizes=erase_sizes, bank=1)
        else:
            addr_bank1 = addr
            addr_bank2 = self.FLASH_START + Stm32FPXL.BANK_SIZE
            data_bank1 = data[:(Stm32FPXL.BANK_SIZE - (addr - self.FLASH_START))]
            data_bank2 = data[(Stm32FPXL.BANK_SIZE - (addr - self.FLASH_START)):]
            self._flash_write(addr_bank1, data_bank1, erase=erase, erase_sizes=erase_sizes, bank=0)
            self._flash_write(addr_bank2, data_bank2, erase=erase, erase_sizes=erase_sizes, bank=1)
