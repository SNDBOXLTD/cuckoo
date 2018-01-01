import os
import platform
import subprocess
import logging
import win32file
import time
import win32process
import win32con
import threading

from lib.common.defines import KERNEL32, GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING
from lib.common.constants import SHUTDOWN_MUTEX
#from lib.common.errors import get_error_string

# Set logger
log = logging.getLogger(__name__)

def get_error_string(data):
    pass

class Thunder(object):
    def __init__(self, pipe_name, forwarder_pipe_name, dispatcher_pipe_name, destination):
        self.is_x64 = platform.machine().endswith("64")
        self._driver_communication_device = 0
        self.ip, self.port = destination

        # Ioctls
        self._ioctl_monitor = 0x222408
        self._ioctl_configuration = 0x22240C
        self._ioctl_communication_new_pipe_name = 0x222410
        self._ioctl_stop_monitoring = 0x22241C

        # Order is crucial, same in the driver it self
        self._configuration_order = ["SSDT", "TIME", "REGISTRY", "FILES", "EXTRA", "LOGGING"]

        # General configurations
        self._driver_pipe_name = "\\\\.\\Thunder"
        self._driver_log_pipe_name = pipe_name  # Kernel

        # Cuckoo is reading from this pipe to forward the host machine
        self._forwarder_log_pipe_name = forwarder_pipe_name  # Forwarder
        self._dispatcher_log_pipe_name = dispatcher_pipe_name  # Dispatcher

        # Binary configuration, exactly as in the binary directory
        self._installer_dll_name = "WdfCoinstaller01009.dll"
        self._installer_exe_name = "Strike.exe"
        self._driver_name = "Thunder.sys"
        self._information_file = "minimal.inf"
        self._log_dispatcher_name = "log_dispatcher.py"

    def _create_device(self):
        # return KERNEL32.CreateFileA(self._driver_pipe, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
        return win32file.CreateFile(self._driver_pipe, win32file.GENERIC_READ | win32file.GENERIC_WRITE, 0, None,
                                    win32file.OPEN_EXISTING, 0, None)

    def _send_ioctl(self, device, ioctl, msg):
        to_send = msg
        if long == type(msg) or int == type(msg):
            #to_send = ("0" + hex(msg)[2:]).replace("L", "").decode("hex")
            to_send = ("%x" % (msg)).decode("hex")
            length = len(to_send)
        else:
            length = len(str(msg))

        print "Sending: [%s] of length: [%d]" % (to_send, length)
        print type(to_send)
        # return KERNEL32.DeviceIoControl(device, ioctl, to_send, length, None) # Not working with kernel32 like that
        return win32file.DeviceIoControl(device, ioctl, to_send, length, None)

    def check_components(self):
        installing_components = [
            self._installer_dll_name,
            self._installer_exe_name,
            self._driver_name,
            self._information_file,
            self._log_dispatcher_name
        ]

        # Sanity
        for component in installing_components:
            comp_path = os.path.abspath(os.path.join("bin", component))
            if not os.path.exists(comp_path):
                log.warning("Driver component not found: [%s]" % (comp_path))
                return False
        return True

    def install(self):
        log.info("Thunder - Installation initialized")
        # Sanity

        if not self.check_components():
            return False

        # Initialize logger command
        args_logs = [
            "cmd.exe",
            "/c",
            "start",
            os.path.abspath(os.path.join("bin", self._log_dispatcher_name)),
            str(self._driver_log_pipe_name),
            str(self._forwarder_log_pipe_name),
            str(self._dispatcher_log_pipe_name),
            self.ip,
            str(self.port)
        ]

        # Initialize installer command
        # Strike.exe 1 C:\temp\WdfCoinstaller01009.dll C:\temp\minimal.inf C:\temp\thunder.sys
        args_installer = [
            os.path.abspath(os.path.join("bin", self._installer_exe_name)),
            "1",
            os.path.abspath(os.path.join("bin", self._installer_dll_name)),
            os.path.abspath(os.path.join("bin", self._information_file)),
            os.path.abspath(os.path.join("bin", self._driver_name)),
        ]

        # Execute command
        log.info("Execution args: [%s][%s]" % (args_logs, args_installer))
        try:
            subprocess.check_call(args_logs, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.check_call(args_installer, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            log.error("Failed [CalledProcessError] installing driver with command args: [%s][%s]" % (
            args_logs, args_installer))
            return False
        log.info("Driver installed successfully")

        return self.initialize()

    def create_monitored_process(self, path, args=None):

        startupinfo = win32process.STARTUPINFO()
        startupinfo.dwFlags = win32process.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = win32con.SW_NORMAL

        command = path
        if None != args:
            command += " " + args

        log.debug("commandline: [%s]", command)
        hProcess, hThread, dwProcessId, dwThreadId = win32process.CreateProcess(
            None,
            command,  # Command
            None,
            None,
            0,
            win32process.NORMAL_PRIORITY_CLASS | win32process.CREATE_SUSPENDED,
            None,
            None,
            startupinfo)

        try:
            # Hack to monitor first pid - this process
            self._send_ioctl(self._driver_communication_device, self._ioctl_monitor, str(dwProcessId))
        except Exception, e:
            error_code = KERNEL32.GetLastError()
            log.error("Failed monitoring, GLE: [%d]-[%s]", error_code, get_error_string(error_code))
            log.error(str(e))
            return (False, hProcess, hThread, dwProcessId, dwThreadId)

        log.warning("create_monitored_process")

        win32process.ResumeThread(hThread)
        log.info("malware run successfully, pid: [%d] tid: [%d]", dwProcessId, dwThreadId)
        return (True, hProcess, hThread, dwProcessId, dwThreadId)

    def initialize(self):
        # Create driver device
        while 1:
            try:
                self._driver_communication_device = win32file.CreateFile(self._driver_pipe_name,
                                                                         win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                                                         0, None,
                                                                         win32file.OPEN_EXISTING, 0, None)
            except:
                log.info("Failed creating communication device: [%d]", KERNEL32.GetLastError())
                time.sleep(1)
                continue
            break
        # Send new pipe for logging communication creation request
        try:
            self._send_ioctl(self._driver_communication_device, self._ioctl_communication_new_pipe_name,
                             self._driver_log_pipe_name.split("\\")[-1] + "\x00")
        except Exception, e:
            error_code = KERNEL32.GetLastError()
            log.error("Failed create_pipe, GLE: [%d]-[%s], dev: [%s]", error_code,
                      get_error_string(error_code), self._driver_log_pipe_name)
            log.error(str(e))
            raw_input()
            return False

        log.info("New pipename initialized: [%s]", self._driver_log_pipe_name)
        return True

    def monitor(self, configuration):
        # Initialize device
        binary_conf = ""

        if 0 == self._driver_communication_device:
            log.error("Bad driver pipe device")
            return False

        try:
            # Parse configurations
            binary_conf = self.parse_configuration(configuration)
            log.info("Driver configuration is: [0x%08X]" % binary_conf)

            # Send configuration
            self._send_ioctl(self._driver_communication_device, self._ioctl_configuration, binary_conf)

            # Hack to monitor first pid - this process
            # self._send_ioctl(self._driver_communication_device, self._ioctl_monitor, str(os.getpid()))
        except Exception, e:
            error_code = KERNEL32.GetLastError()
            log.error("Failed monitoring, GLE: [%d]-[%s], dev: [0x%08X], conf: [%s]", error_code,
                      get_error_string(error_code), self._driver_communication_device, binary_conf)
            log.error(str(e))
            return False

        log.info("Driver monitor initialized")
        return True

    def parse_configuration(self, conf):
        number = ""
        for conf_title in self._configuration_order:
            val = conf.get(conf_title, False)

            if val:
                number = "1" + number
            else:
                number = "0" + number

        return int(number, 2)

    def thread_wait_finish(self):
        # Wait for shutdown mutex to be created
        while True:
            time.sleep(1)
            # Create the shutdown mutex.
            mutex_handle = KERNEL32.OpenMutexA(0x00100000, False, SHUTDOWN_MUTEX)

            # If shutdown mutex is found, exit loop
            if 0 != mutex_handle:
                KERNEL32.CloseHandle(mutex_handle)
                break

        # Stop monitoring
        self._send_ioctl(self._driver_communication_device, self._ioctl_stop_monitoring, "dummymessage")


    def wait_finish(self):
        t = threading.Thread(target=self.thread_wait_finish)
        t.start()

        return True