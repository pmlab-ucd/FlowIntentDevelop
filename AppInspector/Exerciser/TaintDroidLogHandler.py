from AsynchronousFileReader import AsynchronousFileReader
from utils import Utilities
import subprocess
import Queue
import re

'''
Read the TaintDroid during execution of the apps
'''
class TaintDroidLogHandler():
    @staticmethod
    def parse_taint_log(line):
        '''
        TaintDroidNotifyService#processLogEntry
        :param line:
        :return:
        '''
        line = str(line).replace('\r', '')
        if line.startswith('---------'):
            return
        taint_log = {}

        taint_log['log_time'] = line.split(' W')[0]
        taint_log['process_id'] = line.split('):')[0].split('(')[1].replace(' ', '')
        taint_log['process_name'] = Utilities.adb_id2process(taint_log['process_id']).replace('\r', '')
        message = line.split(': ')[1]
        taint_log['message'] = message
        taint_log['dst'] = TaintDroidLogHandler.get_dst(message)
        taint_log['src'] = TaintDroidLogHandler.get_taint_src(message)
        if TaintDroidLogHandler.is_TaintedSend(message):
            taint_log['channel'] = 'HTTP'
        elif TaintDroidLogHandler.is_TaintedSSLSend(message):
            taint_log['channel'] = 'HTTPS'
        elif TaintDroidLogHandler.is_TaintedSMS(message):
            taint_log['channel'] = 'SMS'
        else:
            taint_log['channel'] = 'INTERNAL'
        return taint_log

    @staticmethod
    def is_TaintedSend(msg):
        return 'libcore.os.send' in msg

    @staticmethod
    def is_TaintedSSLSend(msg):
        return 'SSLOutputStream.write' in msg

    @staticmethod
    def is_TaintedSMS(msg):
        return 'GsmSMSDispatcher.sendSMS' in msg or 'CdmaSMSDispatcher.sendSMS' in msg

    @staticmethod
    def get_dst(msg):
        pattern = re.compile('\((.*)\)')
        all = pattern.findall(msg)
        if len(all) > 0:
            return all[0]
        return "Unknown"

    @staticmethod
    def get_taint_src(msg):
        MAP = {'1': "Location",
               '2': "Address Book (ContactsProvider)",
               '4': "Microphone Input",
               '8': "Phone Number",
               '10': "GPS Location",
               '20': "NET-based Location",
               '40': "Last known Location",
               '80': "camera",
               '100': "accelerometer",
               '200': "SMS",
               '400': "IMEI",
               '800': "IMSI",
               '1000': "ICCID (SIM card identifier)",
               '2000': "Device serial number",
               '4000': "User account information",
               '8000': "browser history"}

        MAP = {
            0x00000001: "Location",
            0x00000002: "Address Book (ContactsProvider)",
            0x00000004: "Microphone Input",
            0x00000008: "Phone Number",
            0x00000010: "GPS Location",
            0x00000020: "NET-based Location",
            0x00000040: "Last known Location",
            0x00000080: "camera",
            0x00000100: "accelerometer",
            0x00000200: "SMS",
            0x00000400: "IMEI",
            0x00000800: "IMSI",
            0x00001000: "ICCID (SIM card identifier)",
            0x00002000: "Device serial number",
            0x00004000: "User account information",
            0x00008000: "browser history"
        }
        sub_msg = msg.split('0x')
        if len(sub_msg) < 2:
            return "Unknown"
        hex = sub_msg[1].split(' ')[0]
        taint = int(hex, 16)
        tags = []
        for i in range(32):
            t = (taint >> i) & 0x1
            t = int(t << i)

            if t in MAP:
                tags.append(MAP[t])
            else:
                pass
                # tags.append("Unknown")
        return tags

    @staticmethod
    def get_tainted_data(msg):
        sub_msg = msg.split('data[')
        if len(sub_msg) < 2:
            return "Unknown"
        return sub_msg[1]

    @staticmethod
    def collect_taint_log(taint_logs=[]):
        # You'll need to add any command line arguments here.
        process = subprocess.Popen(['adb', 'logcat', '-v', 'time', '-s', 'TaintLog'], stdout=subprocess.PIPE)

        # Launch the asynchronous readers of the process' stdout.
        stdout_queue = Queue.Queue()
        stdout_reader = AsynchronousFileReader(process.stdout, stdout_queue)
        stdout_reader.start()

        # Check the queues if we received some output (until there is nothing more to get).
        still_looking = True
        try:
            count = 0
            while still_looking and not stdout_reader.eof():
                while not stdout_queue.empty():
                    line = stdout_queue.get().split('\n')[0]
                    print count, line
                    taint_log = TaintDroidLogHandler.parse_taint_log(line)
                    print taint_log
                    if taint_log != None:
                        taint_logs.append(taint_log)
                    count += 1
                    if count > 2:
                        still_looking = False
        finally:
            process.kill()
            return taint_logs


if __name__ == '__main__':
    print TaintDroidLogHandler.collect_taint_log()
