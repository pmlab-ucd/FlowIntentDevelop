from AppInspector.Exerciser.UIExerciser import UIExerciser
from utils import Utilities
import time
import os
from subprocess import STDOUT, Popen, PIPE
from AppInspector.Exerciser.TaintDroidLogHandler import TaintDroidLogHandler
import json
from uiautomator import Device


class FlowIntentExerciser(UIExerciser):
    logger = Utilities.set_logger('FlowIntentExerciser')

    def flowintent_first_page(self, series, apk, examined):
        """
        The version of SECON exerciser. Start the default activity and record the relevant data.
        :param series:
        :param apk:
        :param examined:
        :return:
        """
        current_time = time.strftime(Utilities.ISO_TIME_FORMAT, time.localtime())
        self.logger.info('base name: ' + os.path.basename(apk))
        apk_name, apk_extension = os.path.splitext(apk)

        self.logger.info(apk_name)

        apk_name = os.path.basename(apk_name)

        if apk_name in examined:
            self.logger.error('Already examined ' + apk_name)
            return

        cmd = 'adb devices'
        os.system(cmd)
        self.logger.info(apk)

        par_dir = os.path.basename(os.path.abspath(os.path.join(apk, os.pardir)))  # the parent folder of the apk

        package = self.get_package_name(self.aapt_loc, apk)

        if not package:
            self.logger.error('Not a valid pkg.')
            return

        # self.start_taintdroid(series)

        output_dir = self.out_base_dir + par_dir + '/' + apk_name + '/'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        file_handler = Utilities.set_file_log(self.logger, output_dir + 'FlowIntent_FP_PY.log')
        self.logger.info('apk:' + apk)
        self.logger.info('pkg:' + package)

        UIExerciser.uninstall_pkg(series, package)
        UIExerciser.install_apk(series, apk)

        # self.run_adb_cmd('shell am start -n fu.hao.uidroid/.TaintDroidNotifyController')
        self.run_adb_cmd('shell "su 0 date -s `date +%Y%m%d.%H%M%S`"')
        UIExerciser.run_adb_cmd('shell monkey -p com.lexa.fakegps --ignore-crashes 1')
        d = Device()
        d(text='Set location').click()

        UIExerciser.run_adb_cmd('logcat -c')
        self.logger.info('clear logcat')  # self.screenshot(output_dir, activity)

        # UIExerciser.run_adb_cmd('shell "nohup /data/local/tcpdump -w /sdcard/' + package + current_time  + '.pcap &"')
        # UIExerciser.run_adb_cmd('shell "nohup logcat -v threadtime -s "UiDroid_Taint" > /sdcard/' + package + current_time +'.log &"')

        # cmd = 'adb -s ' + series + ' shell "nohup /data/local/tcpdump -w /sdcard/' + package + current_time + '.pcap &"'
        self.logger.info('tcpdump begins')
        cmd = 'adb -s ' + series + ' shell /data/local/tcpdump -w /sdcard/' + package + '_' + current_time + '.pcap'
        # os.system(cmd)
        self.logger.info(cmd)
        process = Popen(cmd, stdout=PIPE, stderr=STDOUT, shell=True)

        UIExerciser.run_adb_cmd('shell monkey -p ' + package + '_' + ' --ignore-crashes 1')
        for times in range(1, 3):
            if not UIExerciser.check_dev_online(UIExerciser.series):
                if UIExerciser.emu_proc:
                    UIExerciser.close_emulator(UIExerciser.emu_proc)
                    UIExerciser.emu_proc = UIExerciser.open_emu(UIExerciser.emu_loc, UIExerciser.emu_name)
                else:
                    raise Exception('Cannot start the default Activity')
            if Utilities.run_method(self.screenshot, 180, args=[output_dir, '', True, package]):
                break
            else:
                self.logger.warn("Time out while dumping XML for the default activity")

        # UIExerciser.adb_kill('logcat')
        # Utilities.adb_kill('tcpdump')
        # UIExerciser.run_adb_cmd('shell am force-stop fu.hao.uidroid')
        # os.system("TASKKILL /F /PID {pid} /T".format(pid=process.pid))
        time.sleep(60)
        process.kill()  # takes more time
        out_pcap = output_dir + package + current_time  + '.pcap'
        while not os.path.exists(out_pcap) or os.stat(out_pcap).st_size < 2:
            time.sleep(5)
            cmd = 'pull /sdcard/' + package + '_' + current_time  + '.pcap ' + out_pcap
            UIExerciser.run_adb_cmd(cmd)
            if not os.path.exists(out_pcap):
                self.logger.warning('The pcap does not exist.')
                # raise Exception('The pcap does not exist.')
            else:
                UIExerciser.run_adb_cmd('shell rm /sdcard/' + package + current_time + '.pcap')

        # UIExerciser.run_adb_cmd('pull /sdcard/' + package + current_time + '.log ' + output_dir)
        # UIExerciser.run_adb_cmd('shell rm /sdcard/' + package + current_time + '.log')
        taint_logs = []
        Utilities.run_method(TaintDroidLogHandler.collect_taint_log, 15, args=[taint_logs])
        with open(output_dir + package + '_' + current_time + '.json', 'w') as outfile:
            json.dump(taint_logs, outfile)

        self.uninstall_pkg(series, package)
        self.logger.info('End')

        file_handler.close()
        self.logger.removeHandler(file_handler)
        Utilities.kill_by_name('adb.exe')


if __name__ == '__main__':
    device = 'nexus4'
    user = 'hfu'

    if device == 'nexus4':
        series = '01b7006e13dd12a1'
    elif device == 'galaxy':
        series = '014E233C1300800B'
    elif device == 'nexuss':
        series = '39302E8CEA9B00EC'
    else:
        series = 'emulator-5554'
        UIExerciser.emu_loc = 'C:\\Users\\' + user + '\AppData\Local\Android\sdk/tools/emulator.exe'
        UIExerciser.emu_name = 'Qvga'
        UIExerciser.emu_proc = UIExerciser.open_emu(UIExerciser.emu_loc, UIExerciser.emu_name)

    aapt_loc = 'C:\\Users\\' + user + '\AppData\Local\Android\sdk/build-tools/19.1.0/aapt.exe'
    apk_dir = 'C:\\Users\\' + user + '\Documents\FlowIntent\\apks\\VirusShare_Android_20130506_3\\'

    out_base_dir = os.path.abspath(os.pardir + '/output/') + '/'
    examined = UIExerciser.check_examined(out_base_dir)
    for root, dirs, files in os.walk(apk_dir, topdown=False):
        for filename in files:
            if filename.endswith('apk'):
                # main_process = multiprocessing.Process(target=handle_apk, args=[os.path.join(root, filename), examined])
                # main_process.start()
                # main_process.join()
                for i in range(3):
                    try:
                        apk = os.path.join(root, filename)
                        exerciser = FlowIntentExerciser(series, aapt_loc, apk_dir, out_base_dir)
                        exerciser.flowintent_first_page(series, os.path.join(root, filename), examined)
                        break
                    except Exception as e:
                        FlowIntentExerciser.logger.warn(e)
                        UIExerciser.run_adb_cmd('reboot')
                        time.sleep(90)
