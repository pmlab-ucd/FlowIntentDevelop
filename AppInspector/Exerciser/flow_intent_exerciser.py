from ui_exerciser import UIExerciser
from utils import Utilities
import re
import os
import time

if __name__ == '__main__':
    ISOTIMEFORMAT = '%m%d-%H-%M-%S'
    logger = Utilities.set_logger('COSMOS_TRIGGER_PY-Console')

    device = 'nexus4'
    pc = 'iai'

    if device == 'nexus4':
        series = '01b7006e13dd12a1'
    elif device == 'galaxy':
        series = '014E233C1300800B'
    elif device == 'nexuss':
        series = '39302E8CEA9B00EC'
    else:
        series = 'emulator-5554'


    user = 'hfu'
    aapt_loc = 'C:\Users\\' + user + '\AppData\Local\Android\sdk/build-tools/19.1.0/aapt.exe'
    apk_dir = 'C:\Users\\' + user + '\Documents\FlowIntent\\apks\\VirusShare_Android_20130506_3\\'
    UIExerciser.emu_loc = 'C:\Users\hfu\AppData\Local\Android\sdk/tools/emulator.exe'
    UIExerciser.emu_name = 'Qvga'

    out_base_dir = os.path.abspath(os.pardir + '/output/') + '/'

    #UIExerciser.emu_proc = UIExerciser.open_emu(UIExerciser.emu_loc, UIExerciser.emu_name)
    examined = UIExerciser.check_examined(out_base_dir)
    for root, dirs, files in os.walk(apk_dir, topdown=False):
        for filename in files:
            if re.search('apk$', filename):
                # main_process = multiprocessing.Process(target=handle_apk, args=[os.path.join(root, filename), examined])
                # main_process.start()
                # main_process.join()
                for i in range(3):
                    try:
                        apk = os.path.join(root, filename)
                        exerciser = UIExerciser(series, aapt_loc, apk_dir, out_base_dir, logger)
                        exerciser.flowintent_first_page(series, os.path.join(root, filename), examined)
                        break
                    except Exception as e:
                        print e
                        UIExerciser.run_adb_cmd('reboot')
                        time.sleep(90)
