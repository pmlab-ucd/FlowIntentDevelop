from subprocess import STDOUT, check_output
import logging
import psutil
import threading
import os
import time

ISO_TIME_FORMAT = '%m%d-%H-%M-%S'


def set_logger(tag):
    logger = logging.getLogger(tag)
    logger.setLevel(logging.DEBUG)

    consolehandler = logging.StreamHandler()
    consolehandler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    consolehandler.setFormatter(formatter)

    logger.addHandler(consolehandler)
    return logger


logger = set_logger('Utilities')


def run_cmd(cmd):
    logger.debug('Run cmd: ' + cmd)

    seconds = 60
    result = True
    for i in range(1, 3):
        try:
            result = True
            output = check_output(cmd, stderr=STDOUT, timeout=seconds)
            for line in output.split('\n'):
                if 'Failure' in line or 'Error' in line:
                    result = False
                tmp = line.replace(' ', '')
                tmp = tmp.replace('\n', '')
                if tmp != '':
                    Utilities.logger.debug(line)
            break
        except Exception as exc:
            Utilities.logger.warn(exc)
            result = False
            if i == 2:
                # close_emulator(emu_proc)
                # emu_proc = open_emu(emu_loc, emu_name)
                raise Exception(cmd)

    return result


def set_file_log(logger, file_path):
    file_handler = logging.FileHandler(file_path, mode='w')
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    return file_handler


def kill(proc_pid):
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()


def kill_proc_tree(pid, including_parent=True):
    parent = psutil.Process(pid)
    children = parent.children(recursive=True)
    for child in children:
        child.kill()
    psutil.wait_procs(children, timeout=5)
    if including_parent:
        parent.kill()
        parent.wait(5)


def run_method(target, timeout, args=[]):
    p = threading.Thread(target=target, args=args)
    p.start()
    # Wait for 120 seconds or until process finishes
    p.join(timeout)
    # If thread is still active
    if p.is_alive():
        # Terminate
        # p.terminate()
        logger.warn('Timeout!!!')
        try:
            kill_proc_tree(p.ident, including_parent=False)
        except psutil.NoSuchProcess:
            return False
        p.join()
        return False
    else:
        return True


def adb_process2ids(name):
    seconds = 60
    output = check_output('adb shell ps', stderr=STDOUT, timeout=seconds)
    targets = []
    for line in output.split('\n'):
        # print line
        tmp = line.replace(' ', '')
        tmp = tmp.replace('\n', '')
        if tmp != '':
            # print line
            items = str(line).split(' ')
            items = filter(None, items)
            if name in items[len(items) - 1]:
                targets.append(items[1])
    return targets


def adb_id2process(pid):
    seconds = 60
    output = check_output('adb shell ps', stderr=STDOUT, timeout=seconds)
    for line in output.split('\n'):
        # print line
        tmp = line.replace(' ', '')
        tmp = tmp.replace('\n', '')
        if tmp != '':
            # print line
            items = str(line).split(' ')
            items = filter(None, items)
            if pid == items[1]:
                return items[len(items) - 1]
    else:
        return 'Unknown'


def adb_kill(name):
    for target in adb_process2ids(name):
        os.popen('adb shell kill ' + target)


def kill_by_name(name):
    for proc in psutil.process_iter():
        # check whether the process name matches
        if proc.name() == name:
            kill()


def current_time():
    return time.strftime(ISO_TIME_FORMAT, time.localtime())
