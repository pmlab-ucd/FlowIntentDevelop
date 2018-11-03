#!/usr/bin/env python2
# -*-encoding:utf-8-*-
__author__ = 'Hao Fu'

import os
import time
import difflib
import subprocess
import re
from subprocess32 import STDOUT, check_output, Popen, PIPE
from uiautomator import Device  # device as dev
import logging

def run_cmd(cmd):
    global emu_proc
    logger.debug('Run cmd: ' + cmd)

    seconds = 60
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
                    logger.debug(line)
            break
        except Exception as exc:
            logger.warn(exc)
            result = False
            if i == 2:
                close_emulator(emu_proc)
                emu_proc = open_emu(emu_loc, emu_name)
                #raise Exception(cmd)
    return result

# get app name
def appName():
    cmd = 'adb -s ' + series + ' shell pm list packages'
    app_process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, shell=True)
    # p = check_output(cmd, shell = True)
    app_process.wait()
    output = app_process.stdout.readlines()
    output = set(x.split(':')[1].strip() for x in output)
    return output


def touch(node_bounds):
    node_bounds = node_bounds[1: len(node_bounds) - 1]
    node_bounds = node_bounds.split('][')
    node_bounds[0] = node_bounds[0].split(',')
    node_bounds[0] = map(float, node_bounds[0])
    node_bounds[1] = node_bounds[1].split(',')
    node_bounds[1] = map(float, node_bounds[1])
    x = 0.5 * (node_bounds[1][0] - node_bounds[0][0]) + node_bounds[0][0]
    y = 0.5 * (node_bounds[1][1] - node_bounds[0][1]) + node_bounds[0][1]
    dev.click(x, y)


def ui_interact():
    for i in range(8):
        time.sleep(1)
        try:
            xml = dev.dump()
        except:
            return
        scroll = re.findall(r'.*?scrollable=\"true\".*?', xml)
        all_text = re.findall(r'.*?text=.*?', xml)
        none_text = re.findall(r'.*?text=\"\".*?', xml)
        if len(scroll) == 1 and (len(all_text) - len(none_text)) <= 2:
            # scroll = re.search(r'.*?scrollable=\"true\".*?bounds=\"(.*?)\"', xml)
            # dev.swipe(400, 0, 0, 0) # for 480 * 800
            dev.swipe(576, 473, 115, 473, 10)
        else:
            break
    # time.sleep(10)
    try:
        xml = dev.dump()
    except:
        return
    clickable = re.findall(r'.*?clickable=\"true\".*?bounds=\"(.*?)\"', xml)
    if len(clickable) == 1:
        node_bounds = clickable[0]
        touch(node_bounds)
        print 'click single'
    # if detect update info, if 取消， 否
    option_cancle = [u'否', u'取消', u'不升级', u'稍后再说', u'稍后', u'以后'
                                                          u'稍后更新', u'不更新', u'以后再说',
                     u'Not now', u'Cancel', u'以后更新']
    for i in range(5):
        time.sleep(2)
        try:
            xml = dev.dump()
        except:
            return
        clickable = re.findall(r'.*?clickable=\"true\".*?bounds=\"(.*?)\"', xml)
        if len(clickable) <= 3:
            print 'found two clickables'
            # re.findall(r'.*?text=\"(.*?)\".*?[^(text=)].*?clickable=\"true\".*?', xml)
            nodelist = xml.split('><')
            for line in nodelist:
                if re.search('.*?clickable=\"t.*?', line):
                    texts = re.findall(r'text="(.*?)"', line)
                    print texts
                    for text in texts:
                        if text in option_cancle:
                            clickable = re.findall(r'bounds=\"(.*?)\"', line)[0]
                            node_bounds = clickable
                            touch(node_bounds)
                            print 'click cancle'
                        else:
                            break


def get_apks(apk_dir):
    apk_list = []
    for root, dirs, files in os.walk(apk_dir, topdown=True):
        for name in files:
            # print(os.path.join(root, name))
            if str(name).endswith('.apk'):
                apk_list.append(os.path.join(root, name))
    return apk_list

series = 'emulator-5554'
# series = '014E233C1300800B'
# series = '0123456789ABCDEF'
# series = '01b7006e13dd12a1'
# appdir = '/media/hao/Hitachi/BaiduApks/software/504/18/LOC/'  # APP_WALLPAPER
appdir = 'C:\\Users\\hfu\\Documents\\apks'
# appdir = '/media/hao/Hitachi/Apps/SOCIAL/LOC/'
# os.popen('rm -r -f data')
os.popen('mkdir ' + appdir + 'data')
# package = 'com.google.android.deskclock'
# package = 'com.android.settings'
ISOTIMEFORMAT = '%m%d-%H-%M-%S'
# set threashold large to check behaviors underware
logger = logging.getLogger('UiDroid-Console')
logger.setLevel(logging.DEBUG)

consolehandler = logging.StreamHandler()
consolehandler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
consolehandler.setFormatter(formatter)

logger.addHandler(consolehandler)

# package_pattern = re.compile(r'.*apk')
register_pattern = re.compile(r'.*(Regis|REGIS|Sign|SIGN).*')
fline_pattern = re.compile(r'(.*?).json')

if __name__ == '__main__':
    apks = get_apks(appdir)
    dev = Device(series)
    for apk in apks:
        os.popen('adb devices')
        before = appName()
        os.popen('adb -s ' + series + ' install ' + appdir + apk)
        after = appName()
        applist = after - before
        if len(applist) != 1:
            logger.info(apk)
            logger.info(applist)
            logger.info('error! not a single app selected!')
            os.system('rm ' + apk)
            # break
            continue
        for package in applist:
            os.popen('adb -s ' + series + ' shell am start -n fu.hao.uidroid/.TaintDroidNotifyController')
            current_time = time.strftime(ISOTIMEFORMAT, time.localtime())
            os.popen('adb -s ' + series + ' shell "su 0 date -s `date +%Y%m%d.%H%M%S`"')
            os.popen('adb -s ' + series + ' shell monkey -p com.lexa.fakegps --ignore-crashes 1')
            flag = True
            while flag:
                try:
                    dev.info
                    flag = False
                except:
                    pass
            dev.screen.on()
            # dev(text='Set location').click()
            dev.click(300, 150)
            dev.press.back()
            os.popen('adb kill-server')
            os.popen('adb start-server')
            cmd = 'adb -s ' + series + ' shell "nohup /data/local/tcpdump -w /sdcard/' + package + current_time + '.pcap"'
            # os.system(cmd)
            subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, shell=True)
            logger.info('tcpdump begins')
            os.popen('adb -s ' + series + ' logcat -c')
            logger.info('clear logcat')
            dir_data = appdir + 'data/' + package + '/'
            os.popen('mkdir ' + dir_data)
            # os.popen('adb -s ' + series + ' shell "logcat -v threadtime | grep --line-buffered UiDroid_Taint > /sdcard/' + package + current_time +'.log " &')
            cmd = 'adb -s ' + series + ' shell "nohup logcat -v threadtime -s "UiDroid_Taint" > /sdcard/' + apk\
                  + current_time + '.log"'
            # os.system(cmd)
            subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, shell=True)
            logger.info('logcat start')
            # time.sleep(20)
            os.popen('adb -s ' + series + ' shell monkey -p ' + package + ' --ignore-crashes 1')

            # package_list = os.popen('adb -s ' + series + ' shell cat /data/system/packages.list')
            # logger.info(package_list.readlines())
            # ps_list = os.popen('adb -s ' + series + ' shell ps')
            # logger.info(ps_list.readlines())
            flag = True
            while flag:
                try:
                    filehandler = logging.FileHandler(dir_data + '/UiDroid-Console.log')
                    filehandler.setLevel(logging.DEBUG)
                    logger.addHandler(filehandler)
                    filehandler.setFormatter(formatter)

                    # time.sleep(30)
                    ui_interact()
                    flag = False
                except:
                    pass
            # dev.screenshot(dir_data + current_time + ".png")
            os.system('adb -s ' + series + ' shell /system/bin/screencap -p /sdcard/screenshot.png')
            os.system('adb -s ' + series + ' pull /sdcard/screenshot.png ' + dir_data)
            try:
                dev.dump(dir_data + current_time + "hierarchy.xml")
            except:
                print 'except xml'
            logger.info('screen shot at ' + current_time)

            dev.screen.on()
            dev.press.home()
            # time.sleep(20)
            # package_list = os.popen('adb -s ' + series + ' shell cat /data/system/packages.list')
            # logger.info(package_list.readlines())
            # ps_list = os.popen('adb -s ' + series + ' shell ps')
            # logger.info(ps_list.readlines())
            os.popen('adb -s ' + series + ' shell am force-stop ' + package)
            os.popen('adb -s ' + series + ' uninstall ' + package)
            logger.info('uninstall')
            os.popen('adb -s ' + series + ' logcat -c')
            kill_status = os.popen(
                'adb -s ' + series + ' shell ps | grep logcat | awk \'{print $2}\' | xargs adb -s ' + series + ' shell kill')
            logger.info(kill_status.readlines())
            kill_status = os.popen(
                'adb -s ' + series + ' shell ps | grep tcpdump | awk \'{print $2}\' | xargs adb -s ' + series + ' shell kill')
            logger.info(kill_status.readlines())
            kill_status = os.popen('adb -s ' + series + ' shell am force-stop fu.hao.uidroid')
            logger.info(kill_status.readlines())
            pull_status = os.popen('adb -s ' + series + ' pull /sdcard/' + package + current_time + '.pcap ' + dir_data)
            logger.info(pull_status.readlines())
            os.popen('adb -s ' + series + ' shell rm /sdcard/' + package + current_time + '.pcap')
            pull_status = os.popen('adb -s ' + series + ' pull /sdcard/' + apk + current_time + '.log ' + dir_data)
            logger.info(pull_status.readlines())
            os.popen('adb -s ' + series + ' shell rm /sdcard/' + apk + current_time + '.log')
            os.system('mv ' + appdir + apk + ' ' + dir_data)
