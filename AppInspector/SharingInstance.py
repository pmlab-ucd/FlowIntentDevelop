#!/usr/bin/python3
# -*- coding:utf8 -*-
import os
from bs4 import BeautifulSoup as bs
import re
import jieba
from xml.dom.minidom import parseString
import hashlib
from pprint import pprint
import json


class SharingInstance:
    word_topic = {'topic_health': [u'健身', u'运动', u'健康', u'体重', u'身体', u'锻炼'],
                  'topic_sports': [u'足球', u'队员', u'篮球', u'跑步'],
                  'topic_weather': [u'天气', u'预报', u'温度', u'湿度', 'PM2\.5'],
                  'topic_map': [u'旅行', u'地图', u'地理', u'GPS', u'导航', u'旅游']}

    @staticmethod
    def find_html(data_dir):
        for filename in os.listdir(data_dir):
            if filename.endswith('.html'):
                return os.path.join(data_dir, filename)

    @staticmethod
    def chinese(content):
        """
        判断是否是中文需要满足u'[\u4e00-\u9fa5]+'，
        需要注意如果正则表达式的模式中使用unicode，那么
        要匹配的字符串也必须转换为unicode，否则肯定会不匹配。
        """
        zhPattern = re.compile(u'[\u4e00-\u9fa5]+')
        return zhPattern.search(content)

    @staticmethod
    def str2words(string, wordlist):
        string = re.sub('°', 'DegreeMark', string)
        if SharingInstance.chinese(string):
            print('Chinese Detected!')
            string = re.sub(u'[^\u4e00-\u9fa5]', '', string)
            words = jieba.cut(string, cut_all=False)
            # words = [w for w in words if not w in stopwords.words("chinese")]
        else:
            # print 'English Detected!'
            string = re.sub('[^a-zA-Z]', ' ', string)  # if English only
            words = string.lower().split()
            # words = [w for w in words if not w in stopwords.words("english")]
            # print words

        # print '/'.join(words) #  do not use print if you want to return
        for word in words:
            wordlist.append(word)
        # return ' '.join(words)
        return words

    @staticmethod
    def description(html):
        try:
            soup = bs(open(html, 'r', encoding="utf8"), "html.parser")
            appname_soup = bs(str(soup.select('.app-name')), "html.parser")
            appname = appname_soup.span.string
            desc_soup = bs(str(soup.select('.brief-long')), "html.parser")
            desc = str(desc_soup.select('p')) # .split('data_url')[1]
            word_list = []
            unseen = []
            SharingInstance.str2words(desc, word_list)
            topic_word_counter = {}
            for word in word_list:
                if word in unseen:
                    # print word
                    continue
                else:
                    # print word
                    unseen.append(word)
                    for topic in SharingInstance.word_topic.keys():
                        if word in SharingInstance.word_topic[topic]:
                            print(word)
                            if topic not in topic_word_counter.keys():
                                topic_word_counter[topic] = 1
                            else:
                                topic_word_counter[topic] += 1
                            break
            if len(topic_word_counter) == 0:
                return ['', appname]
            for topic in sorted(topic_word_counter, key=topic_word_counter.get, reverse=True):
                return [topic, appname]
        except:
            return ['', None]

    @staticmethod
    def find_xmls(data_dir):
        xmls = []
        for file_name in os.listdir(data_dir):
            if file_name.endswith('.xml'):
                xmls.append(os.path.join(data_dir, file_name))
        return xmls

    @staticmethod
    def hier_xml(xml_path):
        all_views = []
        doc = []
        if os.path.exists(xml_path):
            with open(xml_path, 'rb') as f:
                try:
                    data = f.read()
                    dom = parseString(data)
                    nodes = dom.getElementsByTagName('node')
                    # Iterate over all the uses-permission nodes
                    for node in nodes:
                        if node.getAttribute('text') != '':
                            doc.append(node.getAttribute('text'))
                        # print(node.getAttribute('text'))
                        # print(node.toxml())
                        if node.getAttribute('package') in str(xml_path):
                            all_views.append(node)

                    print(doc)
                except:
                    print(xml_path)
        else:
            print('XML ' + xml_path + ' does not exist!')
        return all_views, doc

    @staticmethod
    def instances(root_dir):
        instances = []
        for root, dirs, files in os.walk(root_dir):
            for dir in dirs:
                if len(SharingInstance.find_xmls(os.path.join(root, dir))) > 0:
                    instances.append(SharingInstance(os.path.join(root, dir)))
        return instances

    def __init__(self, data_dir):
        self.dir = data_dir
        self.id = os.path.basename(data_dir)
        self.doc = []
        # Collect the topic and the app name from the html
        self.html = SharingInstance.find_html(data_dir)
        self.topic = ''
        self.appname = ''
        #self.views = []
        self.ui_doc = ''
        self.xml = ''
        if self.html:
            self.topic, self.appname = SharingInstance.description(self.html)
            self.doc.append(self.topic)
            self.doc.append(self.appname)
            print(self.topic, self.appname)
        # Parse user interfaces
        xmls = SharingInstance.find_xmls(data_dir)
        length = 0
        for xml in xmls:
            views, doc = SharingInstance.hier_xml(xml)
            if len(views) >= length:
                self.xml = xml
                #self.views = views
                self.ui_doc = doc
                length = len(views)
        self.doc.append(self.ui_doc)
        print(self.doc)

    def json(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4, ensure_ascii=False)


if __name__ == '__main__':
    instance = SharingInstance('C:/Users/hao/Documents/Ground/0/5/cn.apps123.shell.jiancaichuangxin')
    print(json.loads(instance.json()))
    with open('test.json', 'w', encoding="utf8") as outfile:
        outfile.write(instance.json())
    with open('test.json', 'r', encoding="utf8") as outfile:
        data = json.load(outfile)
        print(data)

    root_dir = 'C:/Users/hao/Documents/Ground/0/'
    instances_dir_name = hashlib.md5(root_dir.encode('utf-8')).hexdigest()
    instances_dir_path = os.path.join('data', instances_dir_name)
    if not os.path.exists(instances_dir_path):
        os.makedirs(instances_dir_path)
        instances = SharingInstance.instances(root_dir)
        for instance in instances:
            with open(os.path.join(instances_dir_path, instance.id + '.json'), 'w', encoding="utf8") as outfile:
                outfile.write(instance.json())
    else:
        instances = []
        for root, dirs, files in os.walk(instances_dir_path):
            for file_name in files:
                if file_name.endswith('.json'):
                    with open(os.path.join(root, file_name), 'r', encoding="utf8") as myfile:
                        instance = json.load(myfile)
                        print(instance)
                        instances.append(instance)
    print(len(instances))




