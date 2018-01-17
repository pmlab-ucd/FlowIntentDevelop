#!/usr/bin/python3
# -*- coding:utf8 -*-
import os
from bs4 import BeautifulSoup as bs
import re
import jieba


class SharingInstance:
    word_topic = {'topic_health': [u'健身', u'运动', u'健康', u'体重', u'身体', u'锻炼'],
                  'topic_sports': [u'足球', u'队员', u'篮球', u'跑步'],
                  'topic_weather': [u'天气', u'预报', u'温度', u'湿度', 'PM2\.5'],
                  'topic_map': [u'旅行', u'地图', u'地理', u'GPS', u'导航', u'旅游']}

    @staticmethod
    def find_html(dir):
        for root, dirs, files in os.walk(dir):
            for filename in files:
                if filename.endswith('.html'):
                    return os.path.join(root, filename)

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
    def str2words(str, wordlist):
        str = re.sub('°', 'DegreeMark', str)
        if SharingInstance.chinese(str):
            print('Chinese Detected!')
            str = re.sub(u'[^\u4e00-\u9fa5]', '', str)
            words = jieba.cut(str, cut_all=False)
            # words = [w for w in words if not w in stopwords.words("chinese")]
        else:
            # print 'English Detected!'
            str = re.sub('[^a-zA-Z]', ' ', str)  # if English only
            words = str.lower().split()
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
            descsoup = bs(str(soup.select('.brief-long')), "html.parser")
            desc = str(descsoup.select('p')) # .split('data_url')[1]
            wordlist = []
            unseen = []
            SharingInstance.str2words(desc, wordlist)
            topic_word_counter = {}
            for word in wordlist:
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
        except IOError as e:
            print(e)
            return ['', None]

    def __init__(self, dir):
        self.dir = dir
        self.html = SharingInstance.find_html(dir)
        if self.html:
            self.topic, self.appname = SharingInstance.description(self.html)
            print(self.topic, self.appname)
        self.ui = ''


if __name__ == '__main__':
    instance = SharingInstance('C:/Users/hao/Documents/Ground/0/5/cn.apps123.shell.jiancaichuangxin')

