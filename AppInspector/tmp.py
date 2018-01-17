import jieba

words = jieba.cut("关于我们'", cut_all=False)
print("Default Mode: " + "/ ".join(words))  # 精确模式