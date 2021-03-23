# imoki-poc
用于批量检测ip是否存在某漏洞
文件简要说明：
1.fofa.py文件，用于爬取待测试的ip（遵循fofa语法）,将ip写入url.txt文件
2.imoki_poc.py文件，为主要的测试代码，无特殊情况不需要变化
3.config.py文件，只需要往config.py文件添加内容就可以新增能测试的漏洞了（每一个测试模块用class封装了，只用填写headers，data，请求行, 还有判断响应包出现什么信息说明存在漏洞）即可

执行：
1.收集url，根据输入关键词爬取url（cookie文件填写_fofapro_ars_session的值，在file文件夹下README.docx有说明获取方法）
python fofa.py
2.执行，选择相应模块即可对上面收集到的url测试
python imoki_poc.py -p <payload>
例如:
python imoki_poc.py -p CVE_2018_7600
