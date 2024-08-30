# Dongnipp

## 说明

Dongni++ (Dongnipp) 是一个基于[懂你教育平台](https://www.dongni100.com/)在网站中提供的公开API，对学生考试信息进行查询和解析的实用项目。

利用这一项目，你可以方便的查询如考试信息、考试分数、考试班级/年段排名等信息。

由于[懂你教育开放平台](https://open.dongni100.com/)没有开放注册，因此我们只能利用网页端学生账户抓取相关数据包，分析获取信息。

本仓库提供一个[Dongnipp/DongnippSDK.cs](https://github.com/Aunt-Studio/Dongnipp/blob/master/Dongnipp/DongnippSDK.cs), 可以实现类似于SDK的方便快捷API调用方法, 便于二次开发; 以及一个Demo 测试程序[Program.cs](https://github.com/Aunt-Studio/Dongnipp/blob/master/Dongnipp/Program.cs)便于测试*DongnippSDK.cs*的各种方法，以及二次开发的参考。

您可以直接将本仓库导入Microsoft Visual Studio，运行即可体验Dongni++ 提供的查询方法。

## SDK 文档

您可以前往 https://dongnipp.auntstudio.com/ 查看Dongni++ SDK 的所有类以及提供的方法。

这一版本的 SDK 充分利用了[面向对象编程(OOP)](https://zh.wikipedia.org/wiki/面向对象程序设计) 的程序设计思想以及特性。使得整体代码可维护性相对于初始版本的SDK 更高，也更加方便了二次开发。

---

## License | 许可证与版权声明
This project is licensed under [the MIT License](https://opensource.org/license/mit/).

Copyright © 2024 Aunt Studio

**不建议商业用途。一切使用本项目任何内容造成的后果由您自行承担。本项目版权所有者以及开发者、贡献者不对用户产生的行为负责任。**

**Commercial usage is not recommended. You are solely responsible for any consequences resulting from the use of any content in this project. The copyright owners, developers, and contributors of this project are not responsible for the actions of users.**

### [Newtonsoft.Json](https://www.newtonsoft.com/json)
Copyright © 2007 James Newton-King

Licensed under [the MIT License](https://opensource.org/license/mit/).

### [BouncyCastle.Cryptography](https://www.bouncycastle.org/csharp)
Copyright © 2000-2024 [The Legion of the Bouncy Castle Inc](https://www.bouncycastle.org)

Licensed under [the MIT License](https://opensource.org/license/mit/).


