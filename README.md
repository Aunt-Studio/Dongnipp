# Dongni++ NuGet 包

## Dongni++ 概述

[Dongni++ 项目](https://github.com/orgs/Aunt-Studio/projects/1) 的设计初衷是作为学生使用懂你教育平台的辅助。由于懂你教育平台由于政策原因不在前端直接展示具体排名，因而对于需要学生自行量化考评的场景存在一定局限性。

本项目尝试利用了懂你教育平台的一系列 API 接口，通过这些接口来获取前端没有直接展示的排名、成绩等数据。

目前本项目提供了一个 SDK，可以实现基础的考试信息查询（例如成绩、排名...），提供了高度的集成性和可扩展性。

未来将尝试基于本 SDK，开发更多使用工具，以实现我们的初衷。

## 快速开始

### 1. 创建项目

创建任意 .NET C# 项目，例如一个控制台应用程序。

### 2. 添加 NuGet 包引用

在项目根目录中打开终端，利用 .NET CLI 添加对 Dongni++ NuGet 包的引用：
```bash
dotnet add package com.AuntStudio.Dongnipp
```

### 3. 尝试调用 SDK

现在，你可以在项目中自由地使用 Dongni++ SDK 提供的功能了。

例如，对于控制台应用程序，你可以在 `Program.cs` 中添加如下代码：
```csharp
//...
using com.AuntStudio.Dongnipp.SDK;

namespace MyConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            DongnippSDK.DongniUser dongniUser;
            Console.WriteLine("\n请输入用户名 [通常为手机号]:");
            string userName = Console.ReadLine();
            Console.WriteLine("\n\n请输入密码:");
            string password = Console.ReadLine();
            dongniUser = await DongnippSDK.DongniUser.Login(userName, password);
            Console.WriteLine($"你好, {dongniUser.NickName}!");
        }
    }
}
```

现在，生成并运行程序，输入你的懂你平台用户名密码，即可看到你的昵称。

---

## 开发设计

更多功能请参考 [Dongni++ SDK 开发设计文档](https://dongnipp.auntstudio.com/) 进行开发设计。

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
