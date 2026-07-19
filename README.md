# Token Scanner - Burp Suite Extension

一个用于检测HTTP请求/响应中敏感关键字的Burp Suite扩展。

## 功能特性

- **实时监控**: 自动检测通过Burp Proxy的HTTP流量
- **多关键字支持**: 可配置多个监控关键字（逗号分隔）
- **灵活监控范围**: 可选择监控请求包、响应包或两者
- **智能搜索**: 点击记录自动搜索匹配的关键字，重复点击循环切换
- **原生UI**: 使用Burp原生编辑器显示请求/响应，样式一致
- **Tab闪烁提醒**: 检测到关键字时Tab标题黄色闪烁

## 项目结构

```
敏感信息扫描/
├── v1/                     # 基础版
│   ├── src/main/java/
│   └── build/libs/TokenScanner-1.0.jar
├── v2/                     # 完整版（推荐）
│   ├── src/main/java/
│   └── build/libs/TokenScanner-1.0.jar
└── README.md
```

## 编译方法

### 环境要求

- **JDK 21+** (推荐 Eclipse Adoptium Temurin)
- **Gradle 8.5+** (或使用项目自带的Gradle Wrapper)

### 方法一：使用Gradle Wrapper（推荐）

```bash
# 进入项目目录
cd v2

# Windows
gradlew.bat clean jar

# Linux/macOS
./gradlew clean jar
```

编译完成后，JAR文件位于：`build/libs/TokenScanner-1.0.jar`

### 方法二：使用全局Gradle

```bash
# 进入项目目录
cd v2

# 编译
gradle clean jar
```

### 方法三：使用IDE（IntelliJ IDEA）

1. 打开 IntelliJ IDEA
2. 选择 `File > Open`，选择 `v2` 目录
3. 等待 Gradle 同步完成
4. 右键 `build.gradle.kts` > `Run 'build'`
5. 或使用终端运行：`./gradlew jar`

## 安装到Burp Suite

1. 打开 Burp Suite
2. 进入 `Extensions > Installed`
3. 点击 `Add`
4. 选择 `Extension type: Java`
5. 选择编译好的 `TokenScanner-1.0.jar`
6. 点击 `Next > Close`

## 使用说明

### 历史记录 (History)

- 表格显示所有检测到的记录
- 字段：#、Host、Method、URL、Status、Length、MIME、IP、Time、Source、Matched
- 点击记录查看请求/响应详情
- 重复点击同一行循环切换搜索关键字

### 设置 (Settings)

- **Monitor Keywords**: 输入监控关键字，逗号分隔（默认：token）
- **Monitor Scope**: 选择监控范围
  - Monitor Both Request & Response（默认）
  - Monitor Request Only
  - Monitor Response Only
- 点击 `Save Settings` 保存

## 开发说明

### 技术栈

- Java 21
- Montoya API (Burp Suite Extensions API)
- Swing (GUI)

### 关键接口

- `ProxyRequestHandler` - 监听HTTP请求
- `ProxyResponseHandler` - 监听HTTP响应
- `HttpRequestEditor` / `HttpResponseEditor` - 原生请求/响应编辑器

### 添加新功能

1. 修改 `src/main/java/burp/extension/TokenScanner.java`
2. 运行 `gradle clean jar` 重新编译
3. 在Burp中重新加载扩展

## License

MIT
