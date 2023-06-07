# RocketMQ协议

https://github.com/apache/rocketmq

RocketMQ协议基于TCP，是一种二进制协议。协议包括请求头和请求体，所有请求和响应均采用这种格式。核心类`org.apache.rocketmq.remoting.protocol.RemotingCommand`代表了一条远程命令（请求或响应），在Java代码中实现了相关协议规范。

参考：https://github.com/apache/rocketmq/blob/master/remoting/src/main/java/org/apache/rocketmq/remoting/protocol/RemotingCommand.java

RocketMQ——通信协议：https://jaskey.github.io/blog/2016/12/19/rocketmq-network-protocol/


**四个部分:**

1. length：4字节，2、3、4部分的整体长度。

2. headerlength：4字节，请求头的长度。

3. headerdata：请求头数据。

4. bodydata：请求体数据


### 协议检测

python3 rocketmq-protocol.py 生成十六进制字符串payload，将payload填入rocketmq-detect.nse脚本。

* 手动验证

```
echo -n '<十六进制字符串>' | xxd -r -ps ｜ nc <target> 9876
```

* nmap 调试

```
nmap -p 9876 --script /app/nse/rocketmq-detect  -d 3 --script-trace <target>
```