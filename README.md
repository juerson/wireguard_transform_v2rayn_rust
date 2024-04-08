以`WireGuard.conf`文件的参数为模板，`*.csv`（csv后缀的所有文件）和`ips-v4.txt`文件中的数据为数据来源，批量生成WireGuard链接，输出到output.txt文件中。程序中内置Cloudflare WARP的54个端口(UDP)，特别适合使用WARP对应的WireGuard配置文件生成WireGuard链接。

### 一、程序运行，转换为WireGuard链接的流程图：

<img src="images\图1.png" />


### 二、ips-v4.txt文件和*.csv文件

**ips-v4.txt文件支持的数据：**

每条数据独占一行。遇到CIDR会生成IP地址，然后跟没有端口的数据一起添加WARP端口(UDP)。

```
1、IP => 例如：162.159.192.9、2606:4700:d1:79ab:f8c7:76fe:9449:355c
2、CIDR => 例如：162.159.192.0/24、2606:4700:d0::/48
3、域名 => engage.cloudflareclient.com、cloudflareclient.com（顶级域名/子域名）
4、IP:PORT => 例如：162.159.192.9:2408、[2606:4700:d1:79ab:f8c7:76fe:9449:355c]:2408
5、域名:端口 => 例如：engage.cloudflareclient.com:2408
```

***.csv文件支持的数据(第一列)：**

CSV文件的名称随意，程序会检查当前目录下所有的CSV文件，程序会提取CSV文件中，第一列是IP:PORT格式的数据。

```
1、IP:PORT => 例如：162.159.192.9:2408、[2606:4700:d1:79ab:f8c7:76fe:9449:355c]:2408
2、域名:端口 => 例如：engage.cloudflareclient.com:2408
```

注意：ips-v4.txt文件和CSV文件都存在，恰好都拥有数据，程序会同时处理的，最终生成的WireGuard链接，有端口的排在前面，如果数据太多，会导致自己不知道哪个文件为蓝本生成的wireguard链接在哪里？被干扰到。如果不想被太多数据干扰，就将ips-v4.txt文件或CSV文件的数据清空（或者删除其中的一个文件，保留另一个文件）。

### 三、哪些情况才使用程序内置的WARP端口(UDP)？

```
1、ip => 162.159.192.9、2606:4700:d1:79ab:f8c7:76fe:9449:355c
2、CIDR => 162.159.192.0/24、2606:4700:d0::/48
3、纯域名 => engage.cloudflareclient.com
```

### 四、其它截图

<img src="images\生成节点1.png" />

<img src="images\生成节点2.png" />

<img src="images\v2rayN中使用.png" />

### 五、温馨提示

目前支持WireGuard协议前缀的链接，只有[新版v2rayN客户端](https://github.com/2dust/v2rayN/releases)支持使用。WireGuard链接的格式如下：

```
wireguard://OOrigZsSjw2YaY4urjbbU4%2FBNOZKXqW6EYNm8XKLtkU%3D@162.159.192.127:7152/?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A82ce%3Abdeb%3Ae72d%3A572a%3Ae280%2F128&mtu=1280#162.159.192.127%3A7152
```

