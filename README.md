以`WireGuard.conf`文件的参数为模板，`ips-v4.txt`文件中的数据为数据来源，批量生成WireGuard链接，输出到output.txt文件中。程序中内置Cloudflare WARP的54个端口(UPD)，特别适合使用WARP对应的WireGuard配置文件生成WireGuard链接。


### 一、ips-v4.txt文件

#### 1.支持的数据

每条数据独占一行。

```
1、IP => 例如：162.159.192.9、2606:4700:d1:79ab:f8c7:76fe:9449:355c
2、IP:PORT => 例如：162.159.192.9:2408、[2606:4700:d1:79ab:f8c7:76fe:9449:355c]:2408
3、CIDR => 例如：162.159.192.0/24、2606:4700:d0::/48
4、域名:端口 => 例如：engage.cloudflareclient.com:2408
```

#### 2.不支持的数据

除了支持的数据中列举出来的，其它数据不支持。

```
域名 => 例如：engage.cloudflareclient.com、cloudflareclient.com（不管是顶级域名，还是二、三级域名，没有端口的，都不支持的）
```

### 二、哪些情况才使用程序内置的端口？

```
1、ip => 162.159.192.9、2606:4700:d1:79ab:f8c7:76fe:9449:355c
2、CIDR => 162.159.192.0/24、2606:4700:d0::/48
```

### 三、相关截图

<img src="images\生成节点1.png" />

<img src="images\生成节点2.png" />

<img src="images\v2rayN中使用.png" />

### 四、温馨提示

目前支持WireGuard协议前缀的链接，只有[新版v2rayN客户端](https://github.com/2dust/v2rayN/releases)支持使用。WireGuard链接的格式如下：

```
wireguard://OOrigZsSjw2YaY4urjbbU4%2FBNOZKXqW6EYNm8XKLtkU%3D@162.159.192.127:7152/?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A82ce%3Abdeb%3Ae72d%3A572a%3Ae280%2F128&mtu=1280#162.159.192.127%3A7152
```