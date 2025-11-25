# 编译
```
$ go build
```
# 用法

### 初始化
```
$ ./ca_demo cinit

# 如果你想用标准的 P256 曲线：
$ ./ca_demo cinit_p256
```

### 运行
```
$ ./ca_demo crun
```

### 获得打包的证书
```
$ curl -sS --output bundle.zip localhost:10003/get_bundle?cn=test_common_name

$ unzip bundle.zip
```
