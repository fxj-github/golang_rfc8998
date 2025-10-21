# 简介
这个项目主要是增加 golang 对 RFC8998 的支持。
https://www.rfc-editor.org/rfc/rfc8998.html

支持 RFC8998 需要支持国密标准里的 SM2/SM3/SM4。
https://github.com/guanzhi/GM-Standards

考虑到 SM2 和 golang 原生支持的椭圆曲线 P256 非常相似，
只有几个参数的不同。所以本实现参考 P256 的代码支持 SM2，
并且在 amd64 以及 arm64 上基于汇编语言实现以达到最好的性能。

SM2 的实现还参考了 fabric 国密改造的代码。

SM3/SM4 参考 linux 内核的代码实现。

不做成独立的 module 而是 patch 的形式，基于以下考虑:
1. golang 直接以源代码形式发布，便于 patch。
2. SM2 和 P256 曲线非常相似，可以参考 P256 的代码，得到快速以及高质量的实现。
   这样，SM2 就像 golang 原生支持的椭圆曲线一样，可以使用 P256 相同的 api。  
3. x509 以及 tls 非常复杂，基于 golang 的原生实现，可以只做非常少的修改。
4. 随着 golang 发布新版本，只需要更新相关 patch 即可，以最小代价获得对最新 golang 版本的支持。

# 用法
### 生成 patch:
```
git clone https://github.com/fxj-github/golang_rfc8998
cd golang_rfc8998/golang
git diff --binary 1d296f9b41871332de26c1bfa5b384704c59689d 1.25 > /tmp/go1.25.patch
```
### 把上述 patch 应用到本地 go 安装文件上 （这里可能需要切换成 root 用户或者使用 sudo):
```
cd /path/to/go
git apply --verbose -p3 < /tmp/go1.25.patch
```
当前这个 patch 支持 golang 1.25.0/1.25.1/1.25.2/1.25.3。

# 测试
```
cd golang_rfc8998/examples/bench_sm2
go run ./bench.go
```
如果能正常运行，那就没问题了。

# 性能
上述 bench 测试结果如下:

| arch | cpu | sign/verify |
| ---- | --- | ----------- |
| amd64 | Intel(R) Core(TM)2 Duo CPU P8400 @ 2.26GHz | 5500/2800 |
| amd64 | Intel(R) Xeon(R) E-2224 CPU @ 3.40GHz | 21000/12800 |
| arm64 | raspberry pi 400 | 4500/2500 |
