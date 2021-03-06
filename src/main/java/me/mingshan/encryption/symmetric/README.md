# 对称加密算法

对称加密指的就是加密和解密使用同一个秘钥，所以叫做对称加密。对称加密只有一个秘钥，作为私钥。
具体的算法有：DES、3DES、TDEA、Blowfish、RC5、IDEA。但是我们常见的有：DES、AES 等等。

那么对称加密的优点是什么呢？算法公开、计算量小、加密速度快、加密效率高。缺点就是秘钥的管理和分发是非常困难的，
不够安全。在数据传送前，发送方和接收方必须商定好秘钥，然后双方都必须要保存好秘钥，如果一方的秘钥被泄露了，
那么加密的信息也就不安全了。另外，每对用户每次使用对称加密算法时，都需要使用其他人不知道的唯一秘钥，
这会使得收、发双方所拥有的的钥匙数量巨大，秘钥管理也会成为双方的负担。

