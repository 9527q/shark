# 大 O 记号
big-O notation
> Mathematics is more in need 
of good notations than 
of new theorems.
> - Alan Turing

> 好读书不求甚解
> 每有会意，便欣然忘食
> ——陶渊明

（更关心足够大的问题，注重成本增长趋势）
渐进分析 Asymptotic analysis：当 n >> 2 后，对于规模为 n 的输入，算法的

- **需要的基本操作次数 T(n)？**
- 需占用的存储单元数 S(n)？
## 大 O 记号
![](https://cdn.nlark.com/yuque/__latex/028fe52b1a7b935314ddc623bc0cefda.svg#card=math&code=T%28n%29%20%3D%20O%28%5C%20f%28n%29%5C%20%29%0A%5Cquad%20iff%0A%5Cquad%20%5Cexists%20%5C%20c%20%3E%200%EF%BC%8C%E5%BD%93%20%5C%20n%3E%3E2%20%5C%20%E5%90%8E%EF%BC%8C%E6%9C%89%20%5C%20T%28n%29%20%3C%20c%20%5Ccdot%20f%28n%29&id=rn8C5)
> iff（if and only if）：当且仅当 / 充要条件

由![](https://cdn.nlark.com/yuque/__latex/37842ded0afd966061c2e8ab01f51fe6.svg#card=math&code=T%28n%29&id=ixPWw)推导的过程中

- 常系数可忽略
- 低次项可忽略 
## 其他记号
### ![](https://cdn.nlark.com/yuque/__latex/ac952fb2338a5acc539486cbdcae059b.svg#card=math&code=%5COmega&id=G2zvM)
![](https://cdn.nlark.com/yuque/__latex/d1dfcea7c3a3ddab2d03bd5d5fcbfbf4.svg#card=math&code=T%28n%29%20%3D%20%5COmega%28%5C%20f%28n%29%5C%20%29&id=WU6vi)：一般体现的是算法最好的情况
![](https://cdn.nlark.com/yuque/__latex/881572c24c7b20702f61067aef6ec860.svg#card=math&code=%5Cexists%20%5C%20c%3E0%EF%BC%8C%E5%BD%93%5C%20n%3E%3E2%5C%20%E6%97%B6%EF%BC%8C%E6%9C%89%5C%20T%28n%29%3Ec%20%5Ccdot%20f%28n%29&id=iEudN)
### ![](https://cdn.nlark.com/yuque/__latex/63150fb6060b0eb84fbefba4d29f5502.svg#card=math&code=%5CTheta&id=N2EP7)
![](https://cdn.nlark.com/yuque/__latex/8eb56a2fc50beb2a3da77392b52829be.svg#card=math&code=T%28n%29%20%3D%20%5CTheta%28%5C%20f%28n%29%5C%20%29%EF%BC%9A&id=Q2iKt)
![](https://cdn.nlark.com/yuque/__latex/d788075003b9be86ac2429357df9124a.svg#card=math&code=%5Cexists%20%5C%20c_1%20%3E%20c_2%20%3E%200%EF%BC%8C%0A%E5%BD%93%5C%20n%20%3E%3E%202%5C%20%E6%97%B6%EF%BC%8C%0A%E6%9C%89%5C%20c_1%20%5Ccdot%20f%28n%29%20%3E%20T%28n%29%20%3E%20c_2%20%5Ccdot%20f%28n%29&id=xgvlK)
确界
# 常数复杂度 ![](https://cdn.nlark.com/yuque/__latex/a2006f1ac61cb1902beacb3e29fff089.svg#card=math&code=O%281%29&id=L629E)
constant function，最棒的算法
如 RAM 模型的各种基本操作
不含转向（循环、调用、递归等）的，一定是顺序执行，一定是 O(1) 
但是包含转向的，未必不是 O(1)
# 对数/对数多项式 ![](https://cdn.nlark.com/yuque/__latex/8745583d4f0eabf1276bf96106f068d8.svg#card=math&code=O%28%7B%5Crm%20log%7D%5Ec%20n%29&id=ldAGB)
![](https://cdn.nlark.com/yuque/__latex/8494a296ab346d3af363d1f536d35b5e.svg#card=math&code=O%28%7B%5Crm%20log%7Dn%29&id=hpEbJ)，非常高效，复杂度无限趋近于常数
## 常底数忽略
![](https://cdn.nlark.com/yuque/__latex/131c5e2b2dfab183b4367eea6697eb7a.svg#card=math&code=%5Cforall%5C%20a%2C%5C%20b%20%3E%200%2C%5C%20%7B%5Crm%20log%7D_a%20n%0A%3D%20%7B%5Crm%20log%7D_a%20b%5C%20%5Ccdot%5C%20%7B%5Crm%20log%7D_b%20n%0A%3D%20%5CTheta%28%7B%5Crm%20log%7D_b%20n%29&id=Wzw2i)
## 常数次幂忽略
![](https://cdn.nlark.com/yuque/__latex/e36e6c10d246b55d573ca9e58c7e085a.svg#card=math&code=%5Cforall%5C%20c%20%3E%200%2C%5C%0A%7B%5Crm%20log%7Dn%5Ec%0A%3D%20c%20%5Ccdot%20%7B%5Crm%20log%7Dn%0A%3D%20%5CTheta%28%7B%5Crm%20log%7Dn%29&id=ZiOPT)
## 对数多项式 poly-log function
![](https://cdn.nlark.com/yuque/__latex/157225e60c446b34a0baa432556722a6.svg#card=math&code=123%20%2A%20%7B%5Crm%20log%7D%5E%7B321%7D%20n%0A%2B%20%7B%5Crm%20log%7D%5E%7B105%7D%28n%5E2%20-%20n%20%2B%201%29%0A%3D%20%5CTheta%28%7B%5Crm%20log%7D%5E%7B321%7Dn%29&id=DYo23)
简化方式同样是忽略常系数、低次项
# 多项式复杂度 ![](https://cdn.nlark.com/yuque/__latex/dad257993111bdaed347fffd29811a93.svg#card=math&code=O%28n%5Ec%29&id=EZKLc)
属于是**令人满意**的复杂度了
> 多项式 polynomial function

![](https://cdn.nlark.com/yuque/__latex/c9ad6e932f2cb4b797f08ae5ab836edf.svg#card=math&code=a_k%20n%5Ek%0A%2B%20a_%7Bk-1%7D%20n%5E%7Bk-1%7D%0A%2B%20...%0A%2B%20a_1n%0A%2B%20a_0%0A%3D%20O%28n%5Ek%29%2C%5C%20a_k%20%3E%200&id=JmyUa)
## 线性（linear function）O(n)
# 指数![](https://cdn.nlark.com/yuque/__latex/7dcc5b553d4487018ef4f17d8da5e589.svg#card=math&code=O%282%5En%29&id=eW3f3)
> 指数 exponential function

通常认为这种复杂度不可接受
多项式到指数之间，是从有效算法到无效算法的分水岭
# 例题 2-Subset
其实是个 NPC 问题
## 问题描述
S 包含 n 个正整数，![](https://cdn.nlark.com/yuque/__latex/6f2ead944805738a177257510f817943.svg#card=math&code=%5Csum%20S%20%3D%202m&id=B5qVm)
S 是否有子集 T，满足 ![](https://cdn.nlark.com/yuque/__latex/a2a15aff2879090c0fffb14d477b6541.svg#card=math&code=%5Csum%20T%20%3D%20m&id=wFoLy)？
## 直觉算法
逐一枚举 S 的子集，并统计元素总和
所以就是幂集，总数有 ![](https://cdn.nlark.com/yuque/__latex/055ce37910d06a8239ef5a1ee87765f5.svg#card=math&code=2%5En&id=gRKcf)个 
另一个直觉：应该有更好的算法吧？实际没有
定理：2-Subset is NP-complete
**就目前的计算模型而言，不存在可在多项式时间内回答此问题的算法**
所以目前来看，上面那个直觉方案，就是最优了


