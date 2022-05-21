# shark

抓包工具实现

## 格式化

```shell
# 对未 git-add、commit 的文件依次执行 isort、balck 和 flake8
F=$(git status -s | grep -E '(\.py)|(/)$' | cut -c 4-); isort `echo $F`; black `echo $F`; flake8 `echo $F`; unset F
```

# 大 O 记号
big-O notation
> Mathematics is more in need <br />of good notations than <br />of new theorems.
> - Alan Turing

> 好读书不求甚解
> 每有会意，便欣然忘食
> ——陶渊明

（更关心足够大的问题，注重成本增长趋势）<br />渐进分析 Asymptotic analysis：当 n >> 2 后，对于规模为 n 的输入，算法的

- **需要的基本操作次数 T(n)？**
- 需占用的存储单元数 S(n)？
## 大 O 记号
$T(n) = O(\ f(n)\ )
\quad iff
\quad \exists \ c > 0，当 \ n>>2 \ 后，有 \ T(n) < c \cdot f(n)$
> iff（if and only if）：当且仅当 / 充要条件

由$T(n)$推导的过程中

- 常系数可忽略
- 低次项可忽略 
## 其他记号
### $\Omega$
$T(n) = \Omega(\ f(n)\ )$：一般体现的是算法最好的情况<br />$\exists \ c>0，当\ n>>2\ 时，有\ T(n)>c \cdot f(n)$
### $\Theta$
$T(n) = \Theta(\ f(n)\ )：$<br />$\exists \ c_1 > c_2 > 0，
当\ n >> 2\ 时，
有\ c_1 \cdot f(n) > T(n) > c_2 \cdot f(n)$<br />确界
# 常数复杂度 $O(1)$
constant function，最棒的算法<br />如 RAM 模型的各种基本操作<br />不含转向（循环、调用、递归等）的，一定是顺序执行，一定是 O(1) <br />但是包含转向的，未必不是 O(1)
# 对数/对数多项式 $O({\rm log}^c n)$
$O({\rm log}n)$，非常高效，复杂度无限趋近于常数
## 常底数忽略
$\forall\ a,\ b > 0,\ {\rm log}_a n
= {\rm log}_a b\ \cdot\ {\rm log}_b n
= \Theta({\rm log}_b n)$
## 常数次幂忽略
$\forall\ c > 0,\
{\rm log}n^c
= c \cdot {\rm log}n
= \Theta({\rm log}n)$
## 对数多项式 poly-log function
$123 * {\rm log}^{321} n
+ {\rm log}^{105}(n^2 - n + 1)
= \Theta({\rm log}^{321}n)$<br />简化方式同样是忽略常系数、低次项
# 多项式复杂度 $O(n^c)$
属于是**令人满意**的复杂度了
> 多项式 polynomial function

$a_k n^k
+ a_{k-1} n^{k-1}
+ ...
+ a_1n
+ a_0
= O(n^k),\ a_k > 0$
## 线性（linear function）O(n)
# 指数$O(2^n)$
> 指数 exponential function

通常认为这种复杂度不可接受<br />多项式到指数之间，是从有效算法到无效算法的分水岭
# 例题 2-Subset
其实是个 NPC 问题
## 问题描述
S 包含 n 个正整数，$\sum S = 2m$<br />S 是否有子集 T，满足 $\sum T = m$？
## 直觉算法
逐一枚举 S 的子集，并统计元素总和<br />所以就是幂集，总数有 $2^n$个 <br />另一个直觉：应该有更好的算法吧？实际没有<br />定理：2-Subset is NP-complete<br />**就目前的计算模型而言，不存在可在多项式时间内回答此问题的算法**<br />所以目前来看，上面那个直觉方案，就是最优了
