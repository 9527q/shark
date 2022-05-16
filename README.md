# shark

抓包工具实现

## 格式化

```shell
# 对未 git-add、commit 的文件依次执行 isort、balck 和 flake8
F=$(git status -s | grep -E '(\.py)|(/)$' | cut -c 4-); isort `echo $F`; black `echo $F`; flake8 `echo $F`; unset F
```