import time

start = time.time()
with open("f.log", "w") as f:
    for i in range(10 ^ 7):
        f.write("A")
end = time.time()
print(end - start)


B = "A"
start = time.time()
with open("f.log", "w") as f:
    for i in range(10 ^ 7):
        f.write(B)
end = time.time()
print(end - start)
