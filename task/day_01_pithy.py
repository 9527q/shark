with open("./data01.jpg", "rb") as f:
    arr = b''.join(f.read(64) for i in (0, 2) if f.seek(i * -32, i) or 1)
    for i, int_b in enumerate(arr):
        print(f"{int_b:0>2X}", end="\n "[bool((i + 1) % 8)])
