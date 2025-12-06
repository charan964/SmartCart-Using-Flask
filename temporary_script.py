import re

with open("app.py","r") as f:
    code = f.read()

functions = re.findall(r"def (\w+)\(", code)

dupes = set([x for x in functions if functions.count(x) > 1])

print("Duplicate Functions Found:")
for d in dupes:
    print(" -", d)
