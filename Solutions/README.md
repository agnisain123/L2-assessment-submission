# Steps to run

Use Git Bash on Windows, or any bash supported terminal in other Operating Systems.
```
cd solutions
```

## Task 1

```bash
python task_1.py
```

## Task 2
```bash
python task_2.py
```

## Task 3
```bash
bash task_3.sh
```

## Task 4
```bash
sqlite3 ../problems/traffic.db <<EOF
.mode column
.headers on
.output result.txt
.read task_4.sql
EOF
```
