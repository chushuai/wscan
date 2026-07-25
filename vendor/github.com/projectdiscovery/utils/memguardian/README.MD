## Mem Guardian Usage Guide

### Environment Variables

- `MEMGUARDIAN`: Enable or disable memguardian. Set to 1 to enable
- `MEMGUARDIAN_MAX_RAM_RATIO`: Maximum ram ratio from 1 to 100
- `MEMGUARDIAN_MAX_RAM`: Maximum amount of RAM (in size units ex: 10gb)
- `MEMGUARDIAN_INTERVAL`: detection interval (with unit ex: 30s)



## How to Use

1. Set the environment variables as per your requirements.

```bash
export MEMGUARDIAN=1
export MEMGUARDIAN_MAX_RAM_RATIO=75 # default
export MEMGUARDIAN_MAX_RAM=6Gb # optional
export MEMGUARDIAN_INTERVAL=30s # default
```

2. Run your Go application. The profiler will start automatically if MEMGUARDIAN is set to 1.