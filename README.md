# throughput

## Linux

### Investigating dropped UDP packets

You may be easily dropping packets so check `net.core.rmem_max` and maybe do `sudo sysctl -w net.core.rmem_max=2048000000`.

You can check out https://github.com/nhorman/dropwatch and then use `sudo dropwatch -l kas` followed by `start` which is easier to work with then netstat as described below.

## macOS

### Investigating dropped UDP packets

If you're experiencing this, definitely turn on trace logging `PION_LOG_TRACE=all` to see if anything in the pion stack is dropping packets. If you want to know if any packets dropped at the OS level, run: `netstat -s | grep "dropped due to full socket buffers"` before and after to calculate how many packets were dropped.

You may want to check `sysctl net.inet.udp.recvspace` and increase the size if you want to make drops happen at the OS level or avoid them (`sysctl -w net.inet.udp.recvspace=999999`)
