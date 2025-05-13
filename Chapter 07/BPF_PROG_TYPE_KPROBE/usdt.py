from bcc import BPF, USDT

usdt_ctx = USDT(path='/usr/bin/mysql')
usdt_ctx.enable_probe(probe="operation_start", fn_name="trace_operation_start")