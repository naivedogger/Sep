import os
import re

def parse_result_file(filepath):
    load_iops = None
    run_iops = None
    with open(filepath, "r") as f:
        for line in f:
            m = re.search(r"Load IOPS:([\d\.]+)Kops", line)
            if m:
                load_iops = float(m.group(1))
            m = re.search(r"Run IOPS:([\d\.]+)Kops", line)
            if m:
                run_iops = float(m.group(1))
    return load_iops, run_iops

def collect_results(root, out_dir, mode='a'):
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "stat_summary.tsv")
    write_header = (mode == 'w')
    with open(out_path, mode) as fout:
        if write_header:
            fout.write("root\tload_num\tworkload_type\top_type\tthreads\tcoros\tLoadIOPS(K)\tRunIOPS(K)\n")
        if not os.path.isdir(root):
            return
        for load_dir in sorted(os.listdir(root)):
            load_path = os.path.join(root, load_dir)
            if not os.path.isdir(load_path):
                continue
            for workload_dir in sorted(os.listdir(load_path)):
                workload_path = os.path.join(load_path, workload_dir)
                if not os.path.isdir(workload_path):
                    continue
                for op_type in sorted(os.listdir(workload_path)):
                    op_path = os.path.join(workload_path, op_type)
                    if not os.path.isdir(op_path):
                        continue
                    op_type_clean = op_type.lstrip("_")
                    for fname in sorted(os.listdir(op_path)):
                        if not fname.endswith(".txt"):
                            continue
                        match = re.search(r"out_\w*?_(\d+)_(\d+)\.txt", fname)
                        if match:
                            thread_num = match.group(1)
                            coro_num = match.group(2)
                        else:
                            match = re.search(r"out_\w*?_(\d+)\.txt", fname)
                            if match:
                                thread_num = match.group(1)
                                coro_num = "?"
                            else:
                                thread_num = coro_num = "?"
                        fpath = os.path.join(op_path, fname)
                        load_iops, run_iops = parse_result_file(fpath)
                        fout.write(f"{root}\t{load_dir}\t{workload_dir}\t{op_type_clean}\t{thread_num}\t{coro_num}\t{load_iops}\t{run_iops}\n")

def main():
    all_roots = [d for d in os.listdir('.') if d.startswith('results_2CN') and os.path.isdir(d)]
    out_dir = "output_2CN"
    out_path = os.path.join(out_dir, "stat_summary.tsv")
    # 先清空文件
    os.makedirs(out_dir, exist_ok=True)
    with open(out_path, 'w') as fout:
        fout.write("root\tload_num\tworkload_type\top_type\tthreads\tcoros\tLoadIOPS(K)\tRunIOPS(K)\n")
    # 逐个追加
    for root in all_roots:
        print(f"Processing {root}...")
        collect_results(root, out_dir, mode='a')

if __name__ == "__main__":
    main()