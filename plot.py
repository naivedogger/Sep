import pandas as pd
import matplotlib.pyplot as plt
import os

df = pd.read_csv("output/stat_summary.tsv", sep="\t")
df.columns = [c.strip() for c in df.columns]
df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)
df = df[df['threads'].apply(lambda x: str(x).isdigit())]
df = df[df['coros'].apply(lambda x: str(x).isdigit())]
df['threads'] = df['threads'].astype(int)
df['coros'] = df['coros'].astype(int)
df['LoadIOPS(K)'] = pd.to_numeric(df['LoadIOPS(K)'], errors='coerce')
df['RunIOPS(K)'] = pd.to_numeric(df['RunIOPS(K)'], errors='coerce')
df = df.dropna(subset=['LoadIOPS(K)', 'RunIOPS(K)'])

os.makedirs("output/plots", exist_ok=True)

for load_num in sorted(df['load_num'].unique(), key=lambda x: int(x)):
    for workload_type in df['workload_type'].unique():
        for op_type in df['op_type'].unique():
            for coro in sorted(df['coros'].unique()):
                # LoadIOPS
                plt.figure(figsize=(8, 6))
                lines = 0
                for root in df['root'].unique():
                    sub = df[
                        (df['load_num'] == load_num) &
                        (df['workload_type'] == workload_type) &
                        (df['op_type'] == op_type) &
                        (df['coros'] == coro) &
                        (df['root'] == root)
                    ].sort_values('threads')
                    if len(sub) < 2:
                        continue
                    plt.plot(sub['threads'].values, sub['LoadIOPS(K)'].values, marker='o', label=f"{root} LoadIOPS")
                    lines += 1
                if lines > 0:
                    plt.title(f"LoadIOPS vs Threads\nload={load_num} workload={workload_type} op={op_type} coro={coro}")
                    plt.xlabel("Threads")
                    plt.ylabel("LoadIOPS (K)")
                    plt.legend()
                    plt.grid(True)
                    fname = f"output/plots/LoadIOPS_{load_num}_{workload_type}_{op_type}_coro{coro}.png"
                    plt.savefig(fname)
                plt.close()

                # RunIOPS
                plt.figure(figsize=(8, 6))
                lines = 0
                for root in df['root'].unique():
                    sub = df[
                        (df['load_num'] == load_num) &
                        (df['workload_type'] == workload_type) &
                        (df['op_type'] == op_type) &
                        (df['coros'] == coro) &
                        (df['root'] == root)
                    ].sort_values('threads')
                    if len(sub) < 2:
                        continue
                    plt.plot(sub['threads'].values, sub['RunIOPS(K)'].values, marker='o', label=f"{root} RunIOPS")
                    lines += 1
                if lines > 0:
                    plt.title(f"RunIOPS vs Threads\nload={load_num} workload={workload_type} op={op_type} coro={coro}")
                    plt.xlabel("Threads")
                    plt.ylabel("RunIOPS (K)")
                    plt.legend()
                    plt.grid(True)
                    fname = f"output/plots/RunIOPS_{load_num}_{workload_type}_{op_type}_coro{coro}.png"
                    plt.savefig(fname)
                plt.close()