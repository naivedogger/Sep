import matplotlib
matplotlib.use('Agg')
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
df['load_num'] = pd.to_numeric(df['load_num'], errors='coerce')
df = df.dropna(subset=['LoadIOPS(K)', 'RunIOPS(K)', 'load_num'])

df['concurrency'] = df['threads'] * df['coros']

# 分组取均值
grouped = df.groupby(['root', 'load_num', 'workload_type', 'op_type', 'concurrency']).agg({
    'LoadIOPS(K)': 'mean',
    'RunIOPS(K)': 'mean'
}).reset_index()

os.makedirs("output/plots_run_iops", exist_ok=True)
os.makedirs("output/plots_load_iops", exist_ok=True)

for load_num in sorted(grouped['load_num'].unique()):
    load_m = int(load_num) // 1000000  # 以m为单位
    for workload_type in grouped['workload_type'].unique():
        for op_type in grouped['op_type'].unique():
            # RunIOPS
            plt.figure(figsize=(8, 6))
            lines = 0
            for root in grouped['root'].unique():
                sub = grouped[
                    (grouped['load_num'] == load_num) &
                    (grouped['workload_type'] == workload_type) &
                    (grouped['op_type'] == op_type) &
                    (grouped['root'] == root)
                ].sort_values('concurrency')
                sub = sub[sub['concurrency'] <= 48]
                if len(sub) < 2:
                    continue
                plt.plot(sub['concurrency'].values, sub['RunIOPS(K)'].values, marker='o', label=f"{root}")
                lines += 1
            if lines > 0:
                plt.title(f"RunIOPS vs Concurrency\nload={load_m}m workload={workload_type} op={op_type}")
                plt.xlabel("Concurrency (threads * coros)")
                plt.ylabel("RunIOPS (K)")
                plt.legend()
                plt.grid(True)
                fname = f"output/plots_run_iops/RunIOPS_load{load_m}m_{workload_type}_{op_type}.png"
                plt.savefig(fname)
            plt.close()

            # LoadIOPS
            plt.figure(figsize=(8, 6))
            lines = 0
            for root in grouped['root'].unique():
                sub = grouped[
                    (grouped['load_num'] == load_num) &
                    (grouped['workload_type'] == workload_type) &
                    (grouped['op_type'] == op_type) &
                    (grouped['root'] == root)
                ].sort_values('concurrency')
                sub = sub[sub['concurrency'] <= 48]
                if len(sub) < 2:
                    continue
                plt.plot(sub['concurrency'].values, sub['LoadIOPS(K)'].values, marker='o', label=f"{root}")
                lines += 1
            if lines > 0:
                plt.title(f"LoadIOPS vs Concurrency\nload={load_m}m workload={workload_type} op={op_type}")
                plt.xlabel("Concurrency (threads * coros)")
                plt.ylabel("LoadIOPS (K)")
                plt.legend()
                plt.grid(True)
                fname = f"output/plots_load_iops/LoadIOPS_load{load_m}m_{workload_type}_{op_type}.png"
                plt.savefig(fname)
            plt.close()