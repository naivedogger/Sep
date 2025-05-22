import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

plt.rcParams.update({'font.size': 18})  # 设置全局字体大一点

def plot_bar(stat_path, out_dir):
    df = pd.read_csv(stat_path, sep="\t")
    df.columns = [c.strip() for c in df.columns]
    df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)
    df = df[df['threads'].apply(lambda x: str(x).isdigit())]
    df = df[df['coros'].apply(lambda x: str(x).isdigit())]
    df['threads'] = df['threads'].astype(int)
    df['coros'] = df['coros'].astype(int)
    df['LoadIOPS(K)'] = pd.to_numeric(df['LoadIOPS(K)'], errors='coerce')
    df['RunIOPS(K)'] = pd.to_numeric(df['RunIOPS(K)'], errors='coerce')
    df = df.dropna(subset=['LoadIOPS(K)', 'RunIOPS(K)'])

    os.makedirs(f"{out_dir}/barplots", exist_ok=True)

    color_map = {
        'race': '#6baed6',   # 柔和蓝
        'sep':  '#a1d99b',   # 柔和绿
        'tree': '#fdae6b'    # 柔和橙
    }
    default_colors = ['#6baed6', '#a1d99b', '#fdae6b']

    for load_num in sorted(df['load_num'].unique(), key=lambda x: int(x)):
        for workload_type in df['workload_type'].unique():
            for op_type in df['op_type'].unique():
                for coro in sorted(df['coros'].unique()):
                    sub = df[
                        (df['load_num'] == load_num) &
                        (df['workload_type'] == workload_type) &
                        (df['op_type'] == op_type) &
                        (df['coros'] == coro)
                    ]
                    if sub.empty:
                        continue
                    threads_list = sorted(sub['threads'].unique())
                    roots = sorted(sub['root'].unique())
                    bar_width = 0.18
                    x = np.arange(len(threads_list))

                    # ----------- LoadIOPS -----------
                    plt.figure(figsize=(10, 6))
                    for i, root in enumerate(roots):
                        y = []
                        for t in threads_list:
                            val = sub[(sub['threads'] == t) & (sub['root'] == root)]['LoadIOPS(K)']
                            y.append(val.values[0]/1000 if not val.empty else 0)
                        color = color_map.get(root.replace('results_', ''), default_colors[i % len(default_colors)])
                        plt.bar(x + i * bar_width, y, width=bar_width, label=root.replace('results_', '').capitalize(), color=color)
                    plt.xticks(x + bar_width * (len(roots)-1) / 2, threads_list)
                    plt.xlabel("Threads")
                    plt.ylabel("IOPS (Mops)")
                    # 标题美化
                    op_map = {'read': 'Read', 'update': 'Update', 'insert': 'Insert'}
                    title = f"{workload_type.capitalize()} {op_map.get(op_type.strip('_'), op_type.capitalize())}"
                    plt.title('Load')
                    plt.legend()
                    plt.tight_layout()
                    fname = f"{out_dir}/barplots/LoadIOPS_{load_num}_{workload_type}_{op_type}_coro{coro}.png"
                    plt.savefig(fname)
                    plt.close()

                    # ----------- RunIOPS -----------
                    plt.figure(figsize=(10, 6))
                    for i, root in enumerate(roots):
                        y = []
                        for t in threads_list:
                            val = sub[(sub['threads'] == t) & (sub['root'] == root)]['RunIOPS(K)']
                            y.append(val.values[0]/1000 if not val.empty else 0)
                        color = color_map.get(root.replace('results_', ''), default_colors[i % len(default_colors)])
                        plt.bar(x + i * bar_width, y, width=bar_width, label=root.replace('results_', '').capitalize(), color=color)
                    plt.xticks(x + bar_width * (len(roots)-1) / 2, threads_list)
                    plt.xlabel("Threads")
                    plt.ylabel("IOPS (Mops)")
                    plt.title(title)
                    plt.legend()
                    plt.tight_layout()
                    fname = f"{out_dir}/barplots/RunIOPS_{load_num}_{workload_type}_{op_type}_coro{coro}.png"
                    plt.savefig(fname)
                    plt.close()

if __name__ == "__main__":
    # 普通 output
    # plot_bar("output/stat_summary.tsv", "output")
    # 2CN output
    if os.path.exists("output_2CN/stat_summary.tsv"):
        plot_bar("output_2CN/stat_summary.tsv", "output_2CN")