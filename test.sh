# for ((cli_num=1; cli_num<=16; cli_num*=2)); do
#     python3 ./run.py 1 client $cli_num 1
#     pwd
#     mv ./out.txt ./out_tree_$cli_num.txt
# done

#!/bin/bash

# 假设配置文件名为 config.txt
config_file="ser_cli.sh"

# 检查配置文件是否存在
if [ ! -f "$config_file" ]; then
    echo "配置文件 $config_file 不存在！"
    exit 1
fi

for op_num in 10000000 20000000 40000000 60000000 80000000 100000000; do
    sed -i "s/ *for load_num in [0-9]\+/            for load_num in $op_num/" "$config_file"
    # 循环修改 type_pattern 的值为 0、1、2、3
    for type_pattern in 0 1 2 3; do
        # 修改 type_pattern 的值
        sed -i "s/^ *type_pattern=.*/    type_pattern=$type_pattern/" "$config_file"
        
        case $type_pattern in
            0)
                base_name="results/"$op_num"/sequential"
                ;;
            1)
                base_name="results/"$op_num"uniform"
                ;;
            2)
                base_name="results/"$op_num"skewed"
                ;;
            3)
                base_name="results/"$op_num"latest"
                ;;
        esac
        
        for workload in 0 1 2; do
            # 根据 workload 的值，设置其中一个变量为 1
            # 初始化所有变量为 0
            sed -i "s/^ *frac_i=.*/    frac_i=0.0/" "$config_file"
            sed -i "s/^ *frac_r=.*/    frac_r=0.0/" "$config_file"
            sed -i "s/^ *frac_u=.*/    frac_u=0.0/" "$config_file"
            sed -i "s/^ *frac_d=.*/    frac_d=0.0/" "$config_file"
            case $workload in
                0)
                    sed -i "s/^ *frac_i=.*/    frac_i=1.0/" "$config_file"
                    ;;
                1)
                    sed -i "s/^ *frac_r=.*/    frac_r=1.0/" "$config_file"
                    ;;
                2)
                    sed -i "s/^ *frac_u=.*/    frac_u=1.0/" "$config_file"
                    ;;
            esac

            # 创建对应的文件夹
            case $workload in
                0)
                    folder_name=$base_name"_insert"
                    ;;
                1)
                    folder_name=$base_name"_read"
                    ;;
                2)
                    folder_name=$base_name"_update"
                    ;;
            esac
            
            # 创建文件夹（如果不存在）
            mkdir -p "$folder_name"
        
            # 输出当前配置文件的内容（可选）
            echo "当前配置："
            cat "$config_file"
            echo "-----------------------------"
            
            # 运行程序
            for ((cli_num=1; cli_num<=16; cli_num*=2)); do
                for coro_num in 1 3; do
                    python3 ./run.py 1 client $cli_num $coro_num
                    pwd
                    mv "out.txt" "$folder_name/out_tree_$cli_num"_"$coro_num.txt"
                done
            done
        done
    done
done

echo "所有配置修改完成，结果已保存到对应的文件夹中！"