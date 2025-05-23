#!/bin/bash

set -e

SRC="test/ser_cli.cc"
BACKUP="test/ser_cli.cc.bak"
REMOTE="192.169.1.6"
REMOTE_PATH="/home/hyy/TBEH/Sep"

cp $SRC $BACKUP

declare -A STRUCTS=(
    [race]="RACE"
    [sep]="SEPHASH"
    [tree]="TREEBASED"
)

for mode in tree sep race; do
    # 1. 切换 using
    cp $BACKUP $SRC
    sed -i 's/^\(using ClientType = .*\)$/\/\/ \1/' $SRC
    sed -i 's/^\(using ServerType = .*\)$/\/\/ \1/' $SRC
    sed -i 's/^\(using Slice = .*\)$/\/\/ \1/' $SRC
    case $mode in
        race)
            sed -i 's/^\/\/ using ClientType = RACE::Client;/using ClientType = RACE::Client;/' $SRC
            sed -i 's/^\/\/ using ServerType = RACE::Server;/using ServerType = RACE::Server;/' $SRC
            sed -i 's/^\/\/ using Slice = RACE::Slice;/using Slice = RACE::Slice;/' $SRC
            ;;
        sep)
            sed -i 's/^\/\/ using ClientType = SEPHASH::Client;/using ClientType = SEPHASH::Client;/' $SRC
            sed -i 's/^\/\/ using ServerType = SEPHASH::Server;/using ServerType = SEPHASH::Server;/' $SRC
            sed -i 's/^\/\/ using Slice = SEPHASH::Slice;/using Slice = SEPHASH::Slice;/' $SRC
            ;;
        tree)
            sed -i 's/^\/\/ using ClientType = TREEBASED::Client;/using ClientType = TREEBASED::Client;/' $SRC
            sed -i 's/^\/\/ using ServerType = TREEBASED::Server;/using ServerType = TREEBASED::Server;/' $SRC
            sed -i 's/^\/\/ using Slice = TREEBASED::Slice;/using Slice = TREEBASED::Slice;/' $SRC
            ;;
    esac

    # 2. 编译并同步 build 到远端
    cd ./build
    make ser_cli
    rsync -avz ./ "$REMOTE:$REMOTE_PATH/build/"

    # 2.5. 重启 server
    ulimit -s unlimited
    killall ser_cli || true
    stdbuf -i0 -o0 -e0 ../ser_cli.sh server > ser_server.log 2>&1 &
    sleep 30
    cd ../

    # 3. 运行原有测试流程
    config_file="ser_cli.sh"
    if [ ! -f "$config_file" ]; then
        echo "配置文件 $config_file 不存在！"
        exit 1
    fi

    for op_num in 60000000; do
        sed -i "s/ *for load_num in [0-9]\+/            for load_num in $op_num/" "$config_file"
        rsync -avz "$config_file" "$REMOTE:$REMOTE_PATH/ser_cli.sh"
        for type_pattern in 0; do
            sed -i "s/^ *type_pattern=.*/    type_pattern=$type_pattern/" "$config_file"
            rsync -avz "$config_file" "$REMOTE:$REMOTE_PATH/ser_cli.sh"
            case $type_pattern in
                0) base_name="results_2CN_${mode}/$op_num/sequential" ;;
                1) base_name="results_2CN_${mode}/$op_num/uniform" ;;
                2) base_name="results_2CN_${mode}/$op_num/skewed" ;;
                3) base_name="results_2CN_${mode}/$op_num/latest" ;;
            esac

            for workload in 2; do
                sed -i "s/^ *frac_i=.*/    frac_i=0.0/" "$config_file"
                sed -i "s/^ *frac_r=.*/    frac_r=0.0/" "$config_file"
                sed -i "s/^ *frac_u=.*/    frac_u=0.0/" "$config_file"
                sed -i "s/^ *frac_d=.*/    frac_d=0.0/" "$config_file"
                case $workload in
                    0) sed -i "s/^ *frac_r=.*/    frac_r=1.0/" "$config_file" ;;
                    1) sed -i "s/^ *frac_u=.*/    frac_u=1.0/" "$config_file" ;;
                    2) sed -i "s/^ *frac_i=.*/    frac_i=1.0/" "$config_file" ;;
                esac
                rsync -avz "$config_file" "$REMOTE:$REMOTE_PATH/ser_cli.sh"
                sleep 5

                case $workload in
                    0) folder_name=$base_name"/_read" ;;
                    1) folder_name=$base_name"/_update" ;;
                    2) folder_name=$base_name"/_insert" ;;
                esac

                mkdir -p "$folder_name"
                echo "当前配置："
                cat "$config_file"
                echo "-----------------------------"

                for ((cli_num=10; cli_num>=1; cli_num-=1)); do
                    for coro_num in 3; do
                        python3 ./run.py 2 client $cli_num $coro_num
                        pwd
                        mv "out.txt" "$folder_name/out_${mode}_$cli_num"_"$coro_num.txt"
                    done
                done
            done
        done
    done
done

mv $BACKUP $SRC

echo "所有配置和二进制已同步到远端，结果已保存到对应的文件夹中！"