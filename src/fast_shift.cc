// 因为使用协程的原因，不能嵌套太多层子函数调用
#include "fast_shift.h"
namespace FASTSHIFT
{

inline __attribute__((always_inline)) uint64_t get_shift_bits(uint64_t local_depth)
{
    if(local_depth == INIT_DEPTH)
        return INIT_DEPTH;
    uint64_t shift_bits = (local_depth - INIT_DEPTH - 1) / 8;
    shift_bits *= 8;
    shift_bits += INIT_DEPTH;
    return shift_bits;
}

inline __attribute__((always_inline)) uint64_t get_mask_bits(uint64_t local_depth)
{
    uint64_t mask_bits = (local_depth - INIT_DEPTH) % 8;
    return mask_bits;
}

inline __attribute__((always_inline)) uint64_t get_block_size(uint64_t count)
{
    return count * KVBLOCK_SIZE;
}

inline __attribute__((always_inline)) uint64_t fp(uint64_t pattern)
{
    return ((uint64_t)((pattern)>>32)&((1<<8)-1));
}

inline __attribute__((always_inline)) uint64_t fp2(uint64_t pattern, uint64_t local_depth)
{
    uint64_t shift_bits = get_shift_bits(local_depth);
    return ((uint64_t)((pattern)>>shift_bits)&((1<<8)-1));
}

inline __attribute__((always_inline)) uint64_t get_seg_loc(uint64_t pattern, uint64_t global_depth)
{
    return ((pattern) & ((1 << global_depth) - 1));
}
inline __attribute__((always_inline)) uint64_t get_buc_loc(uint64_t pattern)
{
    return (pattern >> (8 * sizeof(uint64_t) - BUCKET_BITS - 1));
}
inline __attribute__((always_inline)) uint64_t get_buc_off(uint64_t buc_idx)
{
    return (((buc_idx / 2) * 3 + (buc_idx % 2)) * sizeof(struct Bucket));
}
inline __attribute__((always_inline)) Bucket *get_main_buc(uint64_t buc_idx, Bucket *buc)
{
    return ((buc_idx % 2 == 0) ? (buc) : (buc + 1));
}
inline __attribute__((always_inline)) Bucket *get_over_buc(uint64_t buc_idx, Bucket *buc)
{
    return ((buc_idx % 2 == 0) ? (buc + 1) : (buc));
}
inline __attribute__((always_inline)) uint64_t get_main_ptr(uint64_t buc_idx, uint64_t buc_ptr)
{
    return ((buc_idx % 2 == 0) ? (buc_ptr) : (buc_ptr + sizeof(struct Bucket)));
}
inline __attribute__((always_inline)) uint64_t get_over_ptr(uint64_t buc_idx, uint64_t buc_ptr)
{
    return ((buc_idx % 2 == 0) ? (buc_ptr + sizeof(struct Bucket)) : (buc_ptr));
}
inline __attribute__((always_inline)) bool check_suffix(uint64_t suffix, uint64_t seg_loc, uint64_t local_depth)
{
    return ((suffix & ((1 << local_depth) - 1)) ^ (seg_loc & ((1 << local_depth) - 1)));
}

int empty_cnt = 0;

inline __attribute__((always_inline)) bool check_empty(uint8_t fp2, uint64_t key, uint64_t local_depth)
{
    if((local_depth - INIT_DEPTH) % 8 == 0)
        return false;
    uint64_t shift_bits = get_shift_bits(local_depth);
    uint64_t mask_bits = get_mask_bits(local_depth);
    assert(shift_bits == INIT_DEPTH);
    // TODO：再想想？应该只要有 1 位不一样就说明是空的
    if((fp2 ^ (key >> shift_bits)) & ((1 << mask_bits) - 1)) {
        // log_err("check_empty: pattern:%lx key:%lx", (pattern >> shift_bits) & ((1 << 8) - 1), (key >> shift_bits) & ((1 << 8) - 1));
        return true;
    }
    return false;
}

void PrintDir(Directory *dir)
{
    printf("---------PrintRACE-----\n");
    printf("Global Depth:%lu\n", dir->global_depth);
    printf("Resize Lock :%lu\n", dir->resize_lock);
    uint64_t dir_size = pow(2, dir->global_depth);
    printf("dir_size :%lu\n", dir_size);
    for (uint64_t i = 0; i < dir_size; i++)
    {
        printf("Segment:seg_loc:%lx lock:%lu local_depth:%lu seg_ptr:%lx\n", i, dir->segs[i].split_lock,
               dir->segs[i].local_depth, dir->segs[i].seg_ptr);
    }
}

Server::Server(Config &config) : dev(nullptr, 1, config.gid_idx), ser(dev)
{
    lmr = dev.reg_mr(233, config.mem_size);
    alloc.Set((char *)lmr->addr, lmr->length);
    dir = (Directory *)alloc.alloc(sizeof(Directory));
    memset(dir, 0, sizeof(Directory));
    Init(dir);
    log_err("init");
    auto wait_exit = [&]() {
        // getchar();
        std::cin.get(); // 等待用户输入
        // 在这里添加你停止服务器的代码
        ser.stop_serve();
        std::cout << "Exiting..." << std::endl;
    };
    std::thread th(wait_exit);
    ser.start_serve();
    th.join();
}

void Server::Init(Directory *dir)
{
    dir->global_depth = INIT_DEPTH;
    dir->resize_lock = 0;
    uint64_t dir_size = pow(2, INIT_DEPTH);
    Segment *tmp;
    for (uint64_t i = 0; i < dir_size; i++)
    {
        tmp = (Segment *)alloc.alloc(sizeof(Segment));
        memset(tmp, 0, sizeof(Segment));
        dir->segs[i].seg_ptr = (uintptr_t)tmp;
        dir->segs[i].local_depth = INIT_DEPTH;
        for (uint64_t j = 0; j < BUCKET_PER_SEGMENT * 3; j++)
        {
            tmp->buckets[j].local_depth = INIT_DEPTH;
            tmp->buckets[j].suffix = i;
        }
    }
}

Server::~Server()
{
    rdma_free_mr(lmr);
}

Client::Client(Config &config, ibv_mr *_lmr, rdma_client *_cli, rdma_conn *_conn,rdma_conn *_wowait_conn, uint64_t _machine_id,
                       uint64_t _cli_id, uint64_t _coro_id)
{
    // id info
    machine_id = _machine_id;
    cli_id = _cli_id;
    coro_id = _coro_id;
    // rdma utils
    cli = _cli;
    conn = _conn;
    wowait_conn = _wowait_conn;
    lmr = _lmr;

    // alloc info
    alloc.Set((char *)lmr->addr, lmr->length);
    log_info("laddr:%lx llen:%lx", (uint64_t)lmr->addr, lmr->length);
    rmr = cli->run(conn->query_remote_mr(233));
    log_info("raddr:%lx rlen:%lx rend:%lx", (uint64_t)rmr.raddr, rmr.rlen, rmr.raddr + rmr.rlen);
    // uint64_t rbuf_size = (rmr.rlen - (1ul << 30) * 50) /
    //                      (config.num_machine * config.num_cli * config.num_coro); // for init_depth = 16
    uint64_t rbuf_size = (rmr.rlen - (1ul << 20) * 100) /
                         (config.num_machine * config.num_cli * config.num_coro); // 头部保留5GB，其他的留给client
    ralloc.SetRemote(
        rmr.raddr + rmr.rlen -
            rbuf_size * (config.machine_id * config.num_cli * config.num_coro + cli_id * config.num_coro + coro_id),
        rbuf_size, rmr.raddr, rmr.rlen);
    perf.init();
    sum_cost.init();

    // sync dir
    dir = (Directory *)alloc.alloc(sizeof(Directory));
    memset(dir, 0, sizeof(Directory));
    cli->run(sync_dir());
}

Client::~Client()
{
    perf.print(cli_id,coro_id);
    sum_cost.print(cli_id,coro_id);
}

task<> Client::reset_remote()
{
    // dir->print();
    //模拟远端分配器信息
    Alloc server_alloc;
    server_alloc.Set((char *)rmr.raddr, rmr.rlen);
    server_alloc.alloc(sizeof(Directory));

    //重置远端segment
    memset(dir, 0, sizeof(Directory));
    dir->global_depth = INIT_DEPTH;
    dir->resize_lock = 0;
    dir->start_cnt = 0;
    uint64_t dir_size = pow(2, INIT_DEPTH);
    alloc.ReSet(sizeof(Directory)); // Make room for local_segment
    Segment *local_seg = (Segment *)alloc.alloc(sizeof(Segment));
    uint64_t remote_seg;
    for (uint64_t i = 0; i < dir_size; i++)
    {
        remote_seg = (uintptr_t)server_alloc.alloc(sizeof(Segment));
        memset(local_seg, 0, sizeof(Segment));
        dir->segs[i].seg_ptr = remote_seg;
        dir->segs[i].local_depth = INIT_DEPTH;
        for (uint64_t j = 0; j < BUCKET_PER_SEGMENT * 3; j++)
        {
            local_seg->buckets[j].local_depth = INIT_DEPTH;
            local_seg->buckets[j].suffix = i;
        }
        co_await conn->write(remote_seg, rmr.rkey, local_seg, size_t(sizeof(Segment)), lmr->lkey);
    }
    //重置远端 Directory
    co_await conn->write(rmr.raddr, rmr.rkey, dir, size_t(sizeof(Directory)), lmr->lkey);
}

task<> Client::start(uint64_t total)
{
    // co_await sync_dir();
    uint64_t *start_cnt = (uint64_t *)alloc.alloc(sizeof(uint64_t), true);
    *start_cnt = 0;
    co_await conn->fetch_add(rmr.raddr + sizeof(Directory) - sizeof(uint64_t), rmr.rkey, *start_cnt, 1);
    // log_info("Start_cnt:%lu", *start_cnt);
    while ((*start_cnt) < total)
    {
        co_await conn->read(rmr.raddr + sizeof(Directory) - sizeof(uint64_t), rmr.rkey, start_cnt, sizeof(uint64_t),
                            lmr->lkey);
    }
}

task<> Client::stop()
{
    uint64_t *start_cnt = (uint64_t *)alloc.alloc(sizeof(uint64_t));
    co_await conn->fetch_add(rmr.raddr + sizeof(Directory) - sizeof(uint64_t), rmr.rkey, *start_cnt, -1);
    // log_info("Start_cnt:%lu", *start_cnt);
    while ((*start_cnt) != 0)
    {
        co_await conn->read(rmr.raddr + sizeof(Directory) - sizeof(uint64_t), rmr.rkey, start_cnt, sizeof(uint64_t),
                            lmr->lkey);
    }
}

task<> Client::cal_utilization(){
    if(this->machine_id !=0 || this->cli_id != 0 || this->coro_id != 0) co_return;
    co_await sync_dir();
    uint64_t space_consumption = 2*sizeof(uint64_t)+(1<<dir->global_depth)*sizeof(DirEntry);
    uint64_t segment_cnt = 0 ;
    uint64_t entry_total = 0 ;
    uint64_t entry_cnt = 0 ;
    uint64_t buc_meta_consumption = 0 ;
    uint64_t dir_entry_consumption = 2*sizeof(uint64_t)+(1<<dir->global_depth)*sizeof(DirEntry) ;
    uint64_t total_meta_consumption = dir_entry_consumption ;
    

    // 遍历Segment，统计空间开销和空间利用率
    log_err("global_dep:%lu",dir->global_depth);
    Segment * cur_seg = (Segment*)alloc.alloc(sizeof(Segment));
    for(uint64_t i = 0 ; i < (1<<dir->global_depth) ; i++){
        uint64_t first_index = i & ((1<<dir->segs[i].local_depth)-1);
        first_index |= 1<<dir->segs[i].local_depth ;
        // log_err("seg:%lu first_index:%lu dir->segs[i].local_depth:%lu flag:%d",i,first_index,dir->segs[i].local_depth,dir->segs[i].local_depth == dir->global_depth || i == first_index);
        if(dir->segs[i].local_depth == dir->global_depth || i == first_index ){
            space_consumption += sizeof(Segment);
            buc_meta_consumption += sizeof(uint64_t) * BUCKET_PER_SEGMENT * 3 ;
            entry_total += BUCKET_PER_SEGMENT*3*SLOT_PER_BUCKET;
            segment_cnt++;
            co_await conn->read(dir->segs[i].seg_ptr,rmr.rkey,cur_seg,sizeof(Segment),lmr->lkey);
            for(uint64_t i = 0 ; i < BUCKET_PER_SEGMENT*3 ; i++){
                for(uint64_t slot_id = 0 ; slot_id < SLOT_PER_BUCKET ; slot_id++){
                    if(cur_seg->buckets[i].slots[slot_id].offset != 0 ){
                        entry_cnt++;
                    }
                }
            }
        }
    }

    total_meta_consumption += buc_meta_consumption;
    double space_utilization = (1.0*entry_cnt*sizeof(Slot))/(1.0*space_consumption);
    double entry_utilization = (1.0*entry_cnt)/(1.0*entry_total);

    // space_consumption = space_consumption>>20;
    // buc_meta_consumption = buc_meta_consumption>>20;
    // dir_entry_consumption = dir_entry_consumption>>20;
    // meta_consumption = meta_consumption>>20;
    // log_err("space_consumption:%luMB segment_cnt:%lu entry_total:%lu entry_cnt:%lu entry_utilization:%lf space_utilization:%lf",space_consumption,segment_cnt,entry_total,entry_cnt,entry_utilization,space_utilization);

    // log_err("space_consumption:%luMB buc_meta_consumption:%luMB dir_entry_consumption:%luMB meta_consumption:%luMB segment_cnt:%lu entry_total:%lu entry_cnt:%lu entry_utilization:%lf space_utilization:%lf",space_consumption,buc_meta_consumption, dir_entry_consumption, meta_consumption,segment_cnt,entry_total,entry_cnt,entry_utilization,space_utilization);

    log_err("space_consumption:%lu buc_meta_consumption:%lu dir_entry_consumption:%lu total_meta_consumption:%lu segment_cnt:%lu entry_total:%lu entry_cnt:%lu entry_utilization:%lf space_utilization:%lf",space_consumption,buc_meta_consumption, dir_entry_consumption, total_meta_consumption,segment_cnt,entry_total,entry_cnt,entry_utilization,space_utilization);
}

void print_buc(Bucket* buc){
    log_err("buc: local_dep:%x suffix:%x ",buc->local_depth,buc->suffix);
    for(uint64_t i = 0 ; i < SLOT_PER_BUCKET ; i++){
        log_err("slot:%lu fp:%d len:%d offset:%lu",i,buc->slots[i].fp,buc->slots[i].fp2,buc->slots[i].offset);
    }
}

int cnt = 0;

task<> Client::insert(Slice *key, Slice *value)
{
    cnt ++;
    // int miss_match = 0;
    // if(cnt == 59482)
    // for(int i = 0; i < 1 << INIT_DEPTH; i ++) {
    //     uintptr_t segptr = dir->segs[i].seg_ptr;
    //     Bucket *buc_data = (Bucket *)alloc.alloc(4ul * sizeof(Bucket));
    //     uintptr_t bucptr_1, bucptr_2;
    //     bucptr_1 = segptr + get_buc_off(64);
    //     auto rbuc1 = conn->read(bucptr_1, rmr.rkey, buc_data, 2 * sizeof(Bucket), lmr->lkey);
    //     co_await std::move(rbuc1);
    //     if(buc_data->suffix != i)
    //         miss_match ++;
    // }
    perf.start_perf();
    sum_cost.start_insert();
    alloc.ReSet(sizeof(Directory));
    uint64_t pattern_1, pattern_2;
    auto pattern = hash(key->data, key->len);
    pattern_1 = (uint64_t)pattern;
    pattern_2 = (uint64_t)(pattern >> 64);
    KVBlock *kv_block = InitKVBlock(key, value, &alloc);
    this->op_key = *(uint64_t *)key->data;
    // uint64_t kvblock_len = key->len + value->len + sizeof(uint64_t) * 2;
    // TODO: 先按照64算，之后再支持变长
    uint64_t kvblock_len = 64;
    uint64_t kvblock_ptr = ralloc.alloc(kvblock_len);
#ifdef WO_WAIT_WRITE
    wowait_conn->pure_write(kvblock_ptr, rmr.rkey, kv_block, kvblock_len, lmr->lkey);
#else
    auto wkv = conn->write(kvblock_ptr, rmr.rkey, kv_block, kvblock_len, lmr->lkey);
#endif
    uint64_t retry_cnt = 0;
Retry:
    // log_err("[%lu:%lu:%lu] op_key:%lu",machine_id,cli_id,coro_id,this->op_key);
    alloc.ReSet(sizeof(Directory) + kvblock_len);
    retry_cnt++;
    // Read Segment Ptr From CCEH_Cache
    uint64_t segloc = get_seg_loc(pattern_1, dir->global_depth);
    uintptr_t segptr = dir->segs[segloc].seg_ptr;

    // Compute two bucket location
    uint64_t bucidx_1, bucidx_2; // calculate bucket idx for each key
    uintptr_t bucptr_1, bucptr_2;
    bucidx_1 = get_buc_loc(pattern_1);
    bucidx_2 = get_buc_loc(pattern_2);
    bucptr_1 = segptr + get_buc_off(bucidx_1);
    bucptr_2 = segptr + get_buc_off(bucidx_2);

    // 1RTT:Doorbell Read && Write KV-Data
    Bucket *buc_data = (Bucket *)alloc.alloc(4ul * sizeof(Bucket));
    auto rbuc1 = conn->read(bucptr_1, rmr.rkey, buc_data, 2 * sizeof(Bucket), lmr->lkey);
    auto rbuc2 = conn->read(bucptr_2, rmr.rkey, buc_data + 2, 2 * sizeof(Bucket), lmr->lkey);
    co_await std::move(rbuc2);
    co_await std::move(rbuc1);
#ifndef WO_WAIT_WRITE
    if (retry_cnt == 1)
    {
        co_await std::move(wkv);
    }
#endif

    // uint64_t segloc_1 = get_seg_loc(pattern_1, buc_data->local_depth);
    // assert(segloc_1 == buc_data->suffix);
    if (dir->segs[segloc].local_depth != buc_data->local_depth ||
        dir->segs[segloc].local_depth != (buc_data + 2)->local_depth)
    {
        co_await sync_dir();
        // log_err("[%lu:%lu:%lu] op_key:%lu segloc:%lu buc_data->local_depth:%u (buc_data + 2)->local_depth:%u dir->segs[segloc].local_depth:%lu",machine_id,cli_id,coro_id,this->op_key,segloc,buc_data->local_depth,(buc_data + 2)->local_depth,dir->segs[segloc].local_depth);
        goto Retry;
    }

    bool buc_flag = FindLessBucket(buc_data, buc_data + 2, pattern_1, pattern_2, buc_data->local_depth);
    uint64_t buc_idx = buc_flag ? bucidx_1 : bucidx_2;
    Bucket *buc = buc_flag ? buc_data : buc_data + 2;
    uintptr_t buc_ptr = buc_flag ? bucptr_1 : bucptr_2;
    uint64_t slot_val = 0;
    // uint64_t pattern_less_bucket = buc_flag ? pattern_1 : pattern_2;
    uintptr_t slot_ptr = FindEmptySlot(buc, buc_idx, buc_ptr, pattern_1, buc_data->local_depth, slot_val);

    if (slot_ptr == 0ul)
    {
        // log_err("[%lu:%lu]%s split for key:%lu with local_depth:%u global_depth:%lu at segloc:%lx",cli_id,coro_id,(buc_data->local_depth==dir->global_depth)?"gloabl":"local",*(uint64_t*)key->data,buc_data->local_depth,dir->global_depth,segloc);
        co_await Split(segloc, segptr, buc->local_depth, buc->local_depth == dir->global_depth);
        goto Retry;
    }

    // 2nd RTT: Using RDMA CAS to write the pointer of the key-value block
    Slot *tmp = (Slot *)alloc.alloc(sizeof(Slot));
    tmp->fp = fp(pattern_1);
    tmp->fp2 = fp2(pattern_1, buc_data->local_depth);
    tmp->offset = ralloc.offset(kvblock_ptr);
    uint64_t pre_val = slot_val;
    if (!co_await conn->cas_n(slot_ptr, rmr.rkey, slot_val, *(uint64_t *)tmp))
    {
        // Slot* slot_data = (Slot*) alloc.alloc(sizeof(Slot));
        // co_await conn->read(slot_ptr, rmr.rkey, slot_data, sizeof(Slot), lmr->lkey);
        // log_err("[%lu:%lu:%lu] op_key:%lu slot_val:%lu fail to cas at slot_ptr:%lx, pre_val:%lx",machine_id,cli_id,coro_id,this->op_key,*(uint64_t*)slot_data,slot_ptr,pre_val);
        goto Retry;
    }

    if(pre_val != 0) {
        empty_cnt ++;
    }

    // 3rd RTT: Re-reading two combined buckets to remove duplicate keys
    auto rbuc3 = conn->read(bucptr_1, rmr.rkey, buc_data, 2 * sizeof(Bucket), lmr->lkey);
    auto rbuc4 = conn->read(bucptr_2, rmr.rkey, buc_data + 2, 2 * sizeof(Bucket), lmr->lkey);
    co_await std::move(rbuc4);
    co_await std::move(rbuc3);

    // 看下这里的bucket有没有写成功

    // Check Dupulicate-key
    for (uint64_t round = 0; round < 4; round++)
    {
        buc = buc_data + round;
        buc_ptr = (round / 2 ? bucptr_2 : bucptr_1) + (round % 2 ? sizeof(Bucket) : 0);
        for (uint64_t i = 0; i < SLOT_PER_BUCKET; i++)
        {
            // TODO: 修改其他的地方的读取key的逻辑！！！！
            if (buc->slots[i].offset != 0 && buc->slots[i].fp == tmp->fp && buc->slots[i].fp2 == tmp->fp2 && buc->slots[i].offset != tmp->offset)
            {
                char *tmp_key = (char *)alloc.alloc(get_block_size(PREFECTH_FACTOR));
                co_await conn->read(ralloc.ptr(buc->slots[i].offset), rmr.rkey, tmp_key, get_block_size(PREFECTH_FACTOR), lmr->lkey);
                // TODO: check the actual len specified in block #1
                uint64_t kv_len = *(uint64_t*)(tmp_key + sizeof(uint64_t));
                assert(kv_len == 1);
                if(kv_len > PREFECTH_FACTOR) {
                    tmp_key = (char*)alloc.alloc(get_block_size(kv_len));
                    // TODO: 支持变长后把这里删除掉
                    assert(0);
                    co_await conn->read(ralloc.ptr(buc->slots[i].offset), rmr.rkey, tmp_key, get_block_size(kv_len), lmr->lkey);
                }
                if (memcmp(key->data, tmp_key + sizeof(uint64_t) * 2, key->len) == 0)
                {
                    // log_err("[%lu:%lu]Duplicate-key :%lu", cli_id, coro_id, *(uint64_t *)key->data);
                    co_await conn->cas_n(buc_ptr + sizeof(uint64_t) * (i + 1), rmr.rkey, *(uint64_t *)tmp, 0);
                }
            }
        }
    }

    buc = buc_flag ? buc_data : buc_data + 2;
    // 可以在最后检查是不是正确的bucket，决定要不要重试insert
    if (IsCorrectBucket(segloc, buc, pattern_1) == false)
    {
        log_err("[%lu:%lu:%lu] op_key:%lu segloc:%lu wrong bucket",machine_id,cli_id,coro_id,this->op_key,segloc);
        co_await conn->cas_n(slot_ptr, rmr.rkey, *(uint64_t *)tmp, slot_val);
        co_await sync_dir();
        goto Retry;
    }

    perf.push_insert();
    sum_cost.end_insert();
    sum_cost.push_retry_cnt(retry_cnt);
    // co_await search(key,value);
}

task<> Client::sync_dir()
{
    co_await conn->read(rmr.raddr + sizeof(uint64_t), rmr.rkey, &dir->global_depth, sizeof(uint64_t), lmr->lkey);
    co_await conn->read(rmr.raddr + sizeof(uint64_t) * 2, rmr.rkey, dir->segs,
                        (1 << dir->global_depth) * sizeof(DirEntry), lmr->lkey);
}

bool Client::FindLessBucket(Bucket *buc1, Bucket *buc2, uint64_t key_1, uint64_t key_2, uint64_t local_depth)
{
    // 应该不需要key_2，pattern_2只是用来计算第二个buc的位置，实际上slot里面的内容是通过pattern_1计算的
    int buc1_tot = 0;
    int buc2_tot = 0;
    Bucket *tmp_1 = buc1, *tmp_2 = buc2;
    for (int round = 0; round < 2; round++)
    {
        for (uint64_t i = 0; i < SLOT_PER_BUCKET; i++)
        {
            if (*(uint64_t *)&tmp_1->slots[i] && !check_empty((tmp_1->slots[i]).fp2,key_1,local_depth))
                buc1_tot++;
            if (*(uint64_t *)&tmp_2->slots[i] && !check_empty((tmp_2->slots[i]).fp2,key_1,local_depth))
                buc2_tot++;
        }
        tmp_1++;
        tmp_2++;
    }
    return buc1_tot < buc2_tot;
}

uintptr_t Client::FindEmptySlot(Bucket *buc, uint64_t buc_idx, uintptr_t buc_ptr, uint64_t key, uint64_t local_depth, uint64_t& slot_val)
{
    Bucket *main_buc = get_main_buc(buc_idx, buc);
    Bucket *over_buc = get_over_buc(buc_idx, buc);
    uint64_t main_buc_ptr = get_main_ptr(buc_idx, buc_ptr);
    uint64_t over_buc_ptr = get_over_ptr(buc_idx, buc_ptr);
    for (uint64_t i = 0; i < SLOT_PER_BUCKET; i++)
    {
        if (*(uint64_t *)(&main_buc->slots[i]) == 0 || check_empty(main_buc->slots[i].fp2, key, local_depth))
        {
            slot_val = *(uint64_t *)(&main_buc->slots[i]);
            return main_buc_ptr + sizeof(uint64_t) * (i + 1);
        }
    }
    for (uint64_t i = 0; i < SLOT_PER_BUCKET; i++)
    {
        if (*(uint64_t *)(&over_buc->slots[i]) == 0|| check_empty(over_buc->slots[i].fp2, key, local_depth))
        {
            slot_val = *(uint64_t *)(&over_buc->slots[i]);
            return over_buc_ptr + sizeof(uint64_t) * (i + 1);
        }
    }
    return 0ul;
}

bool Client::IsCorrectBucket(uint64_t segloc, Bucket *buc, uint64_t pattern)
{
    if (buc->local_depth != dir->segs[segloc].local_depth)
    {
        uint64_t suffix = get_seg_loc(pattern, buc->local_depth);
        if (buc->suffix != suffix)
            return false;
    }
    return true;
}

task<int> Client::Split(uint64_t seg_loc, uintptr_t seg_ptr, uint64_t local_depth, bool global_flag)
{
    sum_cost.start_split();
    // log_err("[%lu:%lu:%lu] %lu split local_depth: %lu",machine_id,cli_id,coro_id,this->op_key,local_depth);
    if (local_depth == MAX_DEPTH)
    {
        log_err("Exceed MAX_DEPTH");
        exit(-1);
    }
    if (co_await LockDir())
    {
        co_await sync_dir();
        sum_cost.end_split();
        co_return 1;
    }

    // Check global depth && global_flag;
    // 检查是否因为本地的过时local_depth导致的错误split类型
    uint64_t *remote_depth = (uint64_t *)alloc.alloc(sizeof(uint64_t));
    co_await conn->read(rmr.raddr + sizeof(uint64_t), rmr.rkey, remote_depth, sizeof(uint64_t), lmr->lkey);
    if (*remote_depth != dir->global_depth)
    {
        co_await UnlockDir();
        co_await sync_dir();
        sum_cost.end_split();
        co_return 1;
    }

    DirEntry *remote_entry = (DirEntry *)alloc.alloc(sizeof(DirEntry));
    co_await conn->read(rmr.raddr + 2 * sizeof(uint64_t) + seg_loc * sizeof(DirEntry), rmr.rkey, remote_entry,
                        sizeof(DirEntry), lmr->lkey);
    if (remote_entry->local_depth != dir->segs[seg_loc].local_depth)
    {
        co_await UnlockDir();
        co_await sync_dir();
        sum_cost.end_split();
        co_return 1;
    }
    if (remote_entry->split_lock == 1)
    {
        co_await UnlockDir();
        co_await sync_dir();
        sum_cost.end_split();
        co_return 1;
    }

    sum_cost.add_split_cnt();

    // 先给 old_seg 里的所有 buckets 的深度加一
    Segment *old_seg = (Segment *)alloc.alloc(sizeof(Segment));
    struct Bucket *cur_buc;
    uint64_t pattern_1, pattern_2, suffix;
    uint64_t buc_ptr;
    std::vector<rdma_future> inflight_req;
    inflight_req.reserve(BUCKET_PER_SEGMENT*3);
    for (uint64_t i = 0; i < BUCKET_PER_SEGMENT * 3; )
    {
        int start_idx = i;
        for(int j = 0; j < dma_default_workq_size; j ++) {
            buc_ptr = seg_ptr + i * sizeof(Bucket);
            cur_buc = &old_seg->buckets[i];
    
            // Update local_depth&suffix
            cur_buc->local_depth = local_depth + 1;
            inflight_req.emplace_back(conn->write(buc_ptr, rmr.rkey, cur_buc, sizeof(uint32_t), lmr->lkey));
            i ++;
        }
        for(int j = 0; j < dma_default_workq_size && (start_idx+j) < i; j ++) {
            co_await std::move(inflight_req[start_idx+j]);
        }
    }

    // usleep(20);

    // 读取旧的segment
    Segment *new_seg = (Segment *)alloc.alloc(sizeof(Segment));
    uint64_t new_seg_ptr = ralloc.alloc(sizeof(Segment), true); //按八字节对齐
    uint64_t first_seg_loc = seg_loc & ((1ull << local_depth) - 1);
    uint64_t new_seg_loc = first_seg_loc | (1ull << local_depth);
    // uint64_t raddrs[BUCKET_PER_SEGMENT*3];
    // void* laddrs[BUCKET_PER_SEGMENT*3];
    // rdma_future inflight_req[BUCKET_PER_SEGMENT*3];
    // TODO:实现batch
    for(int i = 0; i < BUCKET_PER_SEGMENT * 3; ) {
        int start_idx = i;
        for(int j = 0; j < dma_default_workq_size; j ++) {
            buc_ptr = seg_ptr + i * sizeof(Bucket);
            cur_buc = &new_seg->buckets[i];
            inflight_req.emplace_back(conn->read(buc_ptr, rmr.rkey, cur_buc, sizeof(Bucket), lmr->lkey));
            i ++;
        }
        for(int j = 0; j < dma_default_workq_size && (start_idx+j) < i; j ++) {
            co_await std::move(inflight_req[start_idx+j]);
        }
        // raddrs[i] = buc_ptr;
        // laddrs[i] = cur_buc;
        // inflight_req.emplace_back(conn->read(buc_ptr, rmr.rkey, cur_buc, sizeof(Bucket), lmr->lkey));
        // co_await conn->read(buc_ptr, rmr.rkey, cur_buc, sizeof(Bucket), lmr->lkey);
    }

    for(int i = 0; i < BUCKET_PER_SEGMENT*3; i ++) {
        cur_buc = &new_seg->buckets[i];
        cur_buc->local_depth = local_depth + 1;
        cur_buc->suffix = new_seg_loc;
    }
    // co_await conn->read_batch(raddrs, rmr.rkey, laddrs, sizeof(Bucket), lmr->lkey, BUCKET_PER_SEGMENT*3);
    
    // 需要所有叶子的指针
    // if(local_depth - INIT_DEPTH >= 8 && (local_depth - INIT_DEPTH) % 8 == 0) {
    //     // 这里需要再想想怎么做并发控制
    //     // TODO：读取所有key，更新fp2，需要实现一个read_batch
    //     uint64_t ptr_leaves[BUCKET_PER_SEGMENT*3*SLOT_PER_BUCKET];
    //     int leaves_cnt = 0;
    //     for(int i = 0; i < BUCKET_PER_SEGMENT * 3; i ++) {
    //         for(int j = 0; j < SLOT_PER_BUCKET; j ++) {
    //             ptr_leaves[leaves_cnt++] = ralloc.ptr((new_seg->buckets[i]).slots[j].offset);
    //         }
    //     }
    //     KVBlock *kv_block[leaves_cnt];
    //     for(int i = 0; i < leaves_cnt; i ++) {
    //         kv_block[i] = (KVBlock*)alloc.alloc(1);
    //     }
    //     int round = (leaves_cnt + kReadOroMax - 1) / kReadOroMax;
    //     for(int i = 0; i < round; i ++) {
    //         co_await conn->read_batch(&ptr_leaves[kReadOroMax*i], rmr.rkey, kv_block, 1, lmr->lkey, leaves_cnt);
    //     }
    //     // TODO：更新fp2
    // }

    co_await conn->write(new_seg_ptr, rmr.rkey, new_seg, sizeof(Segment), lmr->lkey);

    // Allocate New Seg and Init header && write to server
    // Segment *new_seg = (Segment *)alloc.alloc(sizeof(Segment));
    // memset(new_seg, 0, sizeof(Segment));
    // uint64_t new_seg_ptr = ralloc.alloc(sizeof(Segment), true); //按八字节对齐
    // uint64_t first_seg_loc = seg_loc & ((1ull << local_depth) - 1);
    // uint64_t new_seg_loc = first_seg_loc | (1ull << local_depth);
    // for (uint64_t i = 0; i < BUCKET_PER_SEGMENT * 3; i++)
    // {
    //     new_seg->buckets[i].local_depth = local_depth + 1;
    //     new_seg->buckets[i].suffix = new_seg_loc;
    // }
    // co_await conn->write(new_seg_ptr, rmr.rkey, new_seg, sizeof(Segment), lmr->lkey);

    // Edit Directory pointer
    /* 因为使用了MSB和提前分配充足空间的Directory，所以可以直接往后增加Directory Entry*/
    co_await sync_dir(); // Global Split必须同步一次Dir，来保证之前没有被同步的DirEntry不会被写到远端。
    if (global_flag)
    {
        log_err("[%lu:%lu:%lu] %lu update global_depth from:%lu to %lu",machine_id,cli_id,coro_id,this->op_key,dir->global_depth,dir->global_depth+1);
        // Update Old_seg depth
        // 这里是不是不需要 split_lock
        dir->segs[seg_loc].split_lock = 0;
        dir->segs[seg_loc].local_depth = local_depth + 1;
        co_await conn->write(rmr.raddr + 2 * sizeof(uint64_t) + seg_loc * sizeof(DirEntry), rmr.rkey,
                             &dir->segs[seg_loc], sizeof(DirEntry), lmr->lkey);

        // Extend Dir
        uint64_t dir_size = 1 << dir->global_depth;
        // 涉及目录扩容的时候，直接将旧目录的segs指针复制一份成为新的，也就是说指向同一个桶，且split_lock的状况是相同的
        memcpy(dir->segs + dir_size, dir->segs, dir_size * sizeof(DirEntry));
        dir->segs[new_seg_loc].local_depth = local_depth + 1;
        dir->segs[new_seg_loc].split_lock = 0;
        dir->segs[new_seg_loc].seg_ptr = new_seg_ptr;
        co_await conn->write(rmr.raddr + 2 * sizeof(uint64_t) + dir_size * sizeof(DirEntry), rmr.rkey,
                             dir->segs + dir_size, dir_size * sizeof(DirEntry), lmr->lkey);
        // Update Global Depthx
        dir->global_depth++;
        co_await conn->write(rmr.raddr + sizeof(uint64_t), rmr.rkey, &dir->global_depth, sizeof(uint64_t), lmr->lkey);
    }
    else
    {
        // Local split: Edit all directory share this seg_ptr
        //笔记见备忘录
        uint64_t stride = (1llu) << (dir->global_depth - local_depth);
        uint64_t cur_seg_loc;
        for (uint64_t i = 0; i < stride; i++)
        {
            // 不涉及目录扩容的时候，就是修改那些被影响到的指针，按照第LD位是否为1进行分配
            cur_seg_loc = (i << local_depth) | first_seg_loc;
            if (i & 1)
                dir->segs[cur_seg_loc].seg_ptr = new_seg_ptr;
            else
                dir->segs[cur_seg_loc].seg_ptr = seg_ptr;
            dir->segs[cur_seg_loc].local_depth = local_depth + 1;
            // 这里可以直接设置为0，首先dir上了一把大锁，其次一个seg同时只能被一个线程扩容
            dir->segs[cur_seg_loc].split_lock = 0;

            co_await conn->write(rmr.raddr + 2 * sizeof(uint64_t) + cur_seg_loc * sizeof(DirEntry), rmr.rkey,
                                 dir->segs + cur_seg_loc, sizeof(DirEntry), lmr->lkey);
        }
    }
    co_await UnlockDir();

    // Move Data
    // Segment *old_seg = (Segment *)alloc.alloc(sizeof(Segment));
    // co_await MoveData(seg_ptr, new_seg_ptr, old_seg, new_seg);

    // TODO: 检查一下下面这些的逻辑，感觉好像没有必要
    // Free Move_Data Lock
    // while (co_await LockDir())
    // {
    // }

    // if (global_flag)
    // {
    //     dir->segs[seg_loc].split_lock = 0;
    //     co_await conn->write(rmr.raddr + 2 * sizeof(uint64_t) + seg_loc * sizeof(DirEntry), rmr.rkey,
    //                          &(dir->segs[seg_loc].split_lock), sizeof(uint64_t), lmr->lkey);
    //     dir->segs[new_seg_loc].split_lock = 0;
    //     co_await conn->write(rmr.raddr + 2 * sizeof(uint64_t) + new_seg_loc * sizeof(DirEntry), rmr.rkey,
    //                          &(dir->segs[new_seg_loc].split_lock), sizeof(uint64_t), lmr->lkey);
    // }
    // else
    // {
    //     uint64_t stride =
    //         (1llu) << (dir->global_depth - local_depth + 2); // 这里增加2，是为了给隐式置为1的部分entry解锁
    //     uint64_t cur_seg_loc;
    //     for (uint64_t i = 0; i < stride; i++)
    //     {
    //         cur_seg_loc = (i << local_depth) | first_seg_loc;
    //         dir->segs[cur_seg_loc].split_lock = 0;
    //         co_await conn->write(rmr.raddr + 2 * sizeof(uint64_t) + cur_seg_loc * sizeof(DirEntry), rmr.rkey,
    //                              &(dir->segs[cur_seg_loc].split_lock), sizeof(uint64_t), lmr->lkey);
    //     }
    // }
    // co_await UnlockDir();

    sum_cost.end_split();
    co_return 0;
}

// 这部分后续应该是不需要了
task<> Client::MoveData(uint64_t old_seg_ptr, uint64_t new_seg_ptr, Segment *seg, Segment *new_seg)
{
    struct Bucket *cur_buc;
    uint64_t pattern_1, pattern_2, suffix;
    uint64_t buc_ptr;

    for (uint64_t i = 0; i < BUCKET_PER_SEGMENT * 3; i++)
    {
        buc_ptr = old_seg_ptr + i * sizeof(Bucket);
        cur_buc = &seg->buckets[i];
        co_await conn->read(buc_ptr, rmr.rkey, cur_buc, sizeof(Bucket), lmr->lkey);

        // Update local_depth&suffix
        cur_buc->local_depth = new_seg->buckets[0].local_depth;
        co_await conn->write(buc_ptr, rmr.rkey, cur_buc, sizeof(uint64_t), lmr->lkey);

        for (uint64_t slot_idx = 0; slot_idx < SLOT_PER_BUCKET; slot_idx++)
        {
            if (*(uint64_t *)(&cur_buc->slots[slot_idx]) == 0)
                continue;
            KVBlock *kv_block = (KVBlock *)alloc.alloc(get_block_size(PREFECTH_FACTOR));
            co_await conn->read(ralloc.ptr(cur_buc->slots[slot_idx].offset), rmr.rkey, kv_block,
                                get_block_size(PREFECTH_FACTOR), lmr->lkey);
            uint64_t kv_len = *(uint64_t*)((char*)kv_block + sizeof(uint64_t));
            if(kv_len > PREFECTH_FACTOR) {
                kv_block = (KVBlock*)alloc.alloc(get_block_size(kv_len));
                co_await conn->read(ralloc.ptr(cur_buc->slots[slot_idx].offset), rmr.rkey, kv_block,
                                get_block_size(kv_len), lmr->lkey);
            }

            auto pattern = hash(kv_block->data, kv_block->k_len);
            pattern_1 = (uint64_t)pattern;
            pattern_2 = (uint64_t)(pattern >> 64);
            suffix = get_seg_loc(pattern_1, dir->global_depth);
            if (check_suffix(suffix, new_seg->buckets[0].suffix, new_seg->buckets[0].local_depth) == 0)
            {
                // Find free slot in two bucketgroup
                uint64_t bucidx_1 = get_buc_loc(pattern_1);
                uint64_t bucptr_1 = new_seg_ptr + get_buc_off(bucidx_1);
                uint64_t main_buc_ptr1 = get_main_ptr(bucidx_1, bucptr_1);
                uint64_t over_buc_ptr1 = get_over_ptr(bucidx_1, bucptr_1);
                uint64_t bucidx_2 = get_buc_loc(pattern_2);
                uint64_t bucptr_2 = new_seg_ptr + get_buc_off(bucidx_2);
                uint64_t main_buc_ptr2 = get_main_ptr(bucidx_2, bucptr_2);
                uint64_t over_buc_ptr2 = get_over_ptr(bucidx_2, bucptr_2);

                // 依次尝试Bucket 1，OverBuc 1，Bucket 2，OverBuc 2
                if (co_await SetSlot(main_buc_ptr1, *(uint64_t *)(&cur_buc->slots[slot_idx])) &&
                    co_await SetSlot(over_buc_ptr1, *(uint64_t *)(&cur_buc->slots[slot_idx])) &&
                    co_await SetSlot(main_buc_ptr2, *(uint64_t *)(&cur_buc->slots[slot_idx])) &&
                    co_await SetSlot(over_buc_ptr2, *(uint64_t *)(&cur_buc->slots[slot_idx])))
                {
                    uintptr_t slot_ptr = buc_ptr + sizeof(uint64_t) + sizeof(Slot) * i;
                    log_err("[%lu:%lu:%lu]Fail to move slot_ptr:%lx",machine_id,cli_id,coro_id,slot_ptr);
                    continue;
                }

                // CAS slot in old seg to zero
                //  assert((buc_ptr+sizeof(uint64_t)*(slot_idx+1))%8 == 0);
                uint64_t old_slot = *(uint64_t *)(&cur_buc->slots[slot_idx]);
                co_await conn->cas(buc_ptr + sizeof(uint64_t) * (slot_idx + 1), rmr.rkey, old_slot, 0);
                if (old_slot != *(uint64_t *)(&cur_buc->slots[slot_idx]))
                {
                    //也不影响，只要是这里被的旧slot被删除了就行
                    //只有可能是并发的update导致的
                }
            }
        }
    }
}

/// @brief Used in MoveData
/// @param buc_ptr
/// @param slot
/// @return 0-success to write slot into new_seg at bucidx
//          1-invalid bucidx
task<int> Client::SetSlot(uint64_t buc_ptr, uint64_t slot)
{
    uint64_t slot_idx = 0;
    while (slot_idx < SLOT_PER_BUCKET)
    {
        // assert((buc_ptr+sizeof(uint64_t)*(slot_idx+1))%8 == 0);
        if (co_await conn->cas_n(buc_ptr + sizeof(uint64_t) * (slot_idx + 1), rmr.rkey, 0, slot))
            co_return 0;
        slot_idx++;
    }
    co_return 1;
}

/// @brief 设置Lock为1
/// @return return: 0-success, 1-split conflict
task<int> Client::LockDir()
{
    uint64_t lock;
    // assert((connector.get_remote_addr())%8 == 0);
    if (co_await conn->cas_n(rmr.raddr, rmr.rkey, 0, 1))
    {
        co_return 0;
    }
    co_return 1;
}

task<> Client::UnlockDir()
{
    // Set global split bit
    // assert((connector.get_remote_addr())%8 == 0);
    co_await conn->cas_n(rmr.raddr, rmr.rkey, 1, 0);
}

uint64_t miss_count = 0;
std::atomic<int> read_cnt = 0;

task<std::tuple<uintptr_t, uint64_t>> Client::search(Slice *key, Slice *value)
{
    perf.start_perf();
    read_cnt ++;
Retry_search:
    // 每次重试的时候，会回到头部？？？？
    alloc.ReSet(sizeof(Directory));

    // check buckets
    // int miss_match = 0;
    // if(cnt == 59482)
    // for(int i = 0; i < 1 << INIT_DEPTH; i ++) {
    //     alloc.ReSet(sizeof(Directory));
    //     uintptr_t segptr = dir->segs[i].seg_ptr;
    //     Bucket *buc_data = (Bucket *)alloc.alloc(4ul * sizeof(Bucket));
    //     buc_data->slots[2].fp = 99;
    //     uintptr_t bucptr_1, bucptr_2;
    //     bucptr_1 = segptr + get_buc_off(0);
    //     auto rbuc1 = conn->read(bucptr_1, rmr.rkey, buc_data, 2 * sizeof(Bucket), lmr->lkey);
    //     co_await std::move(rbuc1);
    //     if(buc_data->suffix != i)
    //         miss_match ++;
    // }

    // 1st RTT: Using RDMA doorbell batching to fetch two combined buckets
    uint64_t pattern_1, pattern_2;
    auto pattern = hash(key->data, key->len);
    pattern_1 = (uint64_t)pattern;
    pattern_2 = (uint64_t)(pattern >> 64);
    uint64_t segloc = get_seg_loc(pattern_1, dir->global_depth);
    uintptr_t segptr = dir->segs[segloc].seg_ptr;

    if (dir->segs[segloc].split_lock == 1)
    {
        // log_err("Locked Segment After Load");
        auto slot_info = co_await search_on_resize(key, value);
        perf.push_search();
        co_return slot_info;
    }

    // Compute two bucket location
    uint64_t bucidx_1, bucidx_2; // calculate bucket idx for each key
    uintptr_t bucptr_1, bucptr_2;
    bucidx_1 = get_buc_loc(pattern_1);
    bucidx_2 = get_buc_loc(pattern_2);
    bucptr_1 = segptr + get_buc_off(bucidx_1);
    bucptr_2 = segptr + get_buc_off(bucidx_2);
    // 读过来的bucket suffix和seg对不上
    Bucket *buc_data = (Bucket *)alloc.alloc(4ul * sizeof(Bucket));
    auto rbuc1 = conn->read(bucptr_1, rmr.rkey, buc_data, 2 * sizeof(Bucket), lmr->lkey);
    auto rbuc2 = conn->read(bucptr_2, rmr.rkey, buc_data + 2, 2 * sizeof(Bucket), lmr->lkey);
    co_await std::move(rbuc2);
    co_await std::move(rbuc1);
    // std::move(rbuc2);
    // std::move(rbuc1);
    // usleep(100);
    // 加上一个阻塞的逻辑
    // if (dir->segs[segloc].local_depth != buc_data->local_depth ||
    //     dir->segs[segloc].local_depth != (buc_data + 2)->local_depth)
    // {
    //     co_await sync_dir();
    //     log_err("[%lu:%lu:%lu] op_key:%lu segloc:%lu buc_data->local_depth:%u (buc_data + 2)->local_depth:%u dir->segs[segloc].local_depth:%lu",machine_id,cli_id,coro_id,this->op_key,segloc,buc_data->local_depth,(buc_data + 2)->local_depth,dir->segs[segloc].local_depth);
    //     goto Retry;
    // }
    if (IsCorrectBucket(segloc, buc_data, pattern_1) == false ||
        IsCorrectBucket(segloc, buc_data + 2, pattern_1) == false)
    {
        log_err("Wrong Bucket After Load");
        auto slot_info = co_await search_on_resize(key, value);
        perf.push_search();
        co_return slot_info;
    }

    // Search the slots of two buckets for the key
    uintptr_t slot_ptr;
    uint64_t slot;
    char key_fp = fp(pattern_1);
    // if(read_cnt == 9900000) {
    //     log_err("No match cnt :%lu, slots overwritten :%lu", miss_count, empty_cnt);
    // }
    if (co_await search_bucket(key, value, slot_ptr, slot, buc_data, bucptr_1, bucptr_2, pattern_1)){
        perf.push_search();
        sum_cost.push_level_cnt(1);
        co_return std::make_tuple(slot_ptr, slot);
    }
    miss_count ++;
    log_err("[%lu:%lu]No match:%lu,segloc:%lu,suffix:%lu,buc2:%lu", cli_id, coro_id, *(uint64_t *)key->data, segloc, buc_data->suffix, bucidx_2);
    // for(int i = 0; i < SLOT_PER_BUCKET; i ++) {
    //     KVBlock* kv_block = (KVBlock*)alloc.alloc(sizeof(KVBlock));
    //     if(buc_data->slots[i].offset != 0) {
    //         co_await conn->read(ralloc.ptr(buc_data->slots[i].offset), rmr.rkey, kv_block, sizeof(KVBlock),lmr->lkey);
    //     }
    //     uint64_t pattern_1;
    //     auto pattern = hash(kv_block->data, kv_block->k_len);
    //     pattern_1 = (uint64_t)pattern;
    //     uint64_t segloc = get_seg_loc(pattern_1, buc_data->local_depth);
    //     if(segloc != buc_data->suffix)
    //         miss_count ++;
    // }
    // if(read_cnt == 11800000) {
    //     log_err("No match cnt :%lu, slots overwritten :%lu", miss_count, empty_cnt);
    // }
    perf.push_search();
    sum_cost.push_level_cnt(1);
    co_return std::make_tuple(0ull, 0);
}

task<std::tuple<uintptr_t, uint64_t>> Client::search_on_resize(Slice *key, Slice *value)
{
    uintptr_t slot_ptr;
    uint64_t slot;
    uint64_t cnt = 0;
Retry:
    if((++cnt)%1000==0)
        log_err("[%lu:%lu]search_on_resize for key:%lx",cli_id,coro_id,*(uint64_t*)key->data);
    alloc.ReSet(sizeof(Directory));
    co_await sync_dir();
    uint64_t pattern_1, pattern_2;
    auto pattern = hash(key->data, key->len);
    pattern_1 = (uint64_t)pattern;
    pattern_2 = (uint64_t)(pattern >> 64);
    uint64_t segloc = get_seg_loc(pattern_1, dir->global_depth);
    uintptr_t segptr = dir->segs[segloc].seg_ptr;

    // Compute two bucket location
    uint64_t bucidx_1, bucidx_2; // calculate bucket idx for each key
    uintptr_t bucptr_1, bucptr_2;
    bucidx_1 = get_buc_loc(pattern_1);
    bucidx_2 = get_buc_loc(pattern_2);
    bucptr_1 = segptr + get_buc_off(bucidx_1);
    bucptr_2 = segptr + get_buc_off(bucidx_2);
    Bucket *buc_data = (Bucket *)alloc.alloc(4ul * sizeof(Bucket));
    auto rbuc1 = conn->read(bucptr_1, rmr.rkey, buc_data, 2 * sizeof(Bucket), lmr->lkey);
    auto rbuc2 = conn->read(bucptr_2, rmr.rkey, buc_data + 2, 2 * sizeof(Bucket), lmr->lkey);
    co_await std::move(rbuc2);
    co_await std::move(rbuc1);

    // Search the slots of two buckets for the key
    if (co_await search_bucket(key, value, slot_ptr, slot, buc_data, bucptr_1, bucptr_2, pattern_1)){
        sum_cost.push_level_cnt(cnt);
        co_return std::make_tuple(slot_ptr, slot);
    }

    if (IsCorrectBucket(segloc, buc_data, pattern_1) == false ||
        IsCorrectBucket(segloc, buc_data + 2, pattern_2) == false)
    {
        goto Retry;
    }

    // Check if the subtable is being resized
    uint64_t first_bit = segloc & (1 << buc_data->local_depth);
    if (dir->segs[segloc].split_lock == 1 && first_bit)
    {
        // Search in the old subtable before resizing
        uint64_t old_segloc = get_seg_loc(pattern_1, buc_data->local_depth);
        uintptr_t old_segptr = dir->segs[segloc].seg_ptr;
        uintptr_t old_bucptr_1 = old_segptr + get_buc_off(bucidx_1);
        uintptr_t old_bucptr_2 = old_segptr + get_buc_off(bucidx_2);
        auto rbuc1 = conn->read(old_bucptr_1, rmr.rkey, buc_data, 2 * sizeof(Bucket), lmr->lkey);
        auto rbuc2 = conn->read(old_bucptr_2, rmr.rkey, buc_data + 2, 2 * sizeof(Bucket), lmr->lkey);
        co_await std::move(rbuc2);
        co_await std::move(rbuc1);
        if (co_await search_bucket(key, value, slot_ptr, slot, buc_data, old_bucptr_1, old_bucptr_2, pattern_1)){
            sum_cost.push_level_cnt(cnt);
            co_return std::make_tuple(slot_ptr, slot);
        }
            

        // Search in the subtable again
        auto rbuc3 = conn->read(bucptr_1, rmr.rkey, buc_data, 2 * sizeof(Bucket), lmr->lkey);
        auto rbuc4 = conn->read(bucptr_2, rmr.rkey, buc_data + 2, 2 * sizeof(Bucket), lmr->lkey);
        co_await std::move(rbuc4);
        co_await std::move(rbuc3);
        if (co_await search_bucket(key, value, slot_ptr, slot, buc_data, bucptr_1, bucptr_2, pattern_1)){
            co_return std::make_tuple(slot_ptr, slot);
            sum_cost.push_level_cnt(cnt);
        }
    }
    // log_err("[%lu:%lu]No match key :%lu", cli_id, coro_id, *(uint64_t *)key->data);
    sum_cost.push_level_cnt(cnt);
    co_return std::make_tuple(0ull, 0);
}

task<bool> Client::search_bucket(Slice *key, Slice *value, uintptr_t &slot_ptr, uint64_t &slot, Bucket *buc_data,
                                     uintptr_t bucptr_1, uintptr_t bucptr_2, uint64_t pattern_1)
{
    Bucket *buc;
    uintptr_t buc_ptr;
    for (uint64_t round = 0; round < 4; round++)
    {
        buc = buc_data + round;
        buc_ptr = (round / 2 ? bucptr_2 : bucptr_1) + (round % 2 ? sizeof(Bucket) : 0);
        for (uint64_t i = 0; i < SLOT_PER_BUCKET; i++)
        {
            // search_bucket 有判空逻辑
            if (*(uint64_t*)(&buc->slots[i]) && buc->slots[i].fp == fp(pattern_1))
            {
                char *kv_block = (char *)alloc.alloc(get_block_size(PREFECTH_FACTOR));
                co_await conn->read(ralloc.ptr(buc->slots[i].offset), rmr.rkey, kv_block,
                                    get_block_size(PREFECTH_FACTOR), lmr->lkey);
                uint64_t kv_len = *(uint64_t*)(kv_block + sizeof(uint64_t));
                if(kv_len > PREFECTH_FACTOR) {
                    assert(0);
                    kv_block = (char*)alloc.alloc(get_block_size(kv_len));
                    co_await conn->read(ralloc.ptr(buc->slots[i].offset), rmr.rkey, kv_block,
                                    get_block_size(kv_len), lmr->lkey);
                }
                if (memcmp(key->data, kv_block + sizeof(uint64_t) * 2, key->len) == 0)
                {
                    slot_ptr = buc_ptr + sizeof(uint64_t) + sizeof(Slot) * i;
                    slot = *(uint64_t *)&(buc->slots[i]);
                    value->len = ((KVBlock*)kv_block)->v_len;
                    memcpy(value->data, ((KVBlock*)kv_block)->data + ((KVBlock*)kv_block)->k_len, value->len);
                    co_return true;
                }
            }
        }
    }
    co_return false;
}

task<> Client::remove(Slice *key)
{
    char data[1024];
    Slice ret_value;
    ret_value.data = data;
    uint64_t cnt=0;
Retry:
    alloc.ReSet(sizeof(Directory));
    // 1st RTT: Using RDMA doorbell batching to fetch two combined buckets
    uint64_t pattern_1, pattern_2;
    auto pattern = hash(key->data, key->len);
    pattern_1 = (uint64_t)pattern;
    pattern_2 = (uint64_t)(pattern >> 64);
    uint64_t segloc = get_seg_loc(pattern_1, dir->global_depth);
    uintptr_t segptr = dir->segs[segloc].seg_ptr;

    if (dir->segs[segloc].split_lock == 1){
        co_await sync_dir();
        goto Retry;
    }

    auto [slot_ptr, slot] = co_await search(key, &ret_value);
    if (slot_ptr != 0ull)
    {
        // if((++cnt)%1000==0)
        //     log_err("[%lu:%lu]slot_ptr:%lx slot:%lx for %lu to be deleted with pattern_1:%lx",cli_id,coro_id,slot_ptr,slot,*(uint64_t*)key->data,pattern_1);
        // 3rd RTT: Setting the key-value block to full zero
        if (!co_await conn->cas_n(slot_ptr, rmr.rkey, slot , 0)){
            log_err("[%lu:%lu]fail to cas slot_ptr:%lx for %lu to zero",cli_id,coro_id,slot_ptr,*(uint64_t*)key->data);
            goto Retry;
        }
    }else{
        log_err("[%lu:%lu]No match key for %lu to be deleted",cli_id,coro_id,*(uint64_t*)key->data);
    }
}

task<> Client::update(Slice *key,Slice *value)
{
    char data[1024];
    Slice ret_value;
    ret_value.data = data;
    KVBlock *kv_block = InitKVBlock(key, value, &alloc);
    uint64_t kvblock_len = key->len + value->len + sizeof(uint64_t) * 2;
    uint64_t kvblock_ptr = ralloc.alloc(kvblock_len);
    auto wkv = conn->write(kvblock_ptr, rmr.rkey, kv_block, kvblock_len, lmr->lkey);
    
    uint64_t pattern_1, pattern_2;
    auto pattern = hash(key->data, key->len);
    pattern_1 = (uint64_t)pattern;
    pattern_2 = (uint64_t)(pattern >> 64);
    uint64_t cnt = 0 ;
Retry:
    alloc.ReSet(sizeof(Directory)+kvblock_len);
    // 1st RTT: Using RDMA doorbell batching to fetch two combined buckets
    uint64_t segloc = get_seg_loc(pattern_1, dir->global_depth);
    uintptr_t segptr = dir->segs[segloc].seg_ptr;

    if (dir->segs[segloc].split_lock == 1){
        co_await sync_dir();
        goto Retry;
    }

    auto [slot_ptr, slot] = co_await search(key, &ret_value);
    Slot *tmp = (Slot *)alloc.alloc(sizeof(Slot));
    tmp->fp = fp(pattern_1);
    tmp->fp2 = ((Slot*)slot)->fp2;
    tmp->offset = ralloc.offset(kvblock_ptr);
    if (slot_ptr != 0ull)
    {
        // log_err("[%lu:%lu]slot_ptr:%lx slot:%lx for %lu to be updated with new slot: fp:%d len:%d offset:%lx",cli_id,coro_id,slot_ptr,slot,*(uint64_t*)key->data,tmp->fp,tmp->len,tmp->offset);
        if(cnt++==0) co_await std::move(wkv) ;
        // 3rd RTT: Setting the key-value block to full zero
        if (!co_await conn->cas_n(slot_ptr, rmr.rkey, slot, *(uint64_t*)tmp))
            goto Retry;
    }else{
        log_err("[%lu:%lu]No match key for %lu to update",cli_id,coro_id,*(uint64_t*)key->data);
    }
}

} // NAMESPACE FASTSHIFT