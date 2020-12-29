##########################
BMV2_PATH=~/p4-dev/behavioral-model
P4C_BM_PATH=~/p4-dev/p4c-bm
##########################

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

P4C_BM_SCRIPT=$P4C_BM_PATH/p4c_bm/__main__.py
SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch
CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI

## For compile 
# $P4C_BM_SCRIPT deadline.p4 --json deadline.json
# $P4C_BM_SCRIPT bft_server.p4 --json bft_server.json
# $P4C_BM_SCRIPT bft_client.p4 --json bft_client.json
# $P4C_BM_SCRIPT l2switch.p4 --json switch.json

sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python ~/p4-dev/topk/topology/topo_topk.py \
    --behavioral-exe $BMV2_PATH/targets/simple_switch/simple_switch \
    --switch ~/p4-dev/topk/topk_for_daiet.json \
    --cli $CLI_PATH 