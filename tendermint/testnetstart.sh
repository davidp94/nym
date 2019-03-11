#!/bin/bash

# it is a very crude script to make it easier for me in my local development. It will definitely be improved later on

IP=0.0.0.0
AA=tcp://$IP
# "0.0.0.0:46656,0.0.0.0:46666,0.0.0.0:46676,0.0.0.0:46686"
TESTNET_ROOT_DIR="$HOME/tendermint"
TESTNET_FOLDER="mytestnet"

# temp until properly built
NYM_APP="$HOME/go/src/0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/main.go"

NODE_0_NAME="node0"
NODE_1_NAME="node1"
NODE_2_NAME="node2"
NODE_3_NAME="node3"
NODE_LOG_LEVEL="state:info,*:error"

NODE_0_ID=8f0361d8040f207e629a962cb19722fc2d7bcc61
NODE_1_ID=1d96f5903f8273a3aef91f77a27e1c7c547574b9
NODE_2_ID=8c467aa1b0cbc59f6900baeb3f364882729e1009
NODE_3_ID=15bc590ea7cab3a8eba5349c3863709cc4b463a8

NODE_0_APP_PORT="46658"
NODE_1_APP_PORT="46668"
NODE_2_APP_PORT="46678"
NODE_3_APP_PORT="46688"

PEERS="$NODE_0_ID@$IP:46656,$NODE_1_ID@$IP:46666,$NODE_2_ID@$IP:46676,$NODE_3_ID@$IP:46686"

NODE_0_START="tendermint node \
                --consensus.create_empty_blocks=false \
                --home "$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_0_NAME" \
                --moniker="$NODE_0_NAME" \
                --proxy_app="$AA:$NODE_0_APP_PORT" \
                --log_level="$NODE_LOG_LEVEL" \
                --rpc.laddr="$AA:46657" \
                --p2p.laddr="$AA:46656" \
                --p2p.persistent_peers=$PEERS;"

NODE_0_APP_START="go run $NYM_APP -port=$NODE_0_APP_PORT -dbpath=$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_0_NAME/appdata"

NODE_1_START="tendermint node \
                --consensus.create_empty_blocks=false \
                --home "$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_1_NAME" \
                --moniker="$NODE_1_NAME" \
                --proxy_app="$AA:$NODE_1_APP_PORT" \
                --log_level="$NODE_LOG_LEVEL" \
                --rpc.laddr="$AA:46667" \
                --p2p.laddr="$AA:46666" \
                --p2p.persistent_peers=$PEERS;"

NODE_1_APP_START="go run $NYM_APP -port=$NODE_1_APP_PORT -dbpath=$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_1_NAME/appdata"

NODE_2_START="tendermint node \
                --consensus.create_empty_blocks=false \
                --home "$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_2_NAME" \
                --moniker="$NODE_2_NAME" \
                --proxy_app="$AA:$NODE_2_APP_PORT" \
                --log_level="$NODE_LOG_LEVEL" \
                --rpc.laddr="$AA:46677" \
                --p2p.laddr="$AA:46676" \
                --p2p.persistent_peers=$PEERS;"

NODE_2_APP_START="go run $NYM_APP -port=$NODE_2_APP_PORT -dbpath=$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_2_NAME/appdata"

NODE_3_START="tendermint node \
                --consensus.create_empty_blocks=false \
                --home "$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_3_NAME" \
                --moniker="$NODE_3_NAME" \
                --proxy_app="$AA:$NODE_3_APP_PORT" \
                --log_level="$NODE_LOG_LEVEL" \
                --rpc.laddr="$AA:46687" \
                --p2p.laddr="$AA:46686" \
                --p2p.persistent_peers=$PEERS;"

NODE_3_APP_START="go run $NYM_APP -port=$NODE_3_APP_PORT -dbpath=$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_3_NAME/appdata"


echo "Tendermint Testnet Location: $TESTNET_ROOT_DIR/$TESTNET_FOLDER"
echo "Loading Nodes: $NODE_0_NAME, $NODE_1_NAME, $NODE_2_NAME, $NODE_3_NAME"
echo "Loading peers: $PEERS"


session="tmnet"

tmux new-session -d -s $session -n node0

tmux selectp -t 0 
tmux send-keys "$NODE_0_START" 
tmux send-keys C-m 

tmux splitw -h

tmux selectp -t 1
tmux send-keys "$NODE_0_APP_START"
tmux send-keys C-m

tmux new-window -t $session:1 -n node1

tmux selectp -t 0 
tmux send-keys "$NODE_1_START" 
tmux send-keys C-m 

tmux splitw -h

tmux selectp -t 1
tmux send-keys "$NODE_1_APP_START"
tmux send-keys C-m

tmux new-window -t $session:2 -n node2

tmux selectp -t 0 
tmux send-keys "$NODE_2_START" 
tmux send-keys C-m 

tmux splitw -h

tmux selectp -t 1
tmux send-keys "$NODE_2_APP_START"
tmux send-keys C-m

tmux new-window -t $session:3 -n node3

tmux selectp -t 0 
tmux send-keys "$NODE_3_START" 
tmux send-keys C-m 

tmux splitw -h

tmux selectp -t 1
tmux send-keys "$NODE_3_APP_START"
tmux send-keys C-m

tmux new-window -t $session:4 -n wip

tmux selectp -t 0 
tmux send-keys "cd $TESTNET_ROOT_DIR/$TESTNET_FOLDER"
tmux send-keys C-m 

tmux splitw -h

tmux selectp -t 1
tmux send-keys "cd $HOME/go/src/0xacab.org/jstuczyn/CoconutGo/tendermint"
tmux send-keys C-m


tmux select-window -t $session:0
tmux attach-session -t $session


# note that when those were used, each start command also had 'bash -c'
# xfce4-terminal -T "node0" -e "$NODE_0_START" \
# --tab -T "node0_app" -e "$NODE_0_APP_START" \
# --window -T "node1" -e "$NODE_1_START" \
# --tab -T "node1_app" -e "$NODE_1_APP_START" \
# --window -T "node2" -e "$NODE_2_START" \
# --tab -T "node2_app" -e "$NODE_2_APP_START" \
# --window -T "node3" -e "$NODE_3_START" \
# --tab -T "node3_app" -e "$NODE_3_APP_START"