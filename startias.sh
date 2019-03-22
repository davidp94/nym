#!/bin/bash

SRC="daemon/server"
BIN="~/go/bin/server"

IA_1_CFG="daemon/server/sampleConfigs/config.toml"
IA_2_CFG="daemon/server/sampleConfigs/config2.toml"
IA_3_CFG="daemon/server/sampleConfigs/config3.toml"


pwd=$PWD

if [ $# -gt 0 ] && [ $1 = true ]
then
    cd $SRC; go install
fi

cd $pwd

session="ias"

tmux new-session -d -s $session -n "ia/sp0:4000"

tmux send-keys "$BIN -f $IA_1_CFG"
tmux send-keys C-m

tmux new-window -t $session:1 -n "ia:4001"
tmux send-keys "$BIN -f $IA_2_CFG"
tmux send-keys C-m

tmux new-window -t $session:2 -n "ia:4002"
tmux send-keys "$BIN -f $IA_3_CFG"
tmux send-keys C-m

tmux select-window -t $session:0
tmux attach-session -t $session