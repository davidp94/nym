#!/bin/bash


dev_session="dev"

tmux new-session -d -s $dev_session -n "git"

tmux send-keys -t $dev_session:0 "git status"
tmux send-keys -t $dev_session:0 C-m

tmux new-window -t $dev_session:1 -n "tests"
tmux send-keys -t $dev_session:1 "echo 'go test ./...'"
tmux send-keys -t $dev_session:1 C-m

tmux new-window -t $dev_session:2 -n "client"
tmux send-keys -t $dev_session:2 "cd sampleclientmain"
tmux send-keys -t $dev_session:2 C-m
tmux send-keys -t $dev_session:2 "go run main_sample.go"

xfce4-terminal -T "Tendemint" -x "tendermint/testnetstart.sh" 
sleep 5s # wait for nodes to start
xfce4-terminal -T "Tendemint" -x "./startias.sh"

tmux select-window -t $dev_session:2
tmux attach-session -t $dev_session
