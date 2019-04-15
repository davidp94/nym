# #!/bin/bash

# NO LONGER REQUIRES AS DOCKER IS BEING USED INSTEAD

# SRC="daemon/server"
# BIN="~/go/bin/server"

# IA_1_CFG="daemon/server/sampleConfigs/config.toml"
# IA_2_CFG="daemon/server/sampleConfigs/config2.toml"
# IA_3_CFG="daemon/server/sampleConfigs/config3.toml"


# pwd=$PWD

# if [ $# -gt 0 ] && [ $1 = true ]
# then
#     cd $SRC; go install
# fi

# cd $pwd

# ia_session="ias"

# tmux new-session -d -s $ia_session -n "ia/sp0:4000"

# tmux send-keys -t $ia_session:0 "$BIN -f $IA_1_CFG"
# tmux send-keys -t $ia_session:0 C-m

# tmux new-window -t $ia_session:1 -n "ia:4001"
# tmux send-keys -t $ia_session:1 "$BIN -f $IA_2_CFG"
# tmux send-keys -t $ia_session:1 C-m

# tmux new-window -t $ia_session:2 -n "ia:4002"
# tmux send-keys -t $ia_session:2 "$BIN -f $IA_3_CFG"
# tmux send-keys -t $ia_session:2 C-m

# tmux select-window -t $ia_session:0
# tmux attach-session -t $ia_session